package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
	ConfigLen = 2048
)

var Marker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x99, 0x99, 0x88, 0x88, 0x77, 0x77}

type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func encrypt(data []byte, totalLen int) ([]byte, error) {
	block, err := aes.NewCipher([]byte(ConfigKey))
	if err != nil {
		return nil, err
	}

	if len(data) > totalLen {
		return nil, fmt.Errorf("data too large")
	}

	// Null padding up to totalLen
	rawBuffer := make([]byte, totalLen)
	copy(rawBuffer, data)

	ciphertext := make([]byte, totalLen)
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))

	for i := 0; i < totalLen; i += aes.BlockSize {
		mode.CryptBlocks(ciphertext[i:i+aes.BlockSize], rawBuffer[i:i+aes.BlockSize])
	}

	return ciphertext, nil
}

func main() {
	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	flag.Parse()

	// Read base64.txt
	b64Data, err := os.ReadFile("base64.txt")
	if err != nil {
		log.Fatalf("Error reading base64.txt: %v", err)
	}

	// Clean base64 data from whitespace/newlines
	cleanB64 := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \n\r\t", r) {
			return -1
		}
		return r
	}, string(b64Data))

	// Decode EXE
	exeData, err := base64.StdEncoding.DecodeString(cleanB64)
	if err != nil {
		log.Fatalf("Error decoding base64: %v", err)
	}

	// Create Config JSON
	cfg := Config{
		Host: *ip,
		Port: *port,
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		log.Fatalf("Error marshaling config: %v", err)
	}

	// Encrypt Config - total length for ciphertext should be 2032 (2048 - 16 marker)
	encrypted, err := encrypt(cfgBytes, ConfigLen-len(Marker))
	if err != nil {
		log.Fatalf("Error encrypting config: %v", err)
	}

	// Prepare the patch block
	patchBlock := make([]byte, ConfigLen)
	copy(patchBlock, Marker)
	copy(patchBlock[len(Marker):], encrypted)

	// Find Marker in EXE
	index := bytes.Index(exeData, Marker)
	if index == -1 {
		log.Fatalf("Marker not found in EXE")
	}
	if bytes.LastIndex(exeData, Marker) != index {
		log.Printf("Warning: Multiple markers found, patching the first one.")
	}

	// Apply Patch
	copy(exeData[index:index+ConfigLen], patchBlock)

	// Save to file
	outputName := "client_patched.exe"
	err = os.WriteFile(outputName, exeData, 0755)
	if err != nil {
		log.Fatalf("Error writing output file: %v", err)
	}

	fmt.Printf("Build successful: %s\n", outputName)
}
