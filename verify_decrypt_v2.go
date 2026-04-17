package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
	Marker    = "CONF_DATA_START:"
)

func main() {
	b64Data, _ := os.ReadFile("output_b64.txt")
	exeData, _ := base64.StdEncoding.DecodeString(string(b64Data))

	index := bytes.Index(exeData, []byte(Marker))
	if index == -1 {
		fmt.Println("Marker not found")
		return
	}

	encrypted := exeData[index+len(Marker) : index+2048]

	block, _ := aes.NewCipher([]byte(ConfigKey))
	mode := cipher.NewCBCDecrypter(block, []byte(ConfigIV))

	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	fmt.Printf("Decrypted: [%s]\n", decrypted)
}
