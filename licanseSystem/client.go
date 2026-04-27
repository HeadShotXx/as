package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var secret = []byte("SUPER_SECRET_KEY_123")

func generateNonce() string {
	return strconv.FormatInt(rand.Int63(), 16)
}

func signMessage(message string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func checkLicense(key string) string {
	nonce := generateNonce()
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	message := key + "|" + nonce + "|" + ts
	sig := signMessage(message)

	url := fmt.Sprintf(
		"http://localhost:8080/validate?key=%s&nonce=%s&ts=%s&sig=%s",
		key, nonce, ts, sig,
	)

	resp, err := http.Get(url)
	if err != nil {
		return "request error"
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter license key: ")
	keyInput, _ := reader.ReadString('\n')

	keyInput = strings.TrimSpace(keyInput)

	result := checkLicense(keyInput)

	fmt.Println("Server response:", result)

	if result == "valid" {
		fmt.Println("✔ License OK, program running...")
	} else {
		fmt.Println("❌ License invalid:", result)
	}
}
