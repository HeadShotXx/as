package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

type KeyData struct {
	Expiry time.Time `json:"expiry"`
}

var db map[string]KeyData

var secret = []byte("SUPER_SECRET_KEY_123")

// replay protection (RAM cache)
var usedNonces = map[string]bool{}

func loadDB() {
	file, err := os.ReadFile("db/keys.json")
	if err != nil {
		fmt.Println("keys.json read error:", err)
		os.Exit(1)
	}

	err = json.Unmarshal(file, &db)
	if err != nil {
		fmt.Println("json parse error:", err)
		os.Exit(1)
	}
}

func verifyHMAC(message, sig string) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(sig))
}

func validateKey(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	nonce := r.URL.Query().Get("nonce")
	ts := r.URL.Query().Get("ts")
	sig := r.URL.Query().Get("sig")

	// 1. nonce replay protection
	if usedNonces[nonce] {
		w.Write([]byte("replay detected"))
		return
	}
	usedNonces[nonce] = true

	// 2. timestamp check
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		w.Write([]byte("invalid timestamp"))
		return
	}

	now := time.Now().Unix()

	if now-tsInt > 300 || tsInt-now > 300 {
		w.Write([]byte("timestamp invalid"))
		return
	}

	// 3. key check
	data, exists := db[key]
	if !exists {
		w.Write([]byte("invalid key"))
		return
	}

	if time.Now().After(data.Expiry) {
		w.Write([]byte("expired"))
		return
	}

	// 4. HMAC verify
	message := key + "|" + nonce + "|" + ts

	if !verifyHMAC(message, sig) {
		w.Write([]byte("hmac fail"))
		return
	}

	w.Write([]byte("valid|" + data.Expiry.Format(time.RFC3339)))
}

func main() {
	loadDB()

	http.HandleFunc("/validate", validateKey)

	fmt.Println("License server running on :8081")
	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		fmt.Println("server error:", err)
	}
}