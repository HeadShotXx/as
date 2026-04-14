// Windows system info — pure Rust via windows crate (no PowerShell)

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::*,
    },
};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub fn collect() -> String {
    let win_version  = get_win_version();
    let desktop_name = get_desktop_name();
    let antivirus    = get_antivirus();
    let country      = get_country();
    format!("{}|{}|{}|{}", win_version, desktop_name, antivirus, country)
}

// ── Windows version from registry ────────────────────────────────────────────

fn reg_read_dword(key: HKEY, subkey: &str, value: &str) -> Option<u32> {
    unsafe {
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let value_w:  Vec<u16> = value.encode_utf16().chain(Some(0)).collect();

        let mut hkey = HKEY::default();
        let res = RegOpenKeyExW(key, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey);
        if res != ERROR_SUCCESS { return None; }

        let mut data_type = REG_VALUE_TYPE::default();
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;

        let res2 = RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut data_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        );
        RegCloseKey(hkey);

        if res2 == ERROR_SUCCESS && data_type == REG_DWORD {
            Some(data)
        } else {
            None
        }
    }
}

fn reg_read_sz(key: HKEY, subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let value_w:  Vec<u16> = value.encode_utf16().chain(Some(0)).collect();

        let mut hkey = HKEY::default();
        let res = RegOpenKeyExW(key, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey);
        if res != ERROR_SUCCESS { return None; }

        let mut data_type = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // First call: get size
        RegQueryValueExW(hkey, PCWSTR(value_w.as_ptr()), None, Some(&mut data_type), None, Some(&mut size));

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let res2 = RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut data_type),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        RegCloseKey(hkey);

        if res2 != ERROR_SUCCESS { return None; }

        // REG_SZ is UTF-16LE; convert to Rust String
        let words: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        Some(OsString::from_wide(&words).to_string_lossy().to_string())
    }
}

fn get_win_version() -> String {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let build   = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "CurrentBuild")
        .unwrap_or_default();
    let display = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "DisplayVersion")
        .or_else(|| reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "ReleaseId"))
        .unwrap_or_default();

    if build.is_empty() {
        product
    } else {
        format!("{} {} (Build {})", product, display, build)
    }
}

// ── Computer name from environment ───────────────────────────────────────────

fn get_desktop_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string())
}

// ── Antivirus via WMI & Registry ─────────────────────────────────────────────

fn get_av_wmi() -> Option<String> {
    use windows::{
        core::*,
        Win32::System::Com::*,
        Win32::System::Wmi::*,
        Win32::System::Variant::*,
    };

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).ok()?;

        let server = BSTR::from("ROOT\\SecurityCenter2");
        let services = locator.ConnectServer(&server, None, None, None, 0, None, None).ok()?;

        CoSetProxyBlanket(
            &services, 10, 0, None, // 10 = RPC_C_AUTHN_WINNT, 0 = RPC_C_AUTHZ_NONE
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE
        ).ok()?;

        let query = BSTR::from("SELECT displayName FROM AntivirusProduct");
        let mut enumerator = None;
        services.ExecQuery(
            &BSTR::from("WQL"), &query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, None, &mut enumerator
        ).ok()?;
        let enumerator = enumerator?;

        let mut av_list = Vec::new();
        loop {
            let mut objects: [Option<IWbemClassObject>; 1] = [None; 1];
            let mut returned = 0;
            if enumerator.Next(WBEM_INFINITE, &mut objects, &mut returned).is_err() || returned == 0 {
                break;
            }
            if let Some(obj) = &objects[0] {
                let mut variant = VARIANT::default();
                if obj.Get(w!("displayName"), 0, &mut variant, None, None).is_ok() {
                    let name = variant.to_string();
                    if !name.is_empty() {
                        av_list.push(name);
                    }
                    let _ = VariantClear(&mut variant);
                }
            }
        }

        if av_list.is_empty() {
            None
        } else {
            Some(av_list.join(", "))
        }
    }
}

fn get_antivirus() -> String {
    // 1. Try WMI
    if let Some(wmi_av) = get_av_wmi() {
        return wmi_av;
    }

    // 2. Check Windows Defender registry more carefully
    // DisableAntiSpyware = 0 means enabled
    let disabled = reg_read_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware").unwrap_or(0);
    // Real-time protection (often under Real-Time Protection subkey)
    let rt_disabled = reg_read_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring").unwrap_or(0);

    if disabled == 0 && rt_disabled == 0 {
        return "Windows Defender".to_string();
    }
    
    // 3. Check common antivirus registry paths
    let av_paths = [
        r"SOFTWARE\AVAST Software",
        r"SOFTWARE\AVG",
        r"SOFTWARE\Bitdefender",
        r"SOFTWARE\KasperskyLab",
        r"SOFTWARE\McAfee",
        r"SOFTWARE\Norton",
        r"SOFTWARE\Symantec",
        r"SOFTWARE\ESET",
        r"SOFTWARE\Trend Micro",
        r"SOFTWARE\Malwarebytes",
        r"SOFTWARE\Sophos",
        r"SOFTWARE\Panda Security",
        r"SOFTWARE\Avira",
    ];
    
    for path in av_paths.iter() {
        let path_w: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let mut hkey = HKEY::default();
            let res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()), 0, KEY_READ, &mut hkey);
            if res == ERROR_SUCCESS {
                RegCloseKey(hkey);
                let name = path.trim_start_matches(r"SOFTWARE\").split('\\').next().unwrap_or(path);
                return name.to_string();
            }
        }
    }
    
    "Unknown".to_string()
}

// ── Country via HTTP (pure Rust / windows WinHTTP) ───────────────────────────

fn get_country() -> String {
    use windows::{
        core::PCWSTR,
        Win32::Networking::WinHttp::*,
    };
    unsafe {
        let agent:  Vec<u16> = "client\0".encode_utf16().collect();
        let server: Vec<u16> = "ipinfo.io\0".encode_utf16().collect();
        let path:   Vec<u16> = "/country\0".encode_utf16().collect();

        let session = WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() { return "??".to_string(); }

        let connect = WinHttpConnect(session, PCWSTR(server.as_ptr()), 80, 0);
        if connect.is_null() { WinHttpCloseHandle(session); return "??".to_string(); }

        let verb:    Vec<u16> = "GET\0".encode_utf16().collect();
        let request = WinHttpOpenRequest(
            connect,
            PCWSTR(verb.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null_mut(),
            WINHTTP_OPEN_REQUEST_FLAGS(0),
        );
        if request.is_null() {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return "??".to_string();
        }

        let headers: Vec<u16> = Vec::new();
        if WinHttpSendRequest(
            request,
            if headers.is_empty() { None } else { Some(&headers) },
            None,
            0,
            0,
            0,
        ).is_err() || WinHttpReceiveResponse(request, std::ptr::null_mut()).is_err() {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return "??".to_string();
        }

        let mut body = Vec::new();
        loop {
            let mut available = 0u32;
            if WinHttpQueryDataAvailable(request, &mut available).is_err() || available == 0 {
                break;
            }
            let mut buf = vec![0u8; available as usize];
            let mut read = 0u32;
            if WinHttpReadData(request, buf.as_mut_ptr() as *mut _, available, &mut read).is_err() {
                break;
            }
            buf.truncate(read as usize);
            body.extend_from_slice(&buf);
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        let s = String::from_utf8_lossy(&body).trim().to_string();
        if s.is_empty() { "??".to_string() } else { s }
    }
}