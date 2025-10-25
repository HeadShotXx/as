

use crc::CRC_32_ISO_HDLC;
use crc::Crc;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;
use windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS;
use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Performance::*;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;
use windows::Win32::System::SystemServices::IMAGE_NT_SIGNATURE;
use windows::Win32::System::Threading::*;
use windows::core::*;

#[inline(never)]
fn checksum_g_arrwj_qhisgb(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

fn decode_csxmxfwsd_ega(encrypted: &[u8], key: &[u8], expected_sum: u64) -> &'static str {
    let s: String = {
        use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
        use aes::{Aes128, Aes192, Aes256};
        use base85; // using base85 for base85 decoding
        use bs58; // using bs58 for base58 decoding
        use base64::{engine::general_purpose, Engine as _};

        if key.len() < 88 { return Box::leak(String::from_utf8_lossy(encrypted).to_string().into_boxed_str()); }

        let xor_key = &key[0..16];
        let aes192_key = &key[16..40];
        let aes128_key = &key[40..56];
        let aes256_key = &key[56..88];

        let mut data = encrypted.to_vec();

        let cipher256 = Aes256::new(GenericArray::from_slice(aes256_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher256.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher128 = Aes128::new(GenericArray::from_slice(aes128_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher128.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher192 = Aes192::new(GenericArray::from_slice(aes192_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher192.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        if !data.is_empty() {
            let pad_len = data[data.len() - 1] as usize;
            if pad_len <= 16 && pad_len <= data.len() {
                data.truncate(data.len() - pad_len);
            }
        }

        let xor_decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ xor_key[i % xor_key.len()]).collect();
        let hex_str = match String::from_utf8(xor_decoded) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base64_bytes = match hex::decode(&hex_str) { Ok(b) => b, Err(_) => return Box::leak(hex_str.into_boxed_str()) };
        let base64_str = match String::from_utf8(base64_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base32_bytes = match general_purpose::STANDARD.decode(&base64_str) { Ok(b) => b, Err(_) => return Box::leak(base64_str.into_boxed_str()) };
        let base32_str = match String::from_utf8(base32_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base58_bytes = match base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &base32_str) { Some(b) => b, None => return Box::leak(base32_str.into_boxed_str()) };
        let base58_str = match String::from_utf8(base58_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base85_bytes = match bs58::decode(&base58_str).into_vec() { Ok(b) => b, Err(_) => return Box::leak(base58_str.into_boxed_str()) };
        let base85_str = match String::from_utf8(base85_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base45_bytes = match base85::decode(&base85_str) { Ok(b) => b, Err(_) => return Box::leak(base85_str.into_boxed_str()) };
        let base45_str = match String::from_utf8(base45_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };

        match base45::decode(&base45_str) {
            Ok(final_bytes) => {
                let runtime_sum = checksum_g_arrwj_qhisgb(&final_bytes);
                if runtime_sum != expected_sum {
                    // Tampering detected! Simulated volatile write (to valid memory) then abort.
                    unsafe {
                        let mut dummy: u8 = 0;
                        std::ptr::write_volatile(&mut dummy, 1);
                    }
                    std::process::abort();
                }
                String::from_utf8_lossy(&final_bytes).to_string()
            },
            Err(_) => base45_str,
        }
    };
    Box::leak(s.into_boxed_str())
}

  pub fn is_debugger_present () -> bool { unsafe { IsDebuggerPresent () . as_bool () } } pub fn check_remote_debugger () -> bool { let mut is_present = FALSE ; unsafe { if CheckRemoteDebuggerPresent (GetCurrentProcess () , & mut is_present) . is_ok () { return is_present . as_bool () ; } } false } fn jt_ip_rbcq () -> bool { is_debugger_present () || check_remote_debugger () || nt_query_information_process () || performance_counter_timing_check () || scan_for_int3 () || check_hardware_breakpoints () || is_parent_a_debugger () || crc32_verify_self () } const hxmld_ol_q : i32 = (4 + 13) ; pub fn run_all_checks_hidden () -> bool { let handle = std :: thread :: spawn (| | { type NtSetInformationThread = unsafe extern "system" fn (thread_handle : HANDLE , thread_information_class : i32 , thread_information : * mut std :: ffi :: c_void , thread_information_length : u32 ,) -> NTSTATUS ; let ntdll = unsafe { GetModuleHandleA (s ! ("ntdll.dll\0")) } . unwrap () ; let nt_set_info_thread : NtSetInformationThread = unsafe { std :: mem :: transmute (GetProcAddress (ntdll , s ! ("NtSetInformationThread\0"))) } ; let status = unsafe { nt_set_info_thread (GetCurrentThread () , hxmld_ol_q , std :: ptr :: null_mut () , 0 ,) } ; if status . is_err () { return true ; } jt_ip_rbcq () }) ; handle . join () . unwrap_or (true) } pub fn is_parent_a_debugger () -> bool { let mut pe32 = PROCESSENTRY32 :: default () ; pe32 . dwSize = std :: mem :: size_of :: < PROCESSENTRY32 > () as u32 ; let snapshot = unsafe { CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS , 0) } . unwrap_or (INVALID_HANDLE_VALUE) ; if snapshot == INVALID_HANDLE_VALUE { return false ; } let current_pid = unsafe { GetCurrentProcessId () } ; let mut parent_pid = 0 ; if unsafe { Process32First (snapshot , & mut pe32) } . is_ok () { loop { if pe32 . th32ProcessID == current_pid { parent_pid = pe32 . th32ParentProcessID ; break ; } if unsafe { Process32Next (snapshot , & mut pe32) } . is_err () { break ; } } } if parent_pid == 0 { unsafe { let _ = CloseHandle (snapshot) ; } ; return false ; } let mut parent_is_debugger = false ; if unsafe { Process32First (snapshot , & mut pe32) } . is_ok () { loop { if pe32 . th32ProcessID == parent_pid { let end = pe32 . szExeFile . iter () . position (| & c | c == 0) . unwrap_or ((89 + 171)) ; let parent_name = String :: from_utf8_lossy (& pe32 . szExeFile [.. end]) . to_lowercase () ; let debuggers = [decode_csxmxfwsd_ega (& [76 , 246 , 164 , 93 , 200 , 43 , 180 , 13 , 182 , 141 , 28 , 255 , 216 , 196 , 248 , 206 , 113 , 205 , 70 , 44 , 141 , 51 , 122 , 8 , 200 , 152 , 239 , 185 , 65 , 79 , 14 , 203 , 91 , 145 , 176 , 6 , 198 , 120 , 129 , 195 , 14 , 91 , 239 , 80 , 78 , 54 , 244 , 144 , 85 , 87 , 9 , 13 , 57 , 161 , 233 , 81 , 150 , 172 , 64 , 183 , 3 , 181 , 5 , 69 , 171 , 64 , 226 , 63 , 70 , 74 , 120 , 15 , 141 , 207 , 22 , 117 , 231 , 130 , 119 , 151 , 246 , 191 , 15 , 251 , 8 , 163 , 230 , 145 , 74 , 116 , 97 , 162 , 124 , 150 , 132 , 40 , 89 , 30 , 30 , 255 , 140 , 44 , 82 , 229 , 33 , 121 , 154 , 129 , 140 , 159 , 25 , 83 , 65 , 20 , 179 , 226 , 125 , 216 , 172 , 42 , 101 , 130 , 139 , 233 , 30 , 174 , 149 , 194 , 144 , 200 , 63 , 233 , 59 , 237 , 214 , 175 , 102 , 60 , 193 , 128 , 215 , 155 , 123 , 126] , & [102 , 176 , 91 , 206 , 183 , 133 , 170 , 216 , 198 , 170 , 186 , 47 , 6 , 197 , 166 , 85 , 141 , 171 , 186 , 164 , 191 , 4 , 101 , 116 , 224 , 117 , 99 , 214 , 254 , 144 , 122 , 47 , 132 , 96 , 255 , 198 , 212 , 153 , 59 , 153 , 242 , 23 , 167 , 83 , 190 , 193 , 80 , 9 , 138 , 83 , 242 , 95 , 7 , 195 , 48 , 77 , 198 , 33 , 92 , 57 , 234 , 111 , 199 , 87 , 37 , 207 , 15 , 92 , 46 , 54 , 158 , 55 , 203 , 30 , 153 , 235 , 122 , 251 , 96 , 7 , 194 , 236 , 208 , 154 , 172 , 193 , 244 , 136] , 24292335027180u64) , decode_csxmxfwsd_ega (& [248 , 174 , 149 , 155 , 254 , 18 , 84 , 23 , 246 , 110 , 68 , 36 , 211 , 69 , 85 , 231 , 236 , 27 , 13 , 23 , 185 , 204 , 4 , 236 , 61 , 15 , 239 , 11 , 144 , 200 , 83 , 3 , 17 , 213 , 9 , 26 , 118 , 248 , 42 , 137 , 255 , 38 , 154 , 134 , 227 , 161 , 232 , 186 , 209 , 122 , 8 , 161 , 96 , 56 , 179 , 168 , 25 , 35 , 196 , 138 , 57 , 17 , 236 , 34 , 101 , 59 , 184 , 64 , 73 , 6 , 20 , 203 , 130 , 107 , 146 , 96 , 28 , 255 , 116 , 209 , 47 , 249 , 176 , 190 , 225 , 136 , 252 , 131 , 251 , 231 , 50 , 238 , 149 , 59 , 227 , 191 , 249 , 47 , 122 , 226 , 249 , 61 , 131 , 235 , 195 , 185 , 229 , 132 , 12 , 29 , 105 , 53 , 162 , 88 , 127 , 65 , 36 , 134 , 137 , 181 , 215 , 116 , 19 , 154 , 103 , 158 , 94 , 202 , 110 , 74 , 224 , 157 , 210 , 80 , 53 , 39 , 129 , 19 , 152 , 143 , 55 , 210 , 237 , 245] , & [150 , 3 , 44 , 87 , 109 , 212 , 160 , 175 , 92 , 85 , 76 , 76 , 92 , 69 , 31 , 122 , 126 , 56 , 94 , 150 , 249 , 45 , 188 , 26 , 204 , 2 , 207 , 227 , 225 , 126 , 161 , 95 , 152 , 89 , 220 , 221 , 79 , 243 , 86 , 22 , 151 , 71 , 53 , 114 , 136 , 115 , 228 , 219 , 107 , 179 , 127 , 15 , 113 , 109 , 23 , 103 , 96 , 67 , 24 , 102 , 172 , 8 , 202 , 192 , 164 , 220 , 118 , 98 , 202 , 237 , 35 , 80 , 104 , 125 , 94 , 46 , 226 , 108 , 35 , 214 , 202 , 64 , 144 , 47 , 124 , 182 , 191 , 98] , 20371029885824u64) , decode_csxmxfwsd_ega (& [162 , 217 , 202 , 187 , 48 , 103 , 239 , 72 , 151 , 194 , 46 , 198 , 225 , 194 , 241 , 127 , 100 , 125 , 4 , 198 , 74 , 51 , 152 , 204 , 146 , 48 , 19 , 20 , 174 , 249 , 48 , 226 , 158 , 50 , 130 , 252 , 213 , 2 , 31 , 251 , 223 , 78 , 242 , 80 , 5 , 107 , 104 , 125 , 124 , 129 , 197 , 193 , 88 , 146 , 222 , 108 , 247 , 57 , 178 , 250 , 217 , 203 , 232 , 165 , 191 , 254 , 145 , 194 , 37 , 255 , 123 , 1 , 206 , 174 , 124 , 253 , 247 , 87 , 246 , 177 , 30 , 16 , 241 , 172 , 158 , 17 , 25 , 174 , 208 , 233 , 208 , 28 , 246 , 210 , 231 , 191 , 13 , 220 , 0 , 111 , 232 , 115 , 117 , 33 , 215 , 138 , 127 , 119 , 209 , 52 , 194 , 176 , 161 , 14 , 119 , 46 , 7 , 103 , 165 , 237 , 193 , 2 , 74 , 98 , 112 , 85 , 119 , 142 , 215 , 168 , 36 , 72 , 151 , 223 , 155 , 123 , 63 , 4 , 119 , 183 , 196 , 132 , 147 , 118] , & [127 , 144 , 88 , 171 , 58 , 232 , 192 , 156 , 249 , 240 , 51 , 51 , 194 , 170 , 61 , 108 , 81 , 84 , 190 , 196 , 143 , 159 , 221 , 33 , 79 , 82 , 148 , 84 , 224 , 237 , 110 , 158 , 134 , 190 , 135 , 193 , 27 , 137 , 207 , 7 , 54 , 144 , 223 , 187 , 176 , 130 , 57 , 30 , 112 , 159 , 133 , 33 , 223 , 254 , 118 , 149 , 77 , 94 , 49 , 17 , 125 , 78 , 115 , 171 , 112 , 102 , 39 , 16 , 209 , 91 , 145 , 80 , 146 , 202 , 212 , 76 , 104 , 125 , 132 , 166 , 45 , 111 , 18 , 122 , 133 , 251 , 63 , 116] , 29562259899486u64) , decode_csxmxfwsd_ega (& [71 , 194 , 44 , 193 , 104 , 70 , 243 , 53 , 18 , 231 , 1 , 52 , 9 , 55 , 18 , 10 , 237 , 34 , 60 , 119 , 118 , 193 , 48 , 59 , 227 , 64 , 252 , 26 , 178 , 238 , 79 , 138 , 43 , 159 , 250 , 242 , 186 , 110 , 248 , 96 , 164 , 49 , 124 , 148 , 164 , 132 , 69 , 147 , 48 , 248 , 124 , 180 , 205 , 14 , 147 , 27 , 154 , 163 , 253 , 123 , 112 , 248 , 191 , 46 , 52 , 106 , 5 , 18 , 127 , 115 , 225 , 86 , 249 , 92 , 183 , 165 , 27 , 25 , 21 , 121 , 28 , 20 , 162 , 226 , 213 , 155 , 211 , 211 , 176 , 72 , 0 , 52 , 242 , 10 , 240 , 152 , 58 , 28 , 224 , 43 , 60 , 157 , 55 , 180 , 114 , 53 , 45 , 34 , 83 , 14 , 118 , 186 , 142 , 202 , 214 , 142 , 175 , 109 , 191 , 2 , 202 , 29 , 181 , 101 , 30 , 252 , 241 , 238] , & [54 , 190 , 49 , 163 , 239 , 177 , 174 , 192 , 144 , 240 , 0 , 29 , 162 , 22 , 130 , 73 , 225 , 126 , 206 , 165 , 68 , 40 , 4 , 174 , 174 , 11 , 220 , 176 , 96 , 180 , 164 , 80 , 176 , 101 , 209 , 65 , 10 , 248 , 31 , 31 , 161 , 169 , 8 , 193 , 169 , 191 , 34 , 72 , 199 , 130 , 158 , 165 , 121 , 48 , 104 , 7 , 97 , 139 , 220 , 96 , 143 , 196 , 109 , 201 , 73 , 198 , 234 , 227 , 37 , 150 , 63 , 220 , 182 , 224 , 195 , 202 , 72 , 219 , 99 , 211 , 44 , 255 , 23 , 238 , 87 , 135 , 211 , 241] , 15131169784592u64) , decode_csxmxfwsd_ega (& [87 , 242 , 132 , 40 , 179 , 221 , 177 , 184 , 85 , 24 , 253 , 24 , 114 , 27 , 181 , 76 , 45 , 205 , 249 , 205 , 204 , 72 , 217 , 166 , 2 , 77 , 64 , 19 , 176 , 69 , 133 , 32 , 12 , 41 , 11 , 40 , 24 , 92 , 15 , 54 , 143 , 58 , 39 , 213 , 89 , 39 , 145 , 37 , 11 , 199 , 48 , 197 , 182 , 84 , 230 , 190 , 217 , 240 , 21 , 26 , 130 , 122 , 59 , 172 , 110 , 99 , 245 , 95 , 193 , 56 , 114 , 14 , 222 , 107 , 60 , 220 , 62 , 234 , 203 , 148 , 242 , 12 , 173 , 85 , 145 , 32 , 225 , 133 , 209 , 197 , 227 , 19 , 250 , 192 , 97 , 181 , 62 , 213 , 180 , 28 , 233 , 49 , 248 , 160 , 211 , 77 , 180 , 120 , 198 , 72 , 255 , 218 , 68 , 59 , 179 , 58 , 80 , 44 , 106 , 119 , 83 , 58 , 63 , 126 , 143 , 146 , 94 , 55 , 92 , 108 , 163 , 140 , 141 , 91 , 239 , 117 , 151 , 232 , 141 , 35 , 209 , 182 , 1 , 226] , & [91 , 154 , 76 , 199 , 68 , 85 , 240 , 158 , 227 , 228 , 117 , 56 , 245 , 87 , 125 , 140 , 145 , 147 , 85 , 81 , 26 , 220 , 90 , 97 , 216 , 238 , 170 , 38 , 63 , 165 , 225 , 138 , 32 , 75 , 72 , 145 , 235 , 163 , 136 , 139 , 20 , 218 , 199 , 113 , 97 , 211 , 45 , 200 , 21 , 30 , 30 , 43 , 216 , 204 , 195 , 149 , 223 , 76 , 12 , 171 , 104 , 158 , 48 , 110 , 34 , 242 , 21 , 25 , 72 , 176 , 133 , 100 , 223 , 56 , 28 , 17 , 234 , 205 , 214 , 185 , 180 , 154 , 150 , 165 , 180 , 136 , 214 , 253] , 21212843475834u64) , decode_csxmxfwsd_ega (& [235 , 185 , 102 , 223 , 91 , 189 , 250 , 29 , 219 , 112 , 109 , 105 , 47 , 19 , 36 , 251 , 27 , 124 , 76 , 27 , 63 , 152 , 136 , 58 , 14 , 49 , 71 , 58 , 125 , 191 , 253 , 152 , 20 , 211 , 169 , 67 , 171 , 121 , 207 , 144 , 108 , 47 , 51 , 90 , 126 , 22 , 95 , 162 , 203 , 21 , 228 , 37 , 210 , 41 , 243 , 80 , 27 , 61 , 93 , 37 , 150 , 232 , 238 , 190 , 25 , 47 , 224 , 168 , 120 , 75 , 106 , 240 , 121 , 73 , 57 , 35 , 18 , 205 , 190 , 148 , 5 , 70 , 96 , 160 , 147 , 68 , 12 , 191 , 119 , 227 , 69 , 128 , 134 , 83 , 145 , 47 , 60 , 178 , 129 , 10 , 102 , 160 , 202 , 57 , 240 , 72 , 11 , 102 , 41 , 186 , 186 , 11 , 244 , 8 , 201 , 116 , 51 , 53 , 253 , 239 , 202 , 6 , 160 , 106 , 42 , 130 , 42 , 152 , 27 , 224 , 16 , 0 , 31 , 26 , 201 , 86 , 24 , 235 , 200 , 227 , 250 , 166 , 134 , 185] , & [26 , 121 , 133 , 32 , 190 , 24 , 176 , 72 , 11 , 96 , 167 , 174 , 141 , 217 , 42 , 225 , 192 , 228 , 250 , 209 , 159 , 146 , 157 , 75 , 156 , 73 , 178 , 176 , 99 , 160 , 211 , 11 , 242 , 85 , 84 , 13 , 209 , 195 , 28 , 22 , 222 , 25 , 56 , 174 , 201 , 98 , 75 , 54 , 136 , 75 , 206 , 87 , 247 , 213 , 3 , 234 , 111 , 7 , 167 , 138 , 170 , 229 , 174 , 65 , 202 , 167 , 63 , 162 , 4 , 61 , 76 , 68 , 133 , 204 , 88 , 241 , 144 , 224 , 177 , 48 , 190 , 179 , 194 , 6 , 7 , 122 , 191 , 73] , 24257975288825u64) ,] ; if debuggers . iter () . any (| & d | parent_name . contains (d)) { parent_is_debugger = true ; } break ; } if unsafe { Process32Next (snapshot , & mut pe32) } . is_err () { break ; } } } unsafe { let _ = CloseHandle (snapshot) ; } ; parent_is_debugger } # [cfg (target_arch = "x86_64")] pub fn crc32_verify_self () -> bool { unsafe { let base_address = match GetModuleHandleA (PCSTR (std :: ptr :: null_mut ())) { Ok (h) => h , Err (_) => return true , } ; let dos_header = base_address . 0 as * const IMAGE_DOS_HEADER ; if (* dos_header) . e_magic != IMAGE_DOS_SIGNATURE { return true ; } let nt_headers_ptr = (base_address . 0 as * const u8) . add ((* dos_header) . e_lfanew as usize) ; let nt_headers = & * (nt_headers_ptr as * const IMAGE_NT_HEADERS64) ; if nt_headers . Signature != IMAGE_NT_SIGNATURE { return true ; } let section_header_ptr = nt_headers_ptr . add (std :: mem :: size_of :: < IMAGE_NT_HEADERS64 > ()) ; let sections = std :: slice :: from_raw_parts (section_header_ptr as * const IMAGE_SECTION_HEADER , nt_headers . FileHeader . NumberOfSections as usize ,) ; for section in sections { let name_bytes : Vec < u8 > = section . Name . iter () . cloned () . take_while (| & c | c != 0) . collect () ; if let Ok (name) = String :: from_utf8 (name_bytes) { if name == decode_csxmxfwsd_ega (& [112 , 245 , 133 , 185 , 169 , 147 , 105 , 208 , 103 , 16 , 179 , 251 , 157 , 157 , 220 , 80 , 123 , 126 , 19 , 116 , 27 , 72 , 165 , 60 , 104 , 137 , 12 , 101 , 185 , 76 , 68 , 44 , 137 , 51 , 219 , 142 , 11 , 65 , 154 , 122 , 33 , 15 , 106 , 216 , 11 , 40 , 215 , 110 , 220 , 251 , 199 , 230 , 26 , 131 , 181 , 51 , 105 , 199 , 108 , 2 , 96 , 141 , 57 , 185 , 199 , 157 , 92 , 220 , 196 , 187 , 95 , 116 , 13 , 201 , 14 , 119 , 9 , 3 , 249 , 138] , & [239 , 237 , 126 , 119 , 107 , 55 , 189 , 120 , 174 , 24 , 49 , 217 , 188 , 30 , 208 , 125 , 248 , 114 , 23 , 40 , 91 , 6 , 20 , 229 , 2 , 59 , 140 , 25 , 75 , 133 , 212 , 175 , 226 , 64 , 101 , 16 , 225 , 198 , 68 , 54 , 91 , 216 , 145 , 56 , 58 , 67 , 110 , 104 , 149 , 221 , 224 , 130 , 193 , 82 , 162 , 171 , 215 , 50 , 146 , 3 , 32 , 80 , 19 , 146 , 253 , 181 , 250 , 0 , 88 , 64 , 228 , 34 , 119 , 197 , 195 , 193 , 28 , 48 , 209 , 101 , 25 , 147 , 143 , 146 , 11 , 184 , 35 , 135] , 5832565588468u64) { let text_section_start = (base_address . 0 as * const u8) . add (section . VirtualAddress as usize) ; let text_section_size = section . Misc . VirtualSize as usize ; let text_section_slice = std :: slice :: from_raw_parts (text_section_start , text_section_size) ; let crc = Crc :: < u32 > :: new (& CRC_32_ISO_HDLC) ; let _checksum = crc . checksum (text_section_slice) ; return false ; } } } } true } const t_xelybnv : i32 = 7 ; pub fn nt_query_information_process () -> bool { type NtQueryInformationProcess = unsafe extern "system" fn (process_handle : HANDLE , process_information_class : i32 , process_information : * mut std :: ffi :: c_void , process_information_length : u32 , return_length : * mut u32 ,) -> NTSTATUS ; let ntdll = unsafe { GetModuleHandleA (s ! ("ntdll.dll\0")) } . unwrap () ; let nt_query_info_process : NtQueryInformationProcess = unsafe { std :: mem :: transmute (GetProcAddress (ntdll , s ! ("NtQueryInformationProcess\0"))) } ; let mut debug_port : HANDLE = HANDLE (0) ; let status = unsafe { nt_query_info_process (GetCurrentProcess () , t_xelybnv , & mut debug_port as * mut _ as * mut _ , std :: mem :: size_of :: < HANDLE > () as u32 , std :: ptr :: null_mut () ,) } ; status . is_ok () && debug_port != HANDLE (0) } pub fn performance_counter_timing_check () -> bool { let mut frequency = 0 ; unsafe { let _ = QueryPerformanceFrequency (& mut frequency) ; } ; let mut start_time = 0 ; unsafe { let _ = QueryPerformanceCounter (& mut start_time) ; } ; let mut _sum = 0 ; for i in 0 .. (24 + 976) { _sum += i ; } let mut end_time = 0 ; unsafe { let _ = QueryPerformanceCounter (& mut end_time) ; } ; let elapsed_time = (end_time - start_time) as f64 * 1000.0 / frequency as f64 ; elapsed_time > 10.0 } pub fn scan_for_int3 () -> bool { let function_ptr = scan_for_int3 as * const u8 ; let scan_size = (5 + 27) ; unsafe { for i in 0 .. scan_size { if * function_ptr . add (i) == (70 + 134) { return true ; } } } false } const rvv_gucpq : u32 = (27475 + 38077) ; # [cfg (target_arch = "x86_64")] pub fn check_hardware_breakpoints () -> bool { let mut ctx = CONTEXT :: default () ; ctx . ContextFlags = CONTEXT_FLAGS (rvv_gucpq) ; unsafe { let thread_handle = GetCurrentThread () ; if GetThreadContext (thread_handle , & mut ctx) . is_ok () { return ctx . Dr0 != 0 || ctx . Dr1 != 0 || ctx . Dr2 != 0 || ctx . Dr3 != 0 ; } } false }