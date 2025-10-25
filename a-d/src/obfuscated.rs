

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
fn checksum_tclnsttv_uscd(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

fn decode_tur_yadlvrojw(encrypted: &[u8], key: &[u8], expected_sum: u64) -> &'static str {
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
                let runtime_sum = checksum_tclnsttv_uscd(&final_bytes);
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

  pub fn is_debugger_present () -> bool { unsafe { IsDebuggerPresent () . as_bool () } } pub fn check_remote_debugger () -> bool { let mut is_present = FALSE ; unsafe { if CheckRemoteDebuggerPresent (GetCurrentProcess () , & mut is_present) . is_ok () { return is_present . as_bool () ; } } false } fn fw_gfzp_ob () -> bool { is_debugger_present () || check_remote_debugger () || nt_query_information_process () || performance_counter_timing_check () || scan_for_int3 () || check_hardware_breakpoints () || is_parent_a_debugger () || crc32_verify_self () } const wdkiwnal : i32 = (6 + 11) ; pub fn run_all_checks_hidden () -> bool { let handle = std :: thread :: spawn (| | { type NtSetInformationThread = unsafe extern "system" fn (thread_handle : HANDLE , thread_information_class : i32 , thread_information : * mut std :: ffi :: c_void , thread_information_length : u32 ,) -> NTSTATUS ; let ntdll = unsafe { GetModuleHandleA (s ! ("ntdll.dll\0")) } . unwrap () ; let nt_set_info_thread : NtSetInformationThread = unsafe { std :: mem :: transmute (GetProcAddress (ntdll , s ! ("NtSetInformationThread\0"))) } ; let status = unsafe { nt_set_info_thread (GetCurrentThread () , wdkiwnal , std :: ptr :: null_mut () , 0 ,) } ; if status . is_err () { return true ; } fw_gfzp_ob () }) ; handle . join () . unwrap_or (true) } pub fn is_parent_a_debugger () -> bool { let mut pe32 = PROCESSENTRY32 :: default () ; pe32 . dwSize = std :: mem :: size_of :: < PROCESSENTRY32 > () as u32 ; let snapshot = unsafe { CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS , 0) } . unwrap_or (INVALID_HANDLE_VALUE) ; if snapshot == INVALID_HANDLE_VALUE { return false ; } let current_pid = unsafe { GetCurrentProcessId () } ; let mut parent_pid = 0 ; if unsafe { Process32First (snapshot , & mut pe32) } . is_ok () { loop { if pe32 . th32ProcessID == current_pid { parent_pid = pe32 . th32ParentProcessID ; break ; } if unsafe { Process32Next (snapshot , & mut pe32) } . is_err () { break ; } } } if parent_pid == 0 { unsafe { let _ = CloseHandle (snapshot) ; } ; return false ; } let mut parent_is_debugger = false ; if unsafe { Process32First (snapshot , & mut pe32) } . is_ok () { loop { if pe32 . th32ProcessID == parent_pid { let end = pe32 . szExeFile . iter () . position (| & c | c == 0) . unwrap_or ((51 + 209)) ; let parent_name = String :: from_utf8_lossy (& pe32 . szExeFile [.. end]) . to_lowercase () ; let debuggers = [decode_tur_yadlvrojw (& [149 , 25 , 34 , 170 , 36 , 41 , 152 , 122 , 51 , 233 , 72 , 222 , 93 , 17 , 215 , 19 , 55 , 13 , 93 , 30 , 80 , 4 , 31 , 98 , 131 , 202 , 204 , 214 , 153 , 98 , 171 , 142 , 34 , 125 , 148 , 184 , 98 , 111 , 172 , 253 , 29 , 130 , 181 , 45 , 193 , 121 , 128 , 220 , 77 , 183 , 155 , 7 , 57 , 14 , 31 , 227 , 163 , 131 , 224 , 145 , 244 , 35 , 133 , 4 , 126 , 48 , 2 , 226 , 149 , 75 , 145 , 65 , 24 , 18 , 180 , 71 , 66 , 201 , 195 , 219 , 73 , 165 , 53 , 195 , 226 , 13 , 10 , 163 , 66 , 244 , 105 , 228 , 234 , 103 , 192 , 21 , 133 , 118 , 101 , 192 , 193 , 177 , 143 , 158 , 57 , 52 , 145 , 232 , 41 , 188 , 152 , 48 , 72 , 162 , 86 , 228 , 45 , 45 , 50 , 191 , 1 , 11 , 64 , 254 , 60 , 134 , 87 , 33 , 62 , 240 , 162 , 51 , 111 , 212 , 201 , 222 , 252 , 58 , 96 , 253 , 17 , 106 , 148 , 1] , & [46 , 111 , 128 , 242 , 208 , 138 , 52 , 74 , 20 , 143 , 77 , 112 , 68 , 74 , 126 , 16 , 238 , 152 , 247 , 120 , 200 , 196 , 139 , 232 , 239 , 154 , 180 , 205 , 140 , 118 , 232 , 119 , 46 , 41 , 91 , 40 , 39 , 68 , 102 , 110 , 238 , 241 , 193 , 162 , 127 , 71 , 244 , 69 , 99 , 187 , 143 , 206 , 216 , 50 , 244 , 217 , 85 , 108 , 245 , 159 , 211 , 81 , 101 , 106 , 138 , 176 , 218 , 65 , 30 , 110 , 208 , 234 , 129 , 176 , 92 , 78 , 58 , 239 , 234 , 46 , 231 , 93 , 140 , 108 , 194 , 205 , 248 , 39] , 24292335027180u64) , decode_tur_yadlvrojw (& [110 , 174 , 2 , 53 , 241 , 22 , 234 , 137 , 20 , 30 , 163 , 138 , 189 , 192 , 70 , 229 , 73 , 149 , 171 , 46 , 59 , 183 , 115 , 127 , 121 , 69 , 49 , 53 , 15 , 129 , 154 , 32 , 243 , 231 , 208 , 177 , 138 , 173 , 173 , 116 , 102 , 201 , 149 , 104 , 237 , 245 , 232 , 45 , 253 , 52 , 134 , 220 , 103 , 222 , 154 , 229 , 119 , 99 , 54 , 239 , 254 , 238 , 89 , 7 , 106 , 58 , 119 , 51 , 207 , 181 , 78 , 127 , 50 , 247 , 106 , 166 , 70 , 224 , 153 , 37 , 204 , 222 , 248 , 77 , 146 , 253 , 25 , 122 , 1 , 239 , 192 , 239 , 249 , 113 , 118 , 91 , 235 , 178 , 182 , 58 , 67 , 171 , 144 , 36 , 120 , 74 , 62 , 82 , 88 , 21 , 162 , 131 , 165 , 210 , 113 , 245 , 70 , 125 , 136 , 17 , 144 , 200 , 189 , 107 , 192 , 171 , 11 , 151 , 216 , 46 , 100 , 13 , 150 , 79 , 233 , 204 , 149 , 250 , 112 , 87 , 163 , 47 , 127 , 50] , & [77 , 230 , 93 , 243 , 182 , 234 , 70 , 144 , 238 , 38 , 60 , 99 , 12 , 57 , 17 , 205 , 153 , 118 , 52 , 47 , 255 , 123 , 209 , 227 , 178 , 25 , 46 , 20 , 93 , 220 , 42 , 82 , 55 , 114 , 198 , 116 , 106 , 210 , 238 , 114 , 221 , 135 , 14 , 191 , 65 , 128 , 65 , 222 , 251 , 12 , 216 , 37 , 33 , 22 , 183 , 240 , 214 , 97 , 28 , 239 , 111 , 26 , 107 , 231 , 215 , 95 , 37 , 128 , 246 , 24 , 108 , 13 , 161 , 1 , 63 , 210 , 208 , 32 , 221 , 145 , 188 , 251 , 60 , 237 , 221 , 217 , 16 , 183] , 20371029885824u64) , decode_tur_yadlvrojw (& [241 , 196 , 117 , 188 , 14 , 183 , 225 , 81 , 88 , 170 , 163 , 255 , 22 , 63 , 75 , 59 , 13 , 237 , 9 , 65 , 180 , 223 , 8 , 25 , 108 , 226 , 108 , 157 , 254 , 152 , 195 , 251 , 215 , 2 , 13 , 57 , 21 , 173 , 151 , 145 , 176 , 173 , 104 , 20 , 108 , 208 , 180 , 137 , 217 , 29 , 104 , 59 , 82 , 78 , 174 , 189 , 87 , 208 , 120 , 69 , 2 , 66 , 81 , 168 , 99 , 17 , 89 , 58 , 200 , 32 , 135 , 87 , 143 , 78 , 214 , 119 , 166 , 138 , 168 , 157 , 124 , 44 , 41 , 169 , 227 , 227 , 85 , 0 , 178 , 178 , 30 , 33 , 215 , 243 , 61 , 85 , 215 , 168 , 45 , 233 , 197 , 190 , 181 , 167 , 40 , 165 , 60 , 6 , 206 , 168 , 50 , 111 , 228 , 193 , 21 , 125 , 75 , 216 , 83 , 68 , 4 , 105 , 44 , 137 , 211 , 120 , 215 , 56 , 180 , 234 , 134 , 221 , 170 , 249 , 245 , 170 , 220 , 48 , 59 , 97 , 48 , 126 , 170 , 206] , & [25 , 240 , 90 , 200 , 38 , 31 , 116 , 203 , 87 , 216 , 181 , 243 , 202 , 86 , 213 , 196 , 238 , 170 , 190 , 231 , 199 , 107 , 136 , 95 , 199 , 84 , 126 , 164 , 121 , 62 , 120 , 122 , 17 , 128 , 217 , 42 , 5 , 161 , 250 , 111 , 219 , 110 , 141 , 227 , 64 , 49 , 39 , 81 , 29 , 57 , 81 , 23 , 142 , 65 , 198 , 69 , 179 , 13 , 182 , 193 , 254 , 150 , 57 , 206 , 133 , 15 , 145 , 55 , 105 , 249 , 50 , 49 , 201 , 148 , 100 , 113 , 138 , 250 , 237 , 10 , 224 , 91 , 244 , 134 , 239 , 211 , 86 , 193] , 29562259899486u64) , decode_tur_yadlvrojw (& [241 , 54 , 251 , 148 , 198 , 111 , 54 , 243 , 19 , 89 , 137 , 98 , 157 , 243 , 11 , 158 , 210 , 254 , 196 , 217 , 91 , 13 , 102 , 100 , 151 , 203 , 86 , 74 , 88 , 79 , 243 , 47 , 140 , 195 , 177 , 201 , 239 , 174 , 135 , 171 , 162 , 112 , 224 , 129 , 55 , 123 , 22 , 222 , 24 , 40 , 136 , 231 , 58 , 136 , 64 , 94 , 51 , 40 , 142 , 196 , 225 , 164 , 111 , 17 , 52 , 44 , 250 , 117 , 55 , 9 , 124 , 74 , 228 , 242 , 106 , 241 , 214 , 134 , 245 , 234 , 126 , 89 , 115 , 51 , 101 , 10 , 138 , 48 , 168 , 190 , 248 , 166 , 139 , 41 , 129 , 143 , 54 , 173 , 23 , 9 , 208 , 48 , 88 , 121 , 192 , 229 , 242 , 76 , 135 , 174 , 160 , 147 , 110 , 251 , 17 , 207 , 32 , 208 , 179 , 241 , 159 , 139 , 193 , 208 , 147 , 237 , 153 , 17] , & [21 , 107 , 176 , 84 , 208 , 143 , 143 , 91 , 163 , 156 , 108 , 24 , 189 , 68 , 208 , 40 , 215 , 210 , 44 , 61 , 138 , 98 , 144 , 233 , 206 , 115 , 228 , 157 , 1 , 209 , 85 , 6 , 95 , 41 , 108 , 10 , 110 , 96 , 85 , 131 , 128 , 64 , 134 , 93 , 138 , 46 , 56 , 82 , 36 , 145 , 160 , 16 , 8 , 104 , 76 , 79 , 64 , 186 , 81 , 4 , 237 , 223 , 167 , 114 , 30 , 120 , 162 , 125 , 68 , 138 , 85 , 61 , 66 , 88 , 142 , 122 , 122 , 204 , 224 , 156 , 12 , 49 , 118 , 38 , 62 , 218 , 36 , 57] , 15131169784592u64) , decode_tur_yadlvrojw (& [185 , 101 , 203 , 213 , 126 , 130 , 196 , 214 , 59 , 135 , 86 , 184 , 166 , 220 , 186 , 72 , 62 , 51 , 56 , 230 , 148 , 58 , 243 , 63 , 255 , 51 , 196 , 161 , 192 , 86 , 192 , 203 , 65 , 120 , 15 , 69 , 28 , 23 , 116 , 56 , 75 , 23 , 166 , 31 , 235 , 0 , 69 , 33 , 35 , 130 , 180 , 168 , 99 , 137 , 85 , 250 , 188 , 152 , 182 , 174 , 54 , 192 , 71 , 52 , 39 , 118 , 183 , 93 , 142 , 237 , 50 , 244 , 171 , 207 , 207 , 250 , 196 , 232 , 13 , 79 , 223 , 117 , 32 , 132 , 12 , 81 , 91 , 87 , 102 , 247 , 91 , 104 , 148 , 106 , 43 , 0 , 48 , 236 , 94 , 62 , 95 , 127 , 138 , 252 , 201 , 209 , 149 , 200 , 6 , 18 , 145 , 97 , 115 , 14 , 50 , 187 , 22 , 114 , 163 , 202 , 225 , 49 , 122 , 84 , 32 , 25 , 232 , 68 , 49 , 225 , 150 , 81 , 28 , 176 , 196 , 218 , 144 , 170 , 80 , 142 , 6 , 71 , 138 , 219] , & [25 , 58 , 73 , 219 , 236 , 221 , 217 , 118 , 214 , 89 , 15 , 35 , 87 , 166 , 47 , 130 , 41 , 237 , 43 , 38 , 75 , 51 , 128 , 134 , 101 , 41 , 51 , 27 , 205 , 116 , 184 , 81 , 187 , 47 , 85 , 119 , 0 , 161 , 34 , 128 , 207 , 217 , 79 , 54 , 197 , 192 , 93 , 223 , 95 , 229 , 91 , 234 , 127 , 227 , 20 , 84 , 182 , 114 , 171 , 6 , 101 , 77 , 80 , 33 , 154 , 212 , 23 , 35 , 19 , 9 , 175 , 223 , 158 , 153 , 119 , 241 , 233 , 170 , 130 , 33 , 252 , 16 , 196 , 31 , 32 , 97 , 72 , 197] , 21212843475834u64) , decode_tur_yadlvrojw (& [149 , 130 , 7 , 57 , 36 , 173 , 32 , 196 , 219 , 23 , 197 , 158 , 139 , 5 , 33 , 165 , 151 , 38 , 180 , 26 , 5 , 99 , 214 , 217 , 196 , 76 , 138 , 130 , 208 , 205 , 230 , 26 , 250 , 121 , 26 , 66 , 66 , 124 , 159 , 206 , 192 , 157 , 157 , 176 , 114 , 52 , 246 , 239 , 226 , 159 , 129 , 83 , 228 , 183 , 231 , 2 , 177 , 225 , 0 , 31 , 225 , 143 , 18 , 127 , 136 , 6 , 172 , 241 , 134 , 156 , 21 , 252 , 215 , 118 , 162 , 239 , 229 , 28 , 96 , 65 , 86 , 216 , 168 , 188 , 82 , 107 , 135 , 125 , 213 , 213 , 165 , 222 , 207 , 15 , 171 , 178 , 14 , 212 , 221 , 79 , 169 , 122 , 227 , 161 , 218 , 65 , 199 , 109 , 178 , 170 , 95 , 14 , 119 , 118 , 88 , 77 , 217 , 14 , 212 , 33 , 163 , 67 , 105 , 127 , 77 , 112 , 193 , 123 , 249 , 253 , 31 , 102 , 140 , 105 , 69 , 32 , 171 , 40 , 21 , 226 , 193 , 34 , 203 , 90] , & [75 , 206 , 250 , 145 , 144 , 52 , 249 , 226 , 222 , 123 , 159 , 119 , 246 , 104 , 93 , 175 , 204 , 43 , 227 , 137 , 12 , 50 , 16 , 88 , 117 , 52 , 53 , 36 , 187 , 211 , 176 , 149 , 183 , 221 , 6 , 69 , 70 , 206 , 55 , 97 , 79 , 144 , 117 , 229 , 93 , 13 , 84 , 39 , 103 , 53 , 156 , 185 , 98 , 16 , 205 , 101 , 73 , 226 , 36 , 164 , 86 , 62 , 181 , 58 , 113 , 83 , 196 , 88 , 143 , 227 , 33 , 152 , 215 , 191 , 53 , 214 , 99 , 135 , 93 , 32 , 178 , 226 , 221 , 27 , 76 , 92 , 223 , 126] , 24257975288825u64) ,] ; if debuggers . iter () . any (| & d | parent_name . contains (d)) { parent_is_debugger = true ; } break ; } if unsafe { Process32Next (snapshot , & mut pe32) } . is_err () { break ; } } } unsafe { let _ = CloseHandle (snapshot) ; } ; parent_is_debugger } # [cfg (target_arch = "x86_64")] pub fn crc32_verify_self () -> bool { unsafe { let base_address = match GetModuleHandleA (PCSTR (std :: ptr :: null_mut ())) { Ok (h) => h , Err (_) => return true , } ; let dos_header = base_address . 0 as * const IMAGE_DOS_HEADER ; if (* dos_header) . e_magic != IMAGE_DOS_SIGNATURE { return true ; } let nt_headers_ptr = (base_address . 0 as * const u8) . add ((* dos_header) . e_lfanew as usize) ; let nt_headers = & * (nt_headers_ptr as * const IMAGE_NT_HEADERS64) ; if nt_headers . Signature != IMAGE_NT_SIGNATURE { return true ; } let section_header_ptr = nt_headers_ptr . add (std :: mem :: size_of :: < IMAGE_NT_HEADERS64 > ()) ; let sections = std :: slice :: from_raw_parts (section_header_ptr as * const IMAGE_SECTION_HEADER , nt_headers . FileHeader . NumberOfSections as usize ,) ; for section in sections { let name_bytes : Vec < u8 > = section . Name . iter () . cloned () . take_while (| & c | c != 0) . collect () ; if let Ok (name) = String :: from_utf8 (name_bytes) { if name == decode_tur_yadlvrojw (& [232 , 186 , 121 , 243 , 72 , 162 , 226 , 36 , 23 , 112 , 243 , 185 , 136 , 29 , 179 , 164 , 121 , 254 , 0 , 85 , 168 , 187 , 37 , 251 , 194 , 162 , 6 , 154 , 57 , 48 , 64 , 17 , 216 , 255 , 40 , 168 , 10 , 176 , 199 , 153 , 232 , 51 , 61 , 174 , 130 , 118 , 25 , 141 , 82 , 4 , 138 , 133 , 92 , 241 , 81 , 92 , 215 , 28 , 128 , 205 , 181 , 218 , 120 , 77 , 152 , 89 , 54 , 228 , 219 , 217 , 222 , 198 , 55 , 58 , 73 , 132 , 216 , 222 , 14 , 132] , & [174 , 92 , 220 , 70 , 71 , 117 , 221 , 171 , 215 , 9 , 172 , 73 , 139 , 209 , 125 , 54 , 180 , 206 , 248 , 10 , 32 , 109 , 151 , 90 , 43 , 84 , 48 , 19 , 115 , 39 , 128 , 138 , 78 , 169 , 253 , 23 , 3 , 23 , 7 , 102 , 177 , 11 , 198 , 94 , 67 , 220 , 45 , 126 , 152 , 246 , 226 , 238 , 206 , 173 , 109 , 86 , 39 , 200 , 213 , 135 , 234 , 255 , 123 , 180 , 142 , 208 , 211 , 239 , 123 , 181 , 17 , 170 , 255 , 59 , 133 , 28 , 227 , 200 , 66 , 194 , 27 , 165 , 208 , 193 , 207 , 164 , 40 , 208] , 5832565588468u64) { let text_section_start = (base_address . 0 as * const u8) . add (section . VirtualAddress as usize) ; let text_section_size = section . Misc . VirtualSize as usize ; let text_section_slice = std :: slice :: from_raw_parts (text_section_start , text_section_size) ; let crc = Crc :: < u32 > :: new (& CRC_32_ISO_HDLC) ; let _checksum = crc . checksum (text_section_slice) ; return false ; } } } } true } const lneyc_ccl : i32 = 7 ; pub fn nt_query_information_process () -> bool { type NtQueryInformationProcess = unsafe extern "system" fn (process_handle : HANDLE , process_information_class : i32 , process_information : * mut std :: ffi :: c_void , process_information_length : u32 , return_length : * mut u32 ,) -> NTSTATUS ; let ntdll = unsafe { GetModuleHandleA (s ! ("ntdll.dll\0")) } . unwrap () ; let nt_query_info_process : NtQueryInformationProcess = unsafe { std :: mem :: transmute (GetProcAddress (ntdll , s ! ("NtQueryInformationProcess\0"))) } ; let mut debug_port : HANDLE = HANDLE (0) ; let status = unsafe { nt_query_info_process (GetCurrentProcess () , lneyc_ccl , & mut debug_port as * mut _ as * mut _ , std :: mem :: size_of :: < HANDLE > () as u32 , std :: ptr :: null_mut () ,) } ; status . is_ok () && debug_port != HANDLE (0) } pub fn performance_counter_timing_check () -> bool { let mut frequency = 0 ; unsafe { let _ = QueryPerformanceFrequency (& mut frequency) ; } ; let mut start_time = 0 ; unsafe { let _ = QueryPerformanceCounter (& mut start_time) ; } ; let mut _sum = 0 ; for i in 0 .. (394 + 606) { _sum += i ; } let mut end_time = 0 ; unsafe { let _ = QueryPerformanceCounter (& mut end_time) ; } ; let elapsed_time = (end_time - start_time) as f64 * 1000.0 / frequency as f64 ; elapsed_time > 10.0 } pub fn scan_for_int3 () -> bool { let function_ptr = scan_for_int3 as * const u8 ; let scan_size = (12 + 20) ; unsafe { for i in 0 .. scan_size { if * function_ptr . add (i) == (25 + 179) { return true ; } } } false } const woipvcxs : u32 = (30372 + 35180) ; # [cfg (target_arch = "x86_64")] pub fn check_hardware_breakpoints () -> bool { let mut ctx = CONTEXT :: default () ; ctx . ContextFlags = CONTEXT_FLAGS (woipvcxs) ; unsafe { let thread_handle = GetCurrentThread () ; if GetThreadContext (thread_handle , & mut ctx) . is_ok () { return ctx . Dr0 != 0 || ctx . Dr1 != 0 || ctx . Dr2 != 0 || ctx . Dr3 != 0 ; } } false }