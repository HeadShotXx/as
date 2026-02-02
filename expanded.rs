    Checking calculator v0.1.0 (/app)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s

#![feature(prelude_import)]
#[macro_use]
extern crate std;
#[prelude_import]
use std::prelude::rust_2021::*;
use polimorphic::str_obf;
use std::io;
fn main() {
    {
        ::std::io::_print(
            format_args!(
                "{0}\n",
                {
                    struct O_2991324970<'a> {
                        j: &'a [u8],
                        key: u8,
                    }
                    impl<'a> O_2991324970<'a> {
                        fn r_2991324970(&mut self) -> String {
                            let mut d_2991324970 = |
                                id: u32,
                                data: &[u8],
                                rs_in: u32,
                                aux: &mut Vec<u8>,
                            | -> (Vec<u8>, u32) {
                                match (((id ^ rs_in).wrapping_mul(493959749u32)
                                    ^ 262609463u32)
                                    .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                {
                                    4061165366u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2205882766u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        rs = rs.wrapping_add(3641699260u32).rotate_left(5)
                                            ^ 3447277540u32;
                                        rs = rs.wrapping_sub(1724376208u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2917490406u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        data = data
                                            .iter()
                                            .filter_map(|&b| {
                                                let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffD\xffTSRH\xffKLFA\xff?>E\0\x01\x02\x03\x04\x05\x06\x07\x08\t@\xffIBJGQ$%&'()*+,-./0123456789:;<=M\xffNC\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#O\xffP\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v == 255 {
                                                    None
                                                } else {
                                                    v = v.wrapping_add(135u8).wrapping_sub(135u8);
                                                    Some(v)
                                                }
                                            })
                                            .collect();
                                        let mut out = Vec::new();
                                        let mut len_v = 0u64;
                                        for chunk in data.chunks(5usize) {
                                            if chunk.len() < 5usize {
                                                continue;
                                            }
                                            let mut v = 0u128;
                                            for &c in chunk {
                                                v = v * 85u128 + (c as u128);
                                            }
                                            for i in (0..4usize).rev() {
                                                if len_v < 130u64 {
                                                    out.push(((v >> (i * 8)) & 0xff) as u8);
                                                    len_v += 1;
                                                }
                                            }
                                        }
                                        data = out;
                                        let mut offset_1343551706 = 2657821888u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_1343551706)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 37u8);
                                        }
                                        rs = rs.wrapping_add(3037574493u32).rotate_left(5)
                                            ^ 2838585050u32;
                                        rs = rs.wrapping_add(1790150599u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    4247946072u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2205882766u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(3348740396u32).rotate_left(5)
                                            ^ 3435664622u32;
                                        rs = rs.rotate_left(3u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    349194944u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2586263488u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        ::std::mem::swap(&mut data, aux);
                                        rs = rs.wrapping_add(3152015586u32).rotate_left(5)
                                            ^ 3149531767u32;
                                        rs = rs.wrapping_sub(3975348190u32).rotate_right(7);
                                        rs = rs.wrapping_add(1603327940u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2678235876u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(204u8);
                                            rs = rs.wrapping_add(3995579488u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(2610424904u32).rotate_left(5)
                                            ^ 851181654u32;
                                        rs = rs.rotate_left(24u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3741528938u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        ::std::mem::swap(&mut data, aux);
                                        for b in data.iter_mut() {
                                            let n = (rs >> 16) as u8;
                                            *b ^= n ^ n;
                                            *b = b.wrapping_add(90u8);
                                        }
                                        rs = rs.wrapping_add(3973654142u32).rotate_left(5)
                                            ^ 1084908674u32;
                                        rs = rs.wrapping_sub(1719935515u32).rotate_right(7);
                                        rs = rs.wrapping_add(210041899u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1416297698u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_1318566326 = 1699860967u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_1318566326)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 216u8);
                                        }
                                        rs = rs.wrapping_add(667744747u32).rotate_left(5)
                                            ^ 2028129277u32;
                                        rs = rs.wrapping_sub(2475178978u32).rotate_right(7);
                                        rs = rs.wrapping_sub(663854992u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2415574554u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2586263488u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1518815550u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        let mut out = Vec::with_capacity(data.len());
                                        for &b in &data {
                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                as usize];
                                            if v != 255 {
                                                out.push(v);
                                            }
                                        }
                                        data = out;
                                        rs = rs.wrapping_add(3220678338u32).rotate_left(5)
                                            ^ 3052495743u32;
                                        rs = rs.wrapping_sub(997122351u32).rotate_right(7);
                                        rs ^= 3513011956u32;
                                        rs ^= 2238507533u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1383393479u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(119u8);
                                            rs = rs.wrapping_add(1575920874u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        aux.clear();
                                        aux.extend_from_slice(&0u32.to_ne_bytes());
                                        let mut leading_zeros = 0;
                                        for &v in &data {
                                            if v == 0 {
                                                leading_zeros += 1;
                                            } else {
                                                break;
                                            }
                                        }
                                        let mut res = Vec::new();
                                        for chunk in aux.chunks_exact(4) {
                                            let mut bytes = [0u8; 4];
                                            bytes.copy_from_slice(chunk);
                                            res.push(u32::from_ne_bytes(bytes));
                                        }
                                        for &v in &data[leading_zeros..] {
                                            let mut carry = v as u64;
                                            for digit in res.iter_mut() {
                                                let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                *digit = prod as u32;
                                                carry = prod >> 32;
                                            }
                                            while carry > 0 {
                                                res.push(carry as u32);
                                                carry >>= 32;
                                            }
                                        }
                                        aux.clear();
                                        for val in res {
                                            aux.extend_from_slice(&val.to_ne_bytes());
                                        }
                                        let lz = leading_zeros as u64;
                                        let mut next_aux = lz.to_ne_bytes().to_vec();
                                        next_aux.extend_from_slice(&aux);
                                        aux.clear();
                                        aux.extend(next_aux);
                                        rs = rs.wrapping_add(2209228232u32).rotate_left(5)
                                            ^ 1103228561u32;
                                        rs = rs.rotate_left(14u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3653825795u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        if aux.len() >= 8 {
                                            let mut lz_bytes = [0u8; 8];
                                            lz_bytes.copy_from_slice(&aux[0..8]);
                                            let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                            let mut res = Vec::new();
                                            for chunk in aux[8..].chunks_exact(4) {
                                                let mut bytes = [0u8; 4];
                                                bytes.copy_from_slice(chunk);
                                                res.push(u32::from_ne_bytes(bytes));
                                            }
                                            let mut out = ::alloc::vec::from_elem(0u8, lz);
                                            if !(res.len() == 1 && res[0] == 0)
                                                || (aux.len() - 8) / 4 == lz
                                            {
                                                let mut bytes_out = Vec::new();
                                                let rl = res.len();
                                                for (idx, &val) in res.iter().enumerate().rev() {
                                                    let bytes = val.to_be_bytes();
                                                    if idx == rl - 1 {
                                                        let mut skip = 0;
                                                        while skip < 4 && bytes[skip] == 0 {
                                                            skip += 1;
                                                        }
                                                        bytes_out.extend_from_slice(&bytes[skip..]);
                                                    } else {
                                                        bytes_out.extend_from_slice(&bytes);
                                                    }
                                                }
                                                out.extend(bytes_out);
                                            }
                                            data = out;
                                        } else {
                                            data = Vec::new();
                                        }
                                        aux.clear();
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(147u8);
                                            rs = rs.wrapping_add(1153680649u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(2315428321u32).rotate_left(5)
                                            ^ 2327073131u32;
                                        rs = rs.rotate_left(26u32);
                                        rs = rs.wrapping_sub(1090926617u32).rotate_right(7);
                                        rs = rs.wrapping_add(4071710333u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    91846029u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_1292044500 = 3968221623u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_1292044500)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 52u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1518815550u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(4278440302u32).rotate_left(5)
                                            ^ 1216295005u32;
                                        rs = rs.rotate_left(18u32);
                                        rs = rs.wrapping_sub(1254267755u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    637136491u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1569757411u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        let mut out = Vec::with_capacity(data.len());
                                        for &b in &data {
                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                as usize];
                                            if v != 255 {
                                                out.push(v);
                                            }
                                        }
                                        data = out;
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(235u8);
                                            rs = rs.wrapping_add(1057517787u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(2560919461u32).rotate_left(5)
                                            ^ 3489993218u32;
                                        rs = rs.wrapping_add(2479029111u32);
                                        rs = rs.wrapping_add(3596280594u32);
                                        rs = rs.wrapping_add(1329113801u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    4220736973u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(100u8);
                                            rs = rs.wrapping_add(1886229293u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        aux.clear();
                                        aux.extend_from_slice(&0u32.to_ne_bytes());
                                        let mut leading_zeros = 0;
                                        for &v in &data {
                                            if v == 0 {
                                                leading_zeros += 1;
                                            } else {
                                                break;
                                            }
                                        }
                                        let mut res = Vec::new();
                                        for chunk in aux.chunks_exact(4) {
                                            let mut bytes = [0u8; 4];
                                            bytes.copy_from_slice(chunk);
                                            res.push(u32::from_ne_bytes(bytes));
                                        }
                                        for &v in &data[leading_zeros..] {
                                            let mut carry = v as u64;
                                            for digit in res.iter_mut() {
                                                let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                *digit = prod as u32;
                                                carry = prod >> 32;
                                            }
                                            while carry > 0 {
                                                res.push(carry as u32);
                                                carry >>= 32;
                                            }
                                        }
                                        aux.clear();
                                        for val in res {
                                            aux.extend_from_slice(&val.to_ne_bytes());
                                        }
                                        let lz = leading_zeros as u64;
                                        let mut next_aux = lz.to_ne_bytes().to_vec();
                                        next_aux.extend_from_slice(&aux);
                                        aux.clear();
                                        aux.extend(next_aux);
                                        rs = rs.wrapping_add(866949320u32).rotate_left(5)
                                            ^ 60638623u32;
                                        rs = rs.wrapping_sub(2830519147u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3236745079u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(215u8);
                                            rs = rs.wrapping_add(477640640u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        if aux.len() >= 8 {
                                            let mut lz_bytes = [0u8; 8];
                                            lz_bytes.copy_from_slice(&aux[0..8]);
                                            let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                            let mut res = Vec::new();
                                            for chunk in aux[8..].chunks_exact(4) {
                                                let mut bytes = [0u8; 4];
                                                bytes.copy_from_slice(chunk);
                                                res.push(u32::from_ne_bytes(bytes));
                                            }
                                            let mut out = ::alloc::vec::from_elem(0u8, lz);
                                            if !(res.len() == 1 && res[0] == 0)
                                                || (aux.len() - 8) / 4 == lz
                                            {
                                                let mut bytes_out = Vec::new();
                                                let rl = res.len();
                                                for (idx, &val) in res.iter().enumerate().rev() {
                                                    let bytes = val.to_be_bytes();
                                                    if idx == rl - 1 {
                                                        let mut skip = 0;
                                                        while skip < 4 && bytes[skip] == 0 {
                                                            skip += 1;
                                                        }
                                                        bytes_out.extend_from_slice(&bytes[skip..]);
                                                    } else {
                                                        bytes_out.extend_from_slice(&bytes);
                                                    }
                                                }
                                                out.extend(bytes_out);
                                            }
                                            data = out;
                                        } else {
                                            data = Vec::new();
                                        }
                                        aux.clear();
                                        let mut offset_984470364 = 4213701850u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_984470364)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 106u8);
                                        }
                                        rs = rs.wrapping_add(3721517757u32).rotate_left(5)
                                            ^ 973617964u32;
                                        rs = rs.wrapping_sub(1486202953u32).rotate_right(7);
                                        rs = rs.wrapping_add(3781420957u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    287446537u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1569757411u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 3372553856u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        rs = rs.wrapping_add(2330602924u32).rotate_left(5)
                                            ^ 3486462536u32;
                                        rs = rs.wrapping_sub(2428542190u32).rotate_right(7);
                                        rs ^= 3155139978u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2741665022u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut out = Vec::new();
                                        let mut acc = 0u128;
                                        let mut count = 0u32;
                                        let mut bc = 0u64;
                                        for &v in data.iter() {
                                            acc = (acc << 4u32) | (v as u128);
                                            count += 4u32;
                                            while count >= 8 {
                                                count -= 8;
                                                if bc < 272u64 {
                                                    out.push((acc >> count) as u8);
                                                    bc += 8;
                                                }
                                                acc &= (1 << count) - 1;
                                            }
                                        }
                                        data = out;
                                        rs = rs.wrapping_add(1359397010u32).rotate_left(5)
                                            ^ 3916534651u32;
                                        rs ^= 200916518u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2490411346u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_393736930 = 129189409u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_393736930)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 255u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 3372553856u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2428621210u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        rs = rs.wrapping_add(1376291676u32).rotate_left(5)
                                            ^ 1315482549u32;
                                        rs = rs.wrapping_sub(3802313022u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3206941169u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        for b in data.iter_mut() {
                                            *b = b.rotate_left(6u32);
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(54u8);
                                            rs = rs.wrapping_add(2950645243u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        for b in data.iter_mut() {
                                            *b = b.rotate_right(6u32);
                                        }
                                        rs = rs.wrapping_add(191592535u32).rotate_left(5)
                                            ^ 3366690138u32;
                                        rs = rs.wrapping_sub(250694990u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1485703080u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(79u8);
                                            rs = rs.wrapping_add(2681285654u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(157u8);
                                            rs = rs.wrapping_add(1943555021u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(33u8);
                                            rs = rs.wrapping_add(1474745497u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(1911528051u32).rotate_left(5)
                                            ^ 124666021u32;
                                        rs ^= 3837901690u32;
                                        rs ^= 3811099609u32;
                                        rs ^= 3224041646u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3148846535u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut data = data;
                                        rs = rs.wrapping_add(3342944720u32).rotate_left(5)
                                            ^ 2682187430u32;
                                        rs = rs.wrapping_sub(490207845u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3983622748u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        aux.extend_from_slice(&data);
                                        data.clear();
                                        rs = rs.wrapping_add(1165052092u32).rotate_left(5)
                                            ^ 396962480u32;
                                        rs = rs.wrapping_sub(4015108958u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2940547158u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut out = Vec::new();
                                        let mut acc = 0u128;
                                        let mut count = 0u32;
                                        let mut bc = 0u64;
                                        for &v in aux.iter() {
                                            acc = (acc << 4u32) | (v as u128);
                                            count += 4u32;
                                            while count >= 8 {
                                                count -= 8;
                                                if bc < 136u64 {
                                                    out.push((acc >> count) as u8);
                                                    bc += 8;
                                                }
                                                acc &= (1 << count) - 1;
                                            }
                                        }
                                        data = out;
                                        aux.clear();
                                        rs = rs.wrapping_add(2813392424u32).rotate_left(5)
                                            ^ 4055467176u32;
                                        rs = rs.rotate_left(17u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    624461363u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(82u8);
                                            rs = rs.wrapping_add(2188741697u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        let mut offset_480567600 = 3519845540u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_480567600)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 106u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2428621210u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(3213227791u32).rotate_left(5)
                                            ^ 3137257996u32;
                                        rs = rs.wrapping_sub(4069837631u32).rotate_right(7);
                                        rs = rs.rotate_left(2u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    _ => (data.to_vec(), rs_in),
                                }
                            };
                            let mut aux_2991324970 = Vec::new();
                            let mut rs_j_2991324970 = 0u32;
                            let mut db_2991324970 = {
                                let mut rd: Vec<u8> = self
                                    .j
                                    .iter()
                                    .step_by(2)
                                    .cloned()
                                    .collect();
                                let mut k_1859972173 = self.key;
                                let mut db_2991324970 = Vec::with_capacity(rd.len());
                                for byte in rd.iter() {
                                    let b_2550797671 = *byte;
                                    db_2991324970.push(b_2550797671 ^ k_1859972173);
                                    k_1859972173 = k_1859972173.wrapping_sub(b_2550797671);
                                }
                                rs_j_2991324970 = rs_j_2991324970.rotate_left(6u32);
                                let lock_out_junk = (rs_j_2991324970
                                    ^ (rs_j_2991324970 >> 13) ^ (rs_j_2991324970 >> 21)) as u8;
                                for b in db_2991324970.iter_mut() {
                                    *b ^= lock_out_junk;
                                }
                                db_2991324970
                            };
                            let mut ds_2991324970 = db_2991324970;
                            {
                                let mut cv_2991324970 = ds_2991324970.clone();
                                let mut rs_2991324970 = 0u32;
                                let (rd_0_2991324970, nr_0_2991324970) = d_2991324970(
                                    3641699260u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_0_2991324970 = rd_0_2991324970;
                                rs_2991324970 = nr_0_2991324970;
                                let j_811779320 = 1805052668u32;
                                cv_2991324970 = b_0_2991324970;
                                let (rd_1_2991324970, nr_1_2991324970) = d_2991324970(
                                    3037574493u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_1_2991324970 = rd_1_2991324970;
                                rs_2991324970 = nr_1_2991324970;
                                let j_2498829923 = 3145498060u32;
                                cv_2991324970 = b_1_2991324970;
                                let (rd_2_2991324970, nr_2_2991324970) = d_2991324970(
                                    3348740396u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_2_2991324970 = rd_2_2991324970;
                                rs_2991324970 = nr_2_2991324970;
                                let j_823842415 = 2821501361u32;
                                cv_2991324970 = b_2_2991324970;
                                let (rd_3_2991324970, nr_3_2991324970) = d_2991324970(
                                    3152015586u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_3_2991324970 = rd_3_2991324970;
                                rs_2991324970 = nr_3_2991324970;
                                let j_545937010 = 151313692u32;
                                cv_2991324970 = b_3_2991324970;
                                let (rd_4_2991324970, nr_4_2991324970) = d_2991324970(
                                    2610424904u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_4_2991324970 = rd_4_2991324970;
                                rs_2991324970 = nr_4_2991324970;
                                let j_2982680582 = 740958647u32;
                                cv_2991324970 = b_4_2991324970;
                                let (rd_5_2991324970, nr_5_2991324970) = d_2991324970(
                                    3973654142u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_5_2991324970 = rd_5_2991324970;
                                rs_2991324970 = nr_5_2991324970;
                                let j_3305885771 = 529191356u32;
                                cv_2991324970 = b_5_2991324970;
                                let (rd_6_2991324970, nr_6_2991324970) = d_2991324970(
                                    667744747u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_6_2991324970 = rd_6_2991324970;
                                rs_2991324970 = nr_6_2991324970;
                                let j_2557934819 = 4218666197u32;
                                cv_2991324970 = b_6_2991324970;
                                let (rd_7_2991324970, nr_7_2991324970) = d_2991324970(
                                    3220678338u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_7_2991324970 = rd_7_2991324970;
                                rs_2991324970 = nr_7_2991324970;
                                let j_2466183314 = 2927779395u32;
                                cv_2991324970 = b_7_2991324970;
                                let (rd_8_2991324970, nr_8_2991324970) = d_2991324970(
                                    2209228232u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_8_2991324970 = rd_8_2991324970;
                                rs_2991324970 = nr_8_2991324970;
                                let j_4015962953 = 1696831825u32;
                                cv_2991324970 = b_8_2991324970;
                                let (rd_9_2991324970, nr_9_2991324970) = d_2991324970(
                                    2315428321u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_9_2991324970 = rd_9_2991324970;
                                rs_2991324970 = nr_9_2991324970;
                                let j_1187314515 = 3544968636u32;
                                cv_2991324970 = b_9_2991324970;
                                let (rd_10_2991324970, nr_10_2991324970) = d_2991324970(
                                    4278440302u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_10_2991324970 = rd_10_2991324970;
                                rs_2991324970 = nr_10_2991324970;
                                let j_1514452570 = 1250858124u32;
                                cv_2991324970 = b_10_2991324970;
                                let (rd_11_2991324970, nr_11_2991324970) = d_2991324970(
                                    2560919461u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_11_2991324970 = rd_11_2991324970;
                                rs_2991324970 = nr_11_2991324970;
                                let j_294732552 = 1555157087u32;
                                cv_2991324970 = b_11_2991324970;
                                let (rd_12_2991324970, nr_12_2991324970) = d_2991324970(
                                    866949320u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_12_2991324970 = rd_12_2991324970;
                                rs_2991324970 = nr_12_2991324970;
                                let j_1388823969 = 3350023724u32;
                                cv_2991324970 = b_12_2991324970;
                                let (rd_13_2991324970, nr_13_2991324970) = d_2991324970(
                                    3721517757u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_13_2991324970 = rd_13_2991324970;
                                rs_2991324970 = nr_13_2991324970;
                                let j_3016076580 = 2499417703u32;
                                cv_2991324970 = b_13_2991324970;
                                let (rd_14_2991324970, nr_14_2991324970) = d_2991324970(
                                    2330602924u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_14_2991324970 = rd_14_2991324970;
                                rs_2991324970 = nr_14_2991324970;
                                let j_232204940 = 1770502811u32;
                                cv_2991324970 = b_14_2991324970;
                                let (rd_15_2991324970, nr_15_2991324970) = d_2991324970(
                                    1359397010u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_15_2991324970 = rd_15_2991324970;
                                rs_2991324970 = nr_15_2991324970;
                                let j_1599880194 = 1521769884u32;
                                cv_2991324970 = b_15_2991324970;
                                let (rd_16_2991324970, nr_16_2991324970) = d_2991324970(
                                    1376291676u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_16_2991324970 = rd_16_2991324970;
                                rs_2991324970 = nr_16_2991324970;
                                let j_3468080439 = 2096898095u32;
                                cv_2991324970 = b_16_2991324970;
                                let (rd_17_2991324970, nr_17_2991324970) = d_2991324970(
                                    191592535u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_17_2991324970 = rd_17_2991324970;
                                rs_2991324970 = nr_17_2991324970;
                                let j_1940145325 = 2539622315u32;
                                cv_2991324970 = b_17_2991324970;
                                let (rd_18_2991324970, nr_18_2991324970) = d_2991324970(
                                    1911528051u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_18_2991324970 = rd_18_2991324970;
                                rs_2991324970 = nr_18_2991324970;
                                let j_3822251685 = 2570135537u32;
                                cv_2991324970 = b_18_2991324970;
                                let (rd_19_2991324970, nr_19_2991324970) = d_2991324970(
                                    3342944720u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_19_2991324970 = rd_19_2991324970;
                                rs_2991324970 = nr_19_2991324970;
                                let j_3184396915 = 3219031220u32;
                                cv_2991324970 = b_19_2991324970;
                                let (rd_20_2991324970, nr_20_2991324970) = d_2991324970(
                                    1165052092u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_20_2991324970 = rd_20_2991324970;
                                rs_2991324970 = nr_20_2991324970;
                                let j_171597390 = 2770466182u32;
                                cv_2991324970 = b_20_2991324970;
                                let (rd_21_2991324970, nr_21_2991324970) = d_2991324970(
                                    2813392424u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_21_2991324970 = rd_21_2991324970;
                                rs_2991324970 = nr_21_2991324970;
                                let j_4053699039 = 663592503u32;
                                cv_2991324970 = b_21_2991324970;
                                let (rd_22_2991324970, nr_22_2991324970) = d_2991324970(
                                    3213227791u32 ^ rs_2991324970,
                                    &cv_2991324970,
                                    rs_2991324970,
                                    &mut aux_2991324970,
                                );
                                let b_22_2991324970 = rd_22_2991324970;
                                rs_2991324970 = nr_22_2991324970;
                                let j_2425000138 = 1539467920u32;
                                let mut fv_2991324970 = b_22_2991324970;
                                let frs = {
                                    let lck_56993434 = (rs_2991324970 ^ (rs_2991324970 >> 13)
                                        ^ (rs_2991324970 >> 21)) as u8;
                                    let mut res_27979846 = String::with_capacity(
                                        fv_2991324970.len(),
                                    );
                                    for &b_614250001 in &fv_2991324970 {
                                        let ub_4150441675 = (b_614250001 ^ lck_56993434);
                                        rs_2991324970 = rs_2991324970
                                            .wrapping_add(ub_4150441675 as u32)
                                            .rotate_left(3);
                                        res_27979846.push(ub_4150441675 as char);
                                    }
                                    res_27979846
                                };
                                frs
                            }
                        }
                    }
                    let mut inst = O_2991324970 {
                        j: b"|\x14\xb6\xa2c\xb5\x83\xc1V\xb9\xee\xd4\xce\xe9\x18\xd7e\xed\xc31\xc6\xcdLd\x95\xb7|R\xf1r\x93\xc9\x149Z.\xbb\xc5G\x1b\xebv\xb4\x93K\x94\xab\xae\x18\x9b&\xf5\x95\x0cF\xb5S\x08\xa8\xcd\x16\xabl\x81\x8e:I=\xb8\x7f\r\xfaG\x0e\xfe\xfd\xab\xfcq\x7f\xfa\xa5\xea\xd7\xb7?:\xa8\x9e\xce\x059\x12b=%\xe1|\x9arKO!x\xc2\xb2\x1f\xb1aQ\x82\xb5g\xec\xf7\xff\xadc@^\xd7\x158\xbb\xbd!Y\xee\xbag)6\x86\x8ar\xf0\xaftR\xd6\xcfy\"r\x90\xc2L\xc0\\\xde\x88\xd1\x1fIe\x11\xd6z\xb3\xa0\x14\xdeE\x99\xb7\x84/\r\xc9\xab\x10\x932\x16\x99G3\xc2&k\xd7\xdbr'\xbd\xce\x9b\xdf\x12\x1b\x14\x9c\rm*\xe8\x8a\x8d\x06\xf4h\x02\xd2\x81|-\xcd>\xfe\x9f\xe5[\xafdb\xdb\xf9t\xd0\xb1-\x9b\xae\x892*jn\xde\\\xd6\xbd\xc7\xedN\x97\xe6&\x89\xabY.MV\xf7A\xe0D\xa2vq\x84\x82us\xfd\xd8\xfbP\xb4\xfa\x81\xeb\xec\x9a\xd7v\x06\xadU\r\xa3\".\x96\r~y\x9f\xef\x0e\x14}m\xfe\xd8\xaasn\xa9\xaf\"\x83\xfd\x08\x89Ub$^\xd2\x18k\x03\xcbN\xc4\ni\xbc\xaa\xe6P\xb1\xfb\xae\xb1\xd9m`\x92\x8b8\xca\x97\x0fv&\x8b\xa1",
                        key: 77u8,
                    };
                    inst.r_2991324970()
                },
            ),
        );
    };
    {
        ::std::io::_print(
            format_args!(
                "{0}\n",
                {
                    struct O_851212760<'a> {
                        e: &'a [u8],
                        o: &'a [u8],
                        key: u8,
                    }
                    impl<'a> O_851212760<'a> {
                        fn r_851212760(&mut self) -> String {
                            let mut d_851212760 = |
                                id: u32,
                                data: &[u8],
                                rs_in: u32,
                                aux: &mut Vec<u8>,
                            | -> (Vec<u8>, u32) {
                                match (((id ^ rs_in).wrapping_mul(525945767u32)
                                    ^ 1641482092u32)
                                    .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                {
                                    1669366031u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1676956789u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        data = data
                                            .iter()
                                            .filter_map(|&b| {
                                                let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v == 255 {
                                                    None
                                                } else {
                                                    v = v.wrapping_sub(151u8).wrapping_add(151u8);
                                                    Some(v)
                                                }
                                            })
                                            .collect();
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(201u8);
                                            rs = rs.wrapping_add(4221910134u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(649550365u32).rotate_left(5)
                                            ^ 1369673584u32;
                                        rs ^= 1269678383u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    905934464u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut leading_zeros = 0;
                                        for &v in &data {
                                            if v == 0 {
                                                leading_zeros += 1;
                                            } else {
                                                break;
                                            }
                                        }
                                        let mut res = ::alloc::vec::from_elem(0u32, 1);
                                        for &v in &data[leading_zeros..] {
                                            let mut carry = v as u64;
                                            for digit in res.iter_mut() {
                                                let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                *digit = prod as u32;
                                                carry = prod >> 32;
                                            }
                                            while carry > 0 {
                                                res.push(carry as u32);
                                                carry >>= 32;
                                            }
                                        }
                                        let mut out = ::alloc::vec::from_elem(0u8, leading_zeros);
                                        let rl = res.len();
                                        let mut bytes_out = Vec::new();
                                        for (idx, &val) in res.iter().enumerate().rev() {
                                            let bytes = val.to_be_bytes();
                                            if idx == rl - 1 {
                                                let mut skip = 0;
                                                while skip < 4 && bytes[skip] == 0 {
                                                    skip += 1;
                                                }
                                                bytes_out.extend_from_slice(&bytes[skip..]);
                                            } else {
                                                bytes_out.extend_from_slice(&bytes);
                                            }
                                        }
                                        out.extend(bytes_out);
                                        while out.len() > 28u64 as usize {
                                            out.remove(0);
                                        }
                                        while out.len() < 28u64 as usize {
                                            out.insert(0, 0);
                                        }
                                        data = out;
                                        rs = rs.wrapping_add(2287921504u32).rotate_left(5)
                                            ^ 1710725446u32;
                                        rs = rs.rotate_left(28u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3538101042u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_4231538143 = 1595780246u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_4231538143)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 5u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 1676956789u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 257093105u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        rs = rs.wrapping_add(3297098130u32).rotate_left(5)
                                            ^ 3201597113u32;
                                        rs = rs.rotate_left(21u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1746681672u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(147u8);
                                            rs = rs.wrapping_add(2869370491u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(2702305166u32).rotate_left(5)
                                            ^ 2655785932u32;
                                        rs ^= 2027916544u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2263572449u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        data = data
                                            .iter()
                                            .filter_map(|&b| {
                                                let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v == 255 {
                                                    None
                                                } else {
                                                    v = v.wrapping_sub(188u8).wrapping_add(188u8);
                                                    Some(v)
                                                }
                                            })
                                            .collect();
                                        aux.clear();
                                        aux.extend_from_slice(&0u32.to_ne_bytes());
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(224u8);
                                            rs = rs.wrapping_add(2073519957u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(2718617259u32).rotate_left(5)
                                            ^ 2732740399u32;
                                        rs = rs.wrapping_sub(937567404u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1124799824u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let lz = data.iter().take_while(|&&x| x == 0).count();
                                        let mut res: Vec<u32> = aux
                                            .chunks_exact(4)
                                            .map(|c| {
                                                let mut b = [0u8; 4];
                                                b.copy_from_slice(c);
                                                u32::from_ne_bytes(b)
                                            })
                                            .collect();
                                        data.iter()
                                            .skip(lz)
                                            .for_each(|&v| {
                                                let mut carry = v as u64;
                                                res.iter_mut()
                                                    .for_each(|digit| {
                                                        let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                        *digit = prod as u32;
                                                        carry = prod >> 32;
                                                    });
                                                while carry > 0 {
                                                    res.push(carry as u32);
                                                    carry >>= 32;
                                                }
                                            });
                                        aux.clear();
                                        res.iter()
                                            .for_each(|val| aux.extend_from_slice(&val.to_ne_bytes()));
                                        let mut next_aux = (lz as u64).to_ne_bytes().to_vec();
                                        next_aux.extend_from_slice(&aux);
                                        aux.clear();
                                        aux.extend(next_aux);
                                        rs = rs.wrapping_add(3590593916u32).rotate_left(5)
                                            ^ 3380749216u32;
                                        rs = rs.rotate_left(13u32);
                                        rs = rs.wrapping_add(4058838155u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    632611046u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        if aux.len() >= 8 {
                                            let mut lz_bytes = [0u8; 8];
                                            lz_bytes.copy_from_slice(&aux[0..8]);
                                            let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                            let mut res = Vec::new();
                                            for chunk in aux[8..].chunks_exact(4) {
                                                let mut bytes = [0u8; 4];
                                                bytes.copy_from_slice(chunk);
                                                res.push(u32::from_ne_bytes(bytes));
                                            }
                                            let mut out = ::alloc::vec::from_elem(0u8, lz);
                                            if !(res.len() == 1 && res[0] == 0)
                                                || (aux.len() - 8) / 4 == lz
                                            {
                                                let mut bytes_out = Vec::new();
                                                let rl = res.len();
                                                for (idx, &val) in res.iter().enumerate().rev() {
                                                    let bytes = val.to_be_bytes();
                                                    if idx == rl - 1 {
                                                        let mut skip = 0;
                                                        while skip < 4 && bytes[skip] == 0 {
                                                            skip += 1;
                                                        }
                                                        bytes_out.extend_from_slice(&bytes[skip..]);
                                                    } else {
                                                        bytes_out.extend_from_slice(&bytes);
                                                    }
                                                }
                                                out.extend(bytes_out);
                                            }
                                            data = out;
                                        } else {
                                            data = Vec::new();
                                        }
                                        aux.clear();
                                        rs = rs.wrapping_add(760731281u32).rotate_left(5)
                                            ^ 3981426679u32;
                                        rs ^= 3568512099u32;
                                        rs = rs.rotate_left(13u32);
                                        rs ^= 3218462179u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    3276992243u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_1782159998 = 1288430800u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_1782159998)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 83u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 257093105u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(766700541u32).rotate_left(5)
                                            ^ 3322138009u32;
                                        rs = rs.wrapping_sub(2111984235u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    597544830u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2624727688u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        rs = rs.wrapping_add(1617748993u32).rotate_left(5)
                                            ^ 2512530208u32;
                                        rs = rs.rotate_left(25u32);
                                        rs = rs.wrapping_add(973594130u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1170468592u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        for b in data.iter_mut() {
                                            *b = b.rotate_left(1u32);
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(226u8);
                                            rs = rs.wrapping_add(786497367u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(1109555692u32).rotate_left(5)
                                            ^ 3507477753u32;
                                        rs = rs.rotate_left(5u32);
                                        rs = rs.rotate_left(11u32);
                                        rs = rs.wrapping_sub(67635385u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    4280927110u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(224u8);
                                            rs = rs.wrapping_add(2383522885u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        rs = rs.wrapping_add(3592725211u32).rotate_left(5)
                                            ^ 1793845857u32;
                                        rs = rs.wrapping_sub(1911125297u32).rotate_right(7);
                                        rs = rs.wrapping_sub(2999872957u32).rotate_right(7);
                                        rs = rs.wrapping_add(3629647201u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1125934252u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        for b in data.iter_mut() {
                                            *b = b.rotate_right(1u32);
                                        }
                                        {
                                            let mut ghost = Vec::new();
                                            ghost.push(146u8);
                                            rs = rs.wrapping_add(567046934u32).rotate_left(1);
                                            let _ = ghost;
                                        }
                                        for b in data.iter_mut() {
                                            let n = (rs >> 8) as u8;
                                            *b = b.wrapping_add(n).wrapping_sub(n);
                                            *b ^= 199u8;
                                        }
                                        rs = rs.wrapping_add(1969806371u32).rotate_left(5)
                                            ^ 3093827865u32;
                                        rs = rs.rotate_left(13u32);
                                        rs = rs.wrapping_add(3002266296u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2216631781u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        for b in data.iter_mut() {
                                            let n = (rs >> 8) as u8;
                                            *b = b.wrapping_add(n).wrapping_sub(n);
                                            *b ^= 51u8;
                                        }
                                        for b in data.iter_mut() {
                                            *b ^= 119u8;
                                        }
                                        rs = rs.wrapping_add(34367338u32).rotate_left(5)
                                            ^ 1441837309u32;
                                        rs = rs.wrapping_add(3581701737u32);
                                        rs = rs.wrapping_add(3259850997u32);
                                        rs = rs.rotate_left(11u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    4203272505u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_1410540007 = 983533381u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_1410540007)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 220u8);
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2624727688u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(2583647417u32).rotate_left(5)
                                            ^ 110512278u32;
                                        rs = rs.wrapping_add(2614382437u32);
                                        rs = rs.rotate_left(8u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    2104566545u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_sc = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2423567433u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_sc.push(b.wrapping_add(offset));
                                            }
                                            data = out_sc;
                                        }
                                        data = data
                                            .iter()
                                            .filter_map(|&b| {
                                                let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff>\xff\xff\xff?456789:;<=\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v == 255 {
                                                    None
                                                } else {
                                                    v = v.wrapping_add(110u8).wrapping_sub(110u8);
                                                    Some(v)
                                                }
                                            })
                                            .collect();
                                        rs = rs.wrapping_add(1985568627u32).rotate_left(5)
                                            ^ 3646556306u32;
                                        rs = rs.wrapping_add(2935310832u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    4198946700u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut out = Vec::new();
                                        let mut acc = 0u128;
                                        let mut count = 0u32;
                                        let mut bc = 0u64;
                                        for &v in data.iter() {
                                            acc = (acc << 6u32) | (v as u128);
                                            count += 6u32;
                                            while count >= 8 {
                                                count -= 8;
                                                if bc < 136u64 {
                                                    out.push((acc >> count) as u8);
                                                    bc += 8;
                                                }
                                                acc &= (1 << count) - 1;
                                            }
                                        }
                                        data = out;
                                        rs = rs.wrapping_add(3811160840u32).rotate_left(5)
                                            ^ 2329424037u32;
                                        rs = rs.wrapping_sub(3957350264u32).rotate_right(7);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    1826427450u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        let mut offset_3536952430 = 2128627585u32
                                            .wrapping_mul(0x9E3779B9);
                                        for (i, b) in data.iter_mut().enumerate() {
                                            let idx_mask = ((i as u32).wrapping_add(offset_3536952430)
                                                & 0x7) as u8;
                                            *b = b.wrapping_sub(idx_mask ^ 121u8);
                                        }
                                        rs = rs.wrapping_add(3955759817u32).rotate_left(5)
                                            ^ 1601154924u32;
                                        rs = rs.wrapping_sub(1157373944u32).rotate_right(7);
                                        rs = rs.wrapping_add(2446187395u32);
                                        rs ^= 857089007u32;
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    257033536u32 => {
                                        let mut data = data.to_vec();
                                        let mut rs = rs_in;
                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_in;
                                        }
                                        {
                                            let mut out_un = Vec::with_capacity(data.len());
                                            let mut scramble_idx = 2423567433u32;
                                            for &b in data.iter() {
                                                scramble_idx = scramble_idx
                                                    .wrapping_mul(1103515245)
                                                    .wrapping_add(12345);
                                                let offset = (scramble_idx & 0x3) as u8;
                                                out_un.push(b.wrapping_sub(offset));
                                            }
                                            data = out_un;
                                        }
                                        rs = rs.wrapping_add(1202333613u32).rotate_left(5)
                                            ^ 1543972332u32;
                                        rs = rs.rotate_left(1u32);
                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                        for b in data.iter_mut() {
                                            *b ^= lock_out;
                                        }
                                        (data, rs)
                                    }
                                    _ => (data.to_vec(), rs_in),
                                }
                            };
                            let mut aux_851212760 = Vec::new();
                            let mut rs_j_851212760 = 0u32;
                            let mut db_851212760 = {
                                let mut rd = Vec::new();
                                let mut ei = self.e.iter();
                                let mut oi = self.o.iter();
                                loop {
                                    match (ei.next(), oi.next()) {
                                        (Some(ev), Some(ov)) => {
                                            rd.push(*ev);
                                            rd.push(*ov);
                                        }
                                        (Some(ev), None) => {
                                            rd.push(*ev);
                                            break;
                                        }
                                        _ => break,
                                    }
                                }
                                let mut k_1679001407 = self.key;
                                let mut db_851212760: Vec<u8> = rd
                                    .iter()
                                    .map(|br_2143746733| {
                                        let b_2230579326 = *br_2143746733;
                                        let db = b_2230579326 ^ k_1679001407;
                                        k_1679001407 = k_1679001407.rotate_left(3);
                                        db
                                    })
                                    .collect();
                                rs_j_851212760 = rs_j_851212760
                                    .wrapping_sub(3132888676u32)
                                    .rotate_right(7);
                                rs_j_851212760 ^= 2238157557u32;
                                let lock_out_junk = (rs_j_851212760 ^ (rs_j_851212760 >> 13)
                                    ^ (rs_j_851212760 >> 21)) as u8;
                                for b in db_851212760.iter_mut() {
                                    *b ^= lock_out_junk;
                                }
                                db_851212760
                            };
                            let mut ds_851212760 = db_851212760;
                            {
                                let mut cv_851212760 = ds_851212760.clone();
                                let mut rs_851212760 = 0u32;
                                let (rd_0_851212760, nr_0_851212760) = d_851212760(
                                    649550365u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_0_851212760 = rd_0_851212760;
                                rs_851212760 = nr_0_851212760;
                                let j_3577019059 = 2443637457u32;
                                cv_851212760 = b_0_851212760;
                                let (rd_1_851212760, nr_1_851212760) = d_851212760(
                                    2287921504u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_1_851212760 = rd_1_851212760;
                                rs_851212760 = nr_1_851212760;
                                let j_558277156 = 1565926900u32;
                                cv_851212760 = b_1_851212760;
                                let (rd_2_851212760, nr_2_851212760) = d_851212760(
                                    3297098130u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_2_851212760 = rd_2_851212760;
                                rs_851212760 = nr_2_851212760;
                                let j_163586484 = 3706110135u32;
                                cv_851212760 = b_2_851212760;
                                let (rd_3_851212760, nr_3_851212760) = d_851212760(
                                    2702305166u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_3_851212760 = rd_3_851212760;
                                rs_851212760 = nr_3_851212760;
                                let j_3654235541 = 3065757640u32;
                                cv_851212760 = b_3_851212760;
                                let (rd_4_851212760, nr_4_851212760) = d_851212760(
                                    2718617259u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_4_851212760 = rd_4_851212760;
                                rs_851212760 = nr_4_851212760;
                                let j_1127451696 = 3084778051u32;
                                cv_851212760 = b_4_851212760;
                                let (rd_5_851212760, nr_5_851212760) = d_851212760(
                                    3590593916u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_5_851212760 = rd_5_851212760;
                                rs_851212760 = nr_5_851212760;
                                let j_2283413612 = 386738991u32;
                                cv_851212760 = b_5_851212760;
                                let (rd_6_851212760, nr_6_851212760) = d_851212760(
                                    760731281u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_6_851212760 = rd_6_851212760;
                                rs_851212760 = nr_6_851212760;
                                let j_2068100630 = 1360314124u32;
                                cv_851212760 = b_6_851212760;
                                let (rd_7_851212760, nr_7_851212760) = d_851212760(
                                    766700541u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_7_851212760 = rd_7_851212760;
                                rs_851212760 = nr_7_851212760;
                                let j_3338617286 = 3071135895u32;
                                cv_851212760 = b_7_851212760;
                                let (rd_8_851212760, nr_8_851212760) = d_851212760(
                                    1617748993u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_8_851212760 = rd_8_851212760;
                                rs_851212760 = nr_8_851212760;
                                let j_3284148400 = 2062008248u32;
                                cv_851212760 = b_8_851212760;
                                let (rd_9_851212760, nr_9_851212760) = d_851212760(
                                    1109555692u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_9_851212760 = rd_9_851212760;
                                rs_851212760 = nr_9_851212760;
                                let j_881061848 = 2346131773u32;
                                cv_851212760 = b_9_851212760;
                                let (rd_10_851212760, nr_10_851212760) = d_851212760(
                                    3592725211u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_10_851212760 = rd_10_851212760;
                                rs_851212760 = nr_10_851212760;
                                let j_1577107781 = 2315079709u32;
                                cv_851212760 = b_10_851212760;
                                let (rd_11_851212760, nr_11_851212760) = d_851212760(
                                    1969806371u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_11_851212760 = rd_11_851212760;
                                rs_851212760 = nr_11_851212760;
                                let j_2238844032 = 173375214u32;
                                cv_851212760 = b_11_851212760;
                                let (rd_12_851212760, nr_12_851212760) = d_851212760(
                                    34367338u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_12_851212760 = rd_12_851212760;
                                rs_851212760 = nr_12_851212760;
                                let j_1968732074 = 1740382831u32;
                                cv_851212760 = b_12_851212760;
                                let (rd_13_851212760, nr_13_851212760) = d_851212760(
                                    2583647417u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_13_851212760 = rd_13_851212760;
                                rs_851212760 = nr_13_851212760;
                                let j_2361449785 = 1279671391u32;
                                cv_851212760 = b_13_851212760;
                                let (rd_14_851212760, nr_14_851212760) = d_851212760(
                                    1985568627u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_14_851212760 = rd_14_851212760;
                                rs_851212760 = nr_14_851212760;
                                let j_1808382128 = 285537720u32;
                                cv_851212760 = b_14_851212760;
                                let (rd_15_851212760, nr_15_851212760) = d_851212760(
                                    3811160840u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_15_851212760 = rd_15_851212760;
                                rs_851212760 = nr_15_851212760;
                                let j_3469447454 = 236478769u32;
                                cv_851212760 = b_15_851212760;
                                let (rd_16_851212760, nr_16_851212760) = d_851212760(
                                    3955759817u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_16_851212760 = rd_16_851212760;
                                rs_851212760 = nr_16_851212760;
                                let j_3204084256 = 874138954u32;
                                cv_851212760 = b_16_851212760;
                                let (rd_17_851212760, nr_17_851212760) = d_851212760(
                                    1202333613u32 ^ rs_851212760,
                                    &cv_851212760,
                                    rs_851212760,
                                    &mut aux_851212760,
                                );
                                let b_17_851212760 = rd_17_851212760;
                                rs_851212760 = nr_17_851212760;
                                let j_3575528752 = 3351881494u32;
                                let mut fv_851212760 = b_17_851212760;
                                let mid = fv_851212760.len() / 2;
                                let h1_2517264013 = fv_851212760[..mid].to_vec();
                                let h2_187592077 = fv_851212760[mid..].to_vec();
                                let frs = ::alloc::__export::must_use({
                                    ::alloc::fmt::format(
                                        format_args!(
                                            "{0}{1}",
                                            {
                                                let lck_2287942856 = (rs_851212760 ^ (rs_851212760 >> 13)
                                                    ^ (rs_851212760 >> 21)) as u8;
                                                let mut ubytes = h1_2517264013.clone();
                                                for b_3487421578 in ubytes.iter_mut() {
                                                    let ub_1679477530 = ((*b_3487421578 & !lck_2287942856)
                                                        | (!*b_3487421578 & lck_2287942856));
                                                    rs_851212760 = rs_851212760
                                                        .wrapping_add(ub_1679477530 as u32)
                                                        .rotate_left(3);
                                                    *b_3487421578 = ub_1679477530;
                                                }
                                                String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                            },
                                            {
                                                let mut trs_2227667002 = rs_851212760;
                                                struct S_2764337645(Vec<u8>, u32);
                                                impl ::std::fmt::Display for S_2764337645 {
                                                    fn fmt(
                                                        &self,
                                                        f: &mut ::std::fmt::Formatter<'_>,
                                                    ) -> ::std::fmt::Result {
                                                        let mut irs_1019658777 = self.1;
                                                        let lck_4221271067 = (irs_1019658777
                                                            ^ (irs_1019658777 >> 13) ^ (irs_1019658777 >> 21)) as u8;
                                                        let unlocked: Vec<u8> = self
                                                            .0
                                                            .iter()
                                                            .map(|&b_496113051| {
                                                                ((b_496113051 & !lck_4221271067)
                                                                    | (!b_496113051 & lck_4221271067))
                                                            })
                                                            .collect();
                                                        for chunk in unlocked.chunks(3usize) {
                                                            let s: String = chunk
                                                                .iter()
                                                                .map(|&b_496113051| {
                                                                    irs_1019658777 = irs_1019658777
                                                                        .wrapping_add(b_496113051 as u32)
                                                                        .rotate_left(3);
                                                                    b_496113051 as char
                                                                })
                                                                .collect();
                                                            f.write_str(&s)?;
                                                        }
                                                        Ok(())
                                                    }
                                                }
                                                let res_1888737190 = S_2764337645(
                                                        h2_187592077.clone(),
                                                        trs_2227667002,
                                                    )
                                                    .to_string();
                                                for &b_496113051 in &h2_187592077 {
                                                    let lck_4221271067 = (trs_2227667002
                                                        ^ (trs_2227667002 >> 13) ^ (trs_2227667002 >> 21)) as u8;
                                                    let ub_169648462 = ((b_496113051 ^ (lck_4221271067 ^ 130u8))
                                                        ^ 130u8);
                                                    trs_2227667002 = trs_2227667002
                                                        .wrapping_add(ub_169648462 as u32)
                                                        .rotate_left(3);
                                                }
                                                rs_851212760 = trs_2227667002;
                                                res_1888737190
                                            },
                                        ),
                                    )
                                });
                                frs
                            }
                        }
                    }
                    let mut inst = O_851212760 {
                        e: b"8/}x)j/h\"l*cx-'*$`&u~`",
                        o: b"\xa6\x0e\xe3\x1c\xbf\x1f\xf9\x18\xa7\x12\x89\x15\xa5\x10\xe2\x15\xa3\x13\xe7\x1b\xe5",
                        key: 238u8,
                    };
                    inst.r_851212760()
                },
            ),
        );
    };
    loop {
        {
            ::std::io::_print(
                format_args!(
                    "{0}\n",
                    {
                        struct O_4247222002<'a> {
                            d: &'a [u8],
                            key: u8,
                        }
                        impl<'a> O_4247222002<'a> {
                            fn r_4247222002(&mut self) -> String {
                                let mut d_4247222002 = |
                                    id: u32,
                                    data: &[u8],
                                    rs_in: u32,
                                    aux: &mut Vec<u8>,
                                | -> (Vec<u8>, u32) {
                                    match (((id ^ rs_in).wrapping_mul(1014087367u32)
                                        ^ 4177082700u32)
                                        .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                    {
                                        3507059892u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2778851088u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            let mut out = Vec::with_capacity(data.len());
                                            for &b in &data {
                                                let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v != 255 {
                                                    out.push(v);
                                                }
                                            }
                                            data = out;
                                            rs = rs.wrapping_add(1395606074u32).rotate_left(5)
                                                ^ 1234509370u32;
                                            rs = rs.wrapping_sub(1955226629u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2888161401u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(65u8);
                                                rs = rs.wrapping_add(4043619041u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(216u8);
                                                rs = rs.wrapping_add(1491964968u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            let mut leading_zeros = 0;
                                            for &v in &data {
                                                if v == 0 {
                                                    leading_zeros += 1;
                                                } else {
                                                    break;
                                                }
                                            }
                                            let mut res = ::alloc::vec::from_elem(0u32, 1);
                                            for &v in &data[leading_zeros..] {
                                                let mut carry = v as u64;
                                                for digit in res.iter_mut() {
                                                    let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                    *digit = prod as u32;
                                                    carry = prod >> 32;
                                                }
                                                while carry > 0 {
                                                    res.push(carry as u32);
                                                    carry >>= 32;
                                                }
                                            }
                                            let mut out = ::alloc::vec::from_elem(0u8, leading_zeros);
                                            let rl = res.len();
                                            let mut bytes_out = Vec::new();
                                            for (idx, &val) in res.iter().enumerate().rev() {
                                                let bytes = val.to_be_bytes();
                                                if idx == rl - 1 {
                                                    let mut skip = 0;
                                                    while skip < 4 && bytes[skip] == 0 {
                                                        skip += 1;
                                                    }
                                                    bytes_out.extend_from_slice(&bytes[skip..]);
                                                } else {
                                                    bytes_out.extend_from_slice(&bytes);
                                                }
                                            }
                                            out.extend(bytes_out);
                                            while out.len() > 64u64 as usize {
                                                out.remove(0);
                                            }
                                            while out.len() < 64u64 as usize {
                                                out.insert(0, 0);
                                            }
                                            data = out;
                                            rs = rs.wrapping_add(2705670930u32).rotate_left(5)
                                                ^ 1235986991u32;
                                            rs = rs.wrapping_sub(2550422807u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        705610560u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_4023560990 = 1588445890u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_4023560990)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 108u8);
                                            }
                                            rs = rs.wrapping_add(564405927u32).rotate_left(5)
                                                ^ 2310571770u32;
                                            rs = rs.rotate_left(26u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        87806742u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2778851088u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2919026778u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            rs = rs.wrapping_add(276743291u32).rotate_left(5)
                                                ^ 4078386750u32;
                                            rs = rs.wrapping_sub(481477883u32).rotate_right(7);
                                            rs = rs.rotate_left(16u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        830506608u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                let n = (rs >> 8) as u8;
                                                *b = b.wrapping_add(n).wrapping_sub(n);
                                                *b ^= 62u8;
                                            }
                                            rs = rs.wrapping_add(1858766044u32).rotate_left(5)
                                                ^ 889589730u32;
                                            rs ^= 2476305533u32;
                                            rs = rs.rotate_left(4u32);
                                            rs ^= 1247721348u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2613842249u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_2917033198 = 2612740245u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_2917033198)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 236u8);
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(4u8);
                                                rs = rs.wrapping_add(2407427983u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(1138490546u32).rotate_left(5)
                                                ^ 2970376744u32;
                                            rs = rs.wrapping_add(2879552277u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        591587106u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2919026778u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1342652504u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(165u8);
                                                rs = rs.wrapping_add(345216864u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(1551386976u32).rotate_left(5)
                                                ^ 2821372201u32;
                                            rs = rs.wrapping_add(3371610407u32);
                                            rs = rs.rotate_left(4u32);
                                            rs = rs.wrapping_sub(2944483835u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1557876452u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut out = Vec::with_capacity(data.len());
                                            for &b in &data {
                                                let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v != 255 {
                                                    out.push(v);
                                                }
                                            }
                                            data = out;
                                            let mut out = Vec::new();
                                            let mut bc = 0u64;
                                            for chunk in data.chunks(8) {
                                                let mut val = 0u64;
                                                for (i, &idx) in chunk.iter().enumerate() {
                                                    val |= (idx as u64) << (35 - i * 5);
                                                }
                                                for i in (0..5).rev() {
                                                    if bc < 320u64 {
                                                        out.push(((val >> (i * 8)) & 0xff) as u8);
                                                        bc += 8;
                                                    }
                                                }
                                            }
                                            data = out;
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(152u8);
                                                rs = rs.wrapping_add(1567374619u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(2083986464u32).rotate_left(5)
                                                ^ 2273993046u32;
                                            rs = rs.wrapping_sub(2050621915u32).rotate_right(7);
                                            rs ^= 2274532196u32;
                                            rs ^= 2119806054u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1745736875u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_3472815688 = 2993005911u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_3472815688)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 130u8);
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(0u8);
                                                rs = rs.wrapping_add(265528187u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(3036757048u32).rotate_left(5)
                                                ^ 3999407805u32;
                                            rs = rs.rotate_left(30u32);
                                            rs = rs.wrapping_sub(4164990125u32).rotate_right(7);
                                            rs = rs.wrapping_sub(4125637804u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        533917915u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1342652504u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(2029629058u32).rotate_left(5)
                                                ^ 2116381051u32;
                                            rs ^= 1544270545u32;
                                            rs ^= 534556111u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2236008757u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4258209497u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            if data.len() > 0 {
                                                let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                let mut idx = 0;
                                                for i in 0..2usize {
                                                    let mut j = i;
                                                    while j < data.len() {
                                                        out[j] = data[idx];
                                                        idx += 1;
                                                        j += 2usize;
                                                    }
                                                }
                                                data = out;
                                            }
                                            rs = rs.wrapping_add(2198010775u32).rotate_left(5)
                                                ^ 1252268875u32;
                                            rs = rs.wrapping_add(1989373530u32);
                                            rs = rs.wrapping_add(2791473935u32);
                                            rs ^= 3981983757u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2213524306u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_423940091 = 3198233427u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_423940091)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 54u8);
                                            }
                                            rs = rs.wrapping_add(1444494480u32).rotate_left(5)
                                                ^ 3770618702u32;
                                            rs ^= 3043959335u32;
                                            rs = rs.wrapping_add(3771078169u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3904849803u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4258209497u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(2315565434u32).rotate_left(5)
                                                ^ 2457463212u32;
                                            rs = rs.rotate_left(8u32);
                                            rs = rs.wrapping_sub(3849633848u32).rotate_right(7);
                                            rs = rs.rotate_left(10u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3722708322u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3256766794u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data = data
                                                .iter()
                                                .filter_map(|&b| {
                                                    let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffD\xffTSRH\xffKLFA\xff?>E\0\x01\x02\x03\x04\x05\x06\x07\x08\t@\xffIBJGQ$%&'()*+,-./0123456789:;<=M\xffNC\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#O\xffP\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                        as usize];
                                                    if v == 255 { None } else { Some(v) }
                                                })
                                                .collect();
                                            rs = rs.wrapping_add(2006822626u32).rotate_left(5)
                                                ^ 266145645u32;
                                            rs = rs.wrapping_sub(119165942u32).rotate_right(7);
                                            rs = rs.rotate_left(1u32);
                                            rs = rs.wrapping_add(289324029u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        386219280u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut out = Vec::new();
                                            let mut len_v = 0u64;
                                            for chunk in data.chunks(5usize) {
                                                if chunk.len() < 5usize {
                                                    continue;
                                                }
                                                let mut v = 0u128;
                                                for &c in chunk {
                                                    v = v * 85u128 + (c as u128);
                                                }
                                                for i in (0..4usize).rev() {
                                                    if len_v < 30u64 {
                                                        out.push(((v >> (i * 8)) & 0xff) as u8);
                                                        len_v += 1;
                                                    }
                                                }
                                            }
                                            data = out;
                                            let mut offset_2076060023 = 3154584068u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_2076060023)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 128u8);
                                            }
                                            rs = rs.wrapping_add(2249310046u32).rotate_left(5)
                                                ^ 2617068288u32;
                                            rs = rs.wrapping_sub(1309424882u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2604843911u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3256766794u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(2652939487u32).rotate_left(5)
                                                ^ 3623390652u32;
                                            rs = rs.wrapping_sub(1285558940u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        _ => (data.to_vec(), rs_in),
                                    }
                                };
                                let mut aux_4247222002 = Vec::new();
                                let mut rs_j_4247222002 = 0u32;
                                let mut db_4247222002 = {
                                    let mut rd = self.d.to_vec();
                                    let mut k_1036356845 = self.key;
                                    let mut db_4247222002 = Vec::with_capacity(rd.len());
                                    for byte in rd.iter() {
                                        let b_1587218753 = *byte;
                                        db_4247222002.push(b_1587218753 ^ k_1036356845);
                                        k_1036356845 = k_1036356845.wrapping_add(b_1587218753);
                                    }
                                    rs_j_4247222002 = rs_j_4247222002.rotate_left(22u32);
                                    rs_j_4247222002 ^= 3569371892u32;
                                    let lock_out_junk = (rs_j_4247222002
                                        ^ (rs_j_4247222002 >> 13) ^ (rs_j_4247222002 >> 21)) as u8;
                                    for b in db_4247222002.iter_mut() {
                                        *b ^= lock_out_junk;
                                    }
                                    db_4247222002
                                };
                                let mut ds_4247222002 = db_4247222002;
                                let mut s_4247222002 = 0usize;
                                let mut m_4247222002 = ds_4247222002.clone();
                                let mut rs_4247222002 = 0u32;
                                loop {
                                    match s_4247222002 {
                                        0usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                1395606074u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_3659794607 = 430042951u32;
                                        }
                                        1usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2705670930u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_1949523179 = 1277959188u32;
                                        }
                                        2usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                564405927u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_3288228716 = 3265692549u32;
                                        }
                                        3usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                276743291u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_1331724638 = 4232472185u32;
                                        }
                                        4usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                1858766044u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_601590575 = 2764178065u32;
                                        }
                                        5usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                1138490546u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_1774371081 = 3142270531u32;
                                        }
                                        6usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                1551386976u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_3446746982 = 4270938919u32;
                                        }
                                        7usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2083986464u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_1573279542 = 882722261u32;
                                        }
                                        8usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                3036757048u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_2264184516 = 2898854856u32;
                                        }
                                        9usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2029629058u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_494496836 = 3634574902u32;
                                        }
                                        10usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2198010775u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_2160896944 = 1432650373u32;
                                        }
                                        11usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                1444494480u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_3925855725 = 4229771406u32;
                                        }
                                        12usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2315565434u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_3682276582 = 1896175721u32;
                                        }
                                        13usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2006822626u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_971728547 = 1116312009u32;
                                        }
                                        14usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2249310046u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            m_4247222002 = res_data;
                                            rs_4247222002 = next_rs;
                                            s_4247222002 += 1;
                                            let j_2448515596 = 3652349u32;
                                        }
                                        15usize => {
                                            let (res_data, next_rs) = d_4247222002(
                                                2652939487u32 ^ rs_4247222002,
                                                &m_4247222002,
                                                rs_4247222002,
                                                &mut aux_4247222002,
                                            );
                                            let fb_3875336123 = res_data;
                                            let nr_3547730244 = next_rs;
                                            let fv = {
                                                let lck_1470942912 = (nr_3547730244 ^ (nr_3547730244 >> 13)
                                                    ^ (nr_3547730244 >> 21)) as u8;
                                                let mut ubytes = fb_3875336123.clone();
                                                for b_426217158 in ubytes.iter_mut() {
                                                    let ub_896907783 = ((*b_426217158 ^ (lck_1470942912 ^ 25u8))
                                                        ^ 25u8);
                                                    nr_3547730244 = nr_3547730244
                                                        .wrapping_add(ub_896907783 as u32)
                                                        .rotate_left(3);
                                                    *b_426217158 = ub_896907783;
                                                }
                                                String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                            };
                                            break fv;
                                        }
                                        _ => break String::new(),
                                    }
                                }
                            }
                        }
                        let mut inst = O_4247222002 {
                            d: b"\x16\x89\0\x070/\x1d\xacDu\x93\xbf)W\xc4\xfd\xa6\04E\x87Z\x98w\x96!=\xf6m\xe7\xbf\xb8+v\xcf\xafW\x99X\xad}\x95\r\x7f\xc1\x84{\x86[\xadr\xad\x0co\xed\xbc\x9d;\x7f\xf1\xabF\xd3\xa3^\xf5\x83\x185z\xfd\xcb\x93P\xb0>\x03E\x9a",
                            key: 107u8,
                        };
                        inst.r_4247222002()
                    },
                ),
            );
        };
        let mut num1 = String::new();
        io::stdin().read_line(&mut num1).expect("Failed to read line");
        let num1: f64 = match num1.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                {
                    ::std::io::_print(
                        format_args!(
                            "{0}\n",
                            {
                                struct O_1618569588<'a> {
                                    e: &'a [u8],
                                    o: &'a [u8],
                                    key: u8,
                                }
                                impl<'a> O_1618569588<'a> {
                                    fn r_1618569588(&mut self) -> String {
                                        let mut d_1618569588 = |
                                            id: u32,
                                            data: &[u8],
                                            rs_in: u32,
                                            aux: &mut Vec<u8>,
                                        | -> (Vec<u8>, u32) {
                                            match (((id ^ rs_in).wrapping_mul(3024134069u32)
                                                ^ 754412086u32)
                                                .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                            {
                                                4248953298u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(225u8);
                                                        rs = rs.wrapping_add(3565780260u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 3964098391u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(408331459u32).rotate_left(5)
                                                        ^ 3615017912u32;
                                                    rs = rs.wrapping_add(2117882461u32);
                                                    rs = rs.wrapping_add(2202197044u32);
                                                    rs = rs.wrapping_sub(2775743328u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1963568235u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    data = data
                                                        .iter()
                                                        .filter_map(|&b| {
                                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                as usize];
                                                            if v == 255 { None } else { Some(v) }
                                                        })
                                                        .collect();
                                                    aux.extend_from_slice(&data);
                                                    data.clear();
                                                    rs = rs.wrapping_add(2347997340u32).rotate_left(5)
                                                        ^ 133301436u32;
                                                    rs = rs.wrapping_add(4261853709u32);
                                                    rs ^= 2924032829u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                655559337u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let _ = 50u32;
                                                    rs = rs.wrapping_add(1984926443u32).rotate_left(5)
                                                        ^ 1768357500u32;
                                                    rs = rs.wrapping_sub(628672152u32).rotate_right(7);
                                                    rs = rs.rotate_left(11u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3605188908u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(220u8);
                                                        rs = rs.wrapping_add(3239747819u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(104u8);
                                                        rs = rs.wrapping_add(57723946u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(2210256929u32).rotate_left(5)
                                                        ^ 1295105570u32;
                                                    rs = rs.wrapping_sub(2288160250u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(3115174682u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                23845261u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut out = Vec::new();
                                                    let mut acc = 0u128;
                                                    let mut count = 0u32;
                                                    let mut bc = 0u64;
                                                    for &v in aux.iter() {
                                                        acc = (acc << 5u32) | (v as u128);
                                                        count += 5u32;
                                                        while count >= 8 {
                                                            count -= 8;
                                                            if bc < 464u64 {
                                                                out.push((acc >> count) as u8);
                                                                bc += 8;
                                                            }
                                                            acc &= (1 << count) - 1;
                                                        }
                                                    }
                                                    data = out;
                                                    aux.clear();
                                                    let mut offset_3442310991 = 2302312284u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_3442310991)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 57u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 3964098391u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(1134464618u32).rotate_left(5)
                                                        ^ 1420592069u32;
                                                    rs ^= 323729742u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2056477795u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(224u8);
                                                        rs = rs.wrapping_add(4290906388u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2302086620u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    data = data
                                                        .iter()
                                                        .filter_map(|&b| {
                                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                as usize];
                                                            if v == 255 { None } else { Some(v) }
                                                        })
                                                        .collect();
                                                    rs = rs.wrapping_add(3379177819u32).rotate_left(5)
                                                        ^ 1738645821u32;
                                                    rs ^= 1030220357u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1151794873u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(238u8);
                                                        rs = rs.wrapping_add(1422190685u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(815519113u32).rotate_left(5)
                                                        ^ 3792518509u32;
                                                    rs = rs.wrapping_sub(831434165u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(226622138u32).rotate_right(7);
                                                    rs = rs.rotate_left(25u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2907594013u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    aux.clear();
                                                    aux.extend_from_slice(&0u32.to_ne_bytes());
                                                    rs = rs.wrapping_add(3301419545u32).rotate_left(5)
                                                        ^ 3139442558u32;
                                                    rs = rs.wrapping_sub(1905851587u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(4096590116u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(3741108756u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2673254049u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let lz = data.iter().take_while(|&&x| x == 0).count();
                                                    let mut res: Vec<u32> = aux
                                                        .chunks_exact(4)
                                                        .map(|c| {
                                                            let mut b = [0u8; 4];
                                                            b.copy_from_slice(c);
                                                            u32::from_ne_bytes(b)
                                                        })
                                                        .collect();
                                                    data.iter()
                                                        .skip(lz)
                                                        .for_each(|&v| {
                                                            let mut carry = v as u64;
                                                            res.iter_mut()
                                                                .for_each(|digit| {
                                                                    let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                                    *digit = prod as u32;
                                                                    carry = prod >> 32;
                                                                });
                                                            while carry > 0 {
                                                                res.push(carry as u32);
                                                                carry >>= 32;
                                                            }
                                                        });
                                                    aux.clear();
                                                    res.iter()
                                                        .for_each(|val| aux.extend_from_slice(&val.to_ne_bytes()));
                                                    let mut next_aux = (lz as u64).to_ne_bytes().to_vec();
                                                    next_aux.extend_from_slice(&aux);
                                                    aux.clear();
                                                    aux.extend(next_aux);
                                                    rs = rs.wrapping_add(2708504832u32).rotate_left(5)
                                                        ^ 1103877766u32;
                                                    rs = rs.wrapping_sub(393496012u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1356139753u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    if aux.len() >= 8 {
                                                        let mut lz_bytes = [0u8; 8];
                                                        lz_bytes.copy_from_slice(&aux[0..8]);
                                                        let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                        let mut res = Vec::new();
                                                        for chunk in aux[8..].chunks_exact(4) {
                                                            let mut bytes = [0u8; 4];
                                                            bytes.copy_from_slice(chunk);
                                                            res.push(u32::from_ne_bytes(bytes));
                                                        }
                                                        let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                        if !(res.len() == 1 && res[0] == 0)
                                                            || (aux.len() - 8) / 4 == lz
                                                        {
                                                            let mut bytes_out = Vec::new();
                                                            let rl = res.len();
                                                            for (idx, &val) in res.iter().enumerate().rev() {
                                                                let bytes = val.to_be_bytes();
                                                                if idx == rl - 1 {
                                                                    let mut skip = 0;
                                                                    while skip < 4 && bytes[skip] == 0 {
                                                                        skip += 1;
                                                                    }
                                                                    bytes_out.extend_from_slice(&bytes[skip..]);
                                                                } else {
                                                                    bytes_out.extend_from_slice(&bytes);
                                                                }
                                                            }
                                                            out.extend(bytes_out);
                                                        }
                                                        data = out;
                                                    } else {
                                                        data = Vec::new();
                                                    }
                                                    aux.clear();
                                                    let mut offset_3907360664 = 1604981139u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_3907360664)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 231u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2302086620u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(781325614u32).rotate_left(5)
                                                        ^ 3597519945u32;
                                                    rs = rs.wrapping_sub(1295721116u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(1772829597u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(4213745891u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1092889421u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 132509145u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(2788881782u32).rotate_left(5)
                                                        ^ 2936723282u32;
                                                    rs ^= 1249978345u32;
                                                    rs = rs.wrapping_sub(2233829394u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1182922478u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.rotate_left(2u32);
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(13u8);
                                                        rs = rs.wrapping_add(3281227432u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(1714495712u32).rotate_left(5)
                                                        ^ 1777503180u32;
                                                    rs = rs.wrapping_sub(2264015293u32).rotate_right(7);
                                                    rs ^= 2288931332u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3040724477u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.rotate_right(2u32);
                                                    }
                                                    for b in data.iter_mut() {
                                                        let n = (rs >> 8) as u8;
                                                        *b = b.wrapping_add(n).wrapping_sub(n);
                                                        *b ^= 196u8;
                                                    }
                                                    rs = rs.wrapping_add(1502161681u32).rotate_left(5)
                                                        ^ 2486678761u32;
                                                    rs ^= 933603761u32;
                                                    rs = rs.rotate_left(30u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1664090213u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_1307923561 = 2937637788u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_1307923561)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 26u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 132509145u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1643254844u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(2839743303u32).rotate_left(5)
                                                        ^ 1518328912u32;
                                                    rs = rs.rotate_left(28u32);
                                                    rs = rs.wrapping_sub(2934694799u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1351893512u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b ^= 240u8;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b ^= 195u8;
                                                    }
                                                    let mut offset_3549256848 = 2551775800u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_3549256848)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 38u8);
                                                    }
                                                    rs = rs.wrapping_add(574550661u32).rotate_left(5)
                                                        ^ 3414798147u32;
                                                    rs ^= 632987769u32;
                                                    rs = rs.rotate_left(5u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3352153618u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(150u8);
                                                        rs = rs.wrapping_add(2910682698u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(3884777890u32).rotate_left(5)
                                                        ^ 4118160134u32;
                                                    rs = rs.wrapping_add(270464983u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2268792221u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1643254844u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(2542054503u32).rotate_left(5)
                                                        ^ 2213683977u32;
                                                    rs = rs.wrapping_add(3446492075u32);
                                                    rs = rs.rotate_left(22u32);
                                                    rs ^= 2870549738u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                _ => (data.to_vec(), rs_in),
                                            }
                                        };
                                        let mut aux_1618569588 = Vec::new();
                                        let mut rs_j_1618569588 = 0u32;
                                        let mut db_1618569588 = {
                                            let mut rd = Vec::new();
                                            let mut ei = self.e.iter();
                                            let mut oi = self.o.iter();
                                            loop {
                                                match (ei.next(), oi.next()) {
                                                    (Some(ev), Some(ov)) => {
                                                        rd.push(*ev);
                                                        rd.push(*ov);
                                                    }
                                                    (Some(ev), None) => {
                                                        rd.push(*ev);
                                                        break;
                                                    }
                                                    _ => break,
                                                }
                                            }
                                            let mut k_3297653617 = self.key;
                                            let mut db_1618569588 = Vec::new();
                                            let mut i = 0;
                                            while i < rd.len() {
                                                let b_4087917600 = rd[i];
                                                db_1618569588.push(b_4087917600 ^ k_3297653617);
                                                k_3297653617 = k_3297653617.wrapping_add(b_4087917600);
                                                i += 1;
                                            }
                                            rs_j_1618569588 = rs_j_1618569588
                                                .wrapping_sub(2025290401u32)
                                                .rotate_right(7);
                                            rs_j_1618569588 = rs_j_1618569588.rotate_left(3u32);
                                            let lock_out_junk = (rs_j_1618569588
                                                ^ (rs_j_1618569588 >> 13) ^ (rs_j_1618569588 >> 21)) as u8;
                                            for b in db_1618569588.iter_mut() {
                                                *b ^= lock_out_junk;
                                            }
                                            db_1618569588
                                        };
                                        let mut ds_1618569588 = db_1618569588;
                                        {
                                            let mut nd_0_1618569588 = ds_1618569588.clone();
                                            let mut rs_1618569588 = 0u32;
                                            {
                                                let (res_data, next_rs_val) = d_1618569588(
                                                    408331459u32 ^ rs_1618569588,
                                                    &nd_0_1618569588,
                                                    rs_1618569588,
                                                    &mut aux_1618569588,
                                                );
                                                let mut rs_1618569588 = next_rs_val;
                                                let nb_0_1618569588 = res_data;
                                                let j_604997756 = 366496170u32;
                                                let mut nd_1_1618569588 = nb_0_1618569588;
                                                {
                                                    let (res_data, next_rs_val) = d_1618569588(
                                                        2347997340u32 ^ rs_1618569588,
                                                        &nd_1_1618569588,
                                                        rs_1618569588,
                                                        &mut aux_1618569588,
                                                    );
                                                    let mut rs_1618569588 = next_rs_val;
                                                    let nb_1_1618569588 = res_data;
                                                    let j_4211165864 = 2258355168u32;
                                                    let mut nd_2_1618569588 = nb_1_1618569588;
                                                    {
                                                        let (res_data, next_rs_val) = d_1618569588(
                                                            1984926443u32 ^ rs_1618569588,
                                                            &nd_2_1618569588,
                                                            rs_1618569588,
                                                            &mut aux_1618569588,
                                                        );
                                                        let mut rs_1618569588 = next_rs_val;
                                                        let nb_2_1618569588 = res_data;
                                                        let j_3653278279 = 2356855350u32;
                                                        let mut nd_3_1618569588 = nb_2_1618569588;
                                                        {
                                                            let (res_data, next_rs_val) = d_1618569588(
                                                                2210256929u32 ^ rs_1618569588,
                                                                &nd_3_1618569588,
                                                                rs_1618569588,
                                                                &mut aux_1618569588,
                                                            );
                                                            let mut rs_1618569588 = next_rs_val;
                                                            let nb_3_1618569588 = res_data;
                                                            let j_2477189662 = 844418172u32;
                                                            let mut nd_4_1618569588 = nb_3_1618569588;
                                                            {
                                                                let (res_data, next_rs_val) = d_1618569588(
                                                                    1134464618u32 ^ rs_1618569588,
                                                                    &nd_4_1618569588,
                                                                    rs_1618569588,
                                                                    &mut aux_1618569588,
                                                                );
                                                                let mut rs_1618569588 = next_rs_val;
                                                                let nb_4_1618569588 = res_data;
                                                                let j_2481577460 = 268920656u32;
                                                                let mut nd_5_1618569588 = nb_4_1618569588;
                                                                {
                                                                    let (res_data, next_rs_val) = d_1618569588(
                                                                        3379177819u32 ^ rs_1618569588,
                                                                        &nd_5_1618569588,
                                                                        rs_1618569588,
                                                                        &mut aux_1618569588,
                                                                    );
                                                                    let mut rs_1618569588 = next_rs_val;
                                                                    let nb_5_1618569588 = res_data;
                                                                    let j_3026635137 = 3424033821u32;
                                                                    let mut nd_6_1618569588 = nb_5_1618569588;
                                                                    {
                                                                        let (res_data, next_rs_val) = d_1618569588(
                                                                            815519113u32 ^ rs_1618569588,
                                                                            &nd_6_1618569588,
                                                                            rs_1618569588,
                                                                            &mut aux_1618569588,
                                                                        );
                                                                        let mut rs_1618569588 = next_rs_val;
                                                                        let nb_6_1618569588 = res_data;
                                                                        let j_2675401492 = 15159687u32;
                                                                        let mut nd_7_1618569588 = nb_6_1618569588;
                                                                        {
                                                                            let (res_data, next_rs_val) = d_1618569588(
                                                                                3301419545u32 ^ rs_1618569588,
                                                                                &nd_7_1618569588,
                                                                                rs_1618569588,
                                                                                &mut aux_1618569588,
                                                                            );
                                                                            let mut rs_1618569588 = next_rs_val;
                                                                            let nb_7_1618569588 = res_data;
                                                                            let j_519509665 = 738753086u32;
                                                                            let mut nd_8_1618569588 = nb_7_1618569588;
                                                                            {
                                                                                let (res_data, next_rs_val) = d_1618569588(
                                                                                    2708504832u32 ^ rs_1618569588,
                                                                                    &nd_8_1618569588,
                                                                                    rs_1618569588,
                                                                                    &mut aux_1618569588,
                                                                                );
                                                                                let mut rs_1618569588 = next_rs_val;
                                                                                let nb_8_1618569588 = res_data;
                                                                                let j_3985512428 = 580075241u32;
                                                                                let mut nd_9_1618569588 = nb_8_1618569588;
                                                                                {
                                                                                    let (res_data, next_rs_val) = d_1618569588(
                                                                                        781325614u32 ^ rs_1618569588,
                                                                                        &nd_9_1618569588,
                                                                                        rs_1618569588,
                                                                                        &mut aux_1618569588,
                                                                                    );
                                                                                    let mut rs_1618569588 = next_rs_val;
                                                                                    let nb_9_1618569588 = res_data;
                                                                                    let j_143818903 = 1165914697u32;
                                                                                    let mut nd_10_1618569588 = nb_9_1618569588;
                                                                                    {
                                                                                        let (res_data, next_rs_val) = d_1618569588(
                                                                                            2788881782u32 ^ rs_1618569588,
                                                                                            &nd_10_1618569588,
                                                                                            rs_1618569588,
                                                                                            &mut aux_1618569588,
                                                                                        );
                                                                                        let mut rs_1618569588 = next_rs_val;
                                                                                        let nb_10_1618569588 = res_data;
                                                                                        let j_972617757 = 4107542000u32;
                                                                                        let mut nd_11_1618569588 = nb_10_1618569588;
                                                                                        {
                                                                                            let (res_data, next_rs_val) = d_1618569588(
                                                                                                1714495712u32 ^ rs_1618569588,
                                                                                                &nd_11_1618569588,
                                                                                                rs_1618569588,
                                                                                                &mut aux_1618569588,
                                                                                            );
                                                                                            let mut rs_1618569588 = next_rs_val;
                                                                                            let nb_11_1618569588 = res_data;
                                                                                            let j_3128986227 = 397666200u32;
                                                                                            let mut nd_12_1618569588 = nb_11_1618569588;
                                                                                            {
                                                                                                let (res_data, next_rs_val) = d_1618569588(
                                                                                                    1502161681u32 ^ rs_1618569588,
                                                                                                    &nd_12_1618569588,
                                                                                                    rs_1618569588,
                                                                                                    &mut aux_1618569588,
                                                                                                );
                                                                                                let mut rs_1618569588 = next_rs_val;
                                                                                                let nb_12_1618569588 = res_data;
                                                                                                let j_3820787242 = 3452812860u32;
                                                                                                let mut nd_13_1618569588 = nb_12_1618569588;
                                                                                                {
                                                                                                    let (res_data, next_rs_val) = d_1618569588(
                                                                                                        2839743303u32 ^ rs_1618569588,
                                                                                                        &nd_13_1618569588,
                                                                                                        rs_1618569588,
                                                                                                        &mut aux_1618569588,
                                                                                                    );
                                                                                                    let mut rs_1618569588 = next_rs_val;
                                                                                                    let nb_13_1618569588 = res_data;
                                                                                                    let j_2118512868 = 2245012620u32;
                                                                                                    let mut nd_14_1618569588 = nb_13_1618569588;
                                                                                                    {
                                                                                                        let (res_data, next_rs_val) = d_1618569588(
                                                                                                            574550661u32 ^ rs_1618569588,
                                                                                                            &nd_14_1618569588,
                                                                                                            rs_1618569588,
                                                                                                            &mut aux_1618569588,
                                                                                                        );
                                                                                                        let mut rs_1618569588 = next_rs_val;
                                                                                                        let nb_14_1618569588 = res_data;
                                                                                                        let j_2579580043 = 1767797617u32;
                                                                                                        let mut nd_15_1618569588 = nb_14_1618569588;
                                                                                                        {
                                                                                                            let (res_data, next_rs_val) = d_1618569588(
                                                                                                                3884777890u32 ^ rs_1618569588,
                                                                                                                &nd_15_1618569588,
                                                                                                                rs_1618569588,
                                                                                                                &mut aux_1618569588,
                                                                                                            );
                                                                                                            let mut rs_1618569588 = next_rs_val;
                                                                                                            let nb_15_1618569588 = res_data;
                                                                                                            let j_4162098310 = 2500559973u32;
                                                                                                            let mut nd_16_1618569588 = nb_15_1618569588;
                                                                                                            {
                                                                                                                let (res_data, next_rs) = d_1618569588(
                                                                                                                    2542054503u32 ^ rs_1618569588,
                                                                                                                    &nd_16_1618569588,
                                                                                                                    rs_1618569588,
                                                                                                                    &mut aux_1618569588,
                                                                                                                );
                                                                                                                let lb_1618569588 = res_data;
                                                                                                                let nr_last_1618569588 = next_rs;
                                                                                                                {
                                                                                                                    let lck_3930769488 = (nr_last_1618569588
                                                                                                                        ^ (nr_last_1618569588 >> 13) ^ (nr_last_1618569588 >> 21))
                                                                                                                        as u8;
                                                                                                                    let mut res_2303070576 = String::with_capacity(
                                                                                                                        lb_1618569588.len(),
                                                                                                                    );
                                                                                                                    for &b_1407365845 in &lb_1618569588 {
                                                                                                                        let ub_70577553 = ((b_1407365845 ^ (lck_3930769488 ^ 3u8))
                                                                                                                            ^ 3u8);
                                                                                                                        nr_last_1618569588 = nr_last_1618569588
                                                                                                                            .wrapping_add(ub_70577553 as u32)
                                                                                                                            .rotate_left(3);
                                                                                                                        res_2303070576.push(ub_70577553 as char);
                                                                                                                    }
                                                                                                                    res_2303070576
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                let mut inst = O_1618569588 {
                                    e: b"A$9\xcc\xc7\xcc7]\xe2)`\xdd\xe1!Y\xfb\x04\x1e\xfb#\x08\x1e\xf9\xd9\xdd\xc2\xc2\xee\xe2\x1c\xa0\x02\x0e\xa54qA\xf3\xd8\x9a\xeeT\xe1V\xce\xf6\xdd",
                                    o: b"\x1a\xcb\xfc3&\x0f\xc2\xed\xdb\xda\xc5=\xde\x98/\xa2\x12-\xc5\xc6\x07.\xf9&);[\xfa\xd9j\x82DP\x17\x91\x84Y\xf0'q\xc2\xfe\x87'Z\xef",
                                    key: 29u8,
                                };
                                inst.r_1618569588()
                            },
                        ),
                    );
                };
                continue;
            }
        };
        {
            ::std::io::_print(
                format_args!(
                    "{0}\n",
                    {
                        struct O_2613639558<'a> {
                            e: &'a [u8],
                            o: &'a [u8],
                            key: u8,
                        }
                        impl<'a> O_2613639558<'a> {
                            fn r_2613639558(&mut self) -> String {
                                let mut d_2613639558 = |
                                    id: u32,
                                    data: &[u8],
                                    rs_in: u32,
                                    aux: &mut Vec<u8>,
                                | -> (Vec<u8>, u32) {
                                    match (((id ^ rs_in).wrapping_mul(593593317u32)
                                        ^ 2325736834u32)
                                        .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                    {
                                        1380286993u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1517451761u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data = data
                                                .iter()
                                                .filter_map(|&b| {
                                                    let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffD\xffTSRH\xffKLFA\xff?>E\0\x01\x02\x03\x04\x05\x06\x07\x08\t@\xffIBJGQ$%&'()*+,-./0123456789:;<=M\xffNC\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#O\xffP\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                        as usize];
                                                    if v == 255 {
                                                        None
                                                    } else {
                                                        v = (v ^ 196u8) ^ 196u8;
                                                        Some(v)
                                                    }
                                                })
                                                .collect();
                                            let mut out = Vec::new();
                                            let mut len_v = 0u64;
                                            for chunk in data.chunks(5usize) {
                                                if chunk.len() < 5usize {
                                                    continue;
                                                }
                                                let mut v = 0u128;
                                                for &c in chunk {
                                                    v = v * 85u128 + (c as u128);
                                                }
                                                for i in (0..4usize).rev() {
                                                    if len_v < 95u64 {
                                                        out.push(((v >> (i * 8)) & 0xff) as u8);
                                                        len_v += 1;
                                                    }
                                                }
                                            }
                                            data = out;
                                            rs = rs.wrapping_add(1048102338u32).rotate_left(5)
                                                ^ 670793374u32;
                                            rs = rs.rotate_left(5u32);
                                            rs = rs.wrapping_add(79737225u32);
                                            rs = rs.wrapping_add(1180296723u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        940979107u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_783579115 = 3503005645u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_783579115)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 37u8);
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(182u8);
                                                rs = rs.wrapping_add(1140107993u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(2360320172u32).rotate_left(5)
                                                ^ 931747840u32;
                                            rs = rs.rotate_left(3u32);
                                            rs = rs.wrapping_add(2363783012u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        4094839885u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(255u8);
                                                rs = rs.wrapping_add(3632357989u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1517451761u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3144331401u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            rs = rs.wrapping_add(3289209064u32).rotate_left(5)
                                                ^ 1031233044u32;
                                            rs ^= 1273748352u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1877844402u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            rs = rs.wrapping_add(403464801u32).rotate_left(5)
                                                ^ 678448656u32;
                                            rs = rs.rotate_left(1u32);
                                            rs ^= 616963682u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3396462667u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(147u8);
                                                rs = rs.wrapping_add(1066071043u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(2596382668u32).rotate_left(5)
                                                ^ 4152356969u32;
                                            rs = rs.rotate_left(4u32);
                                            rs = rs.rotate_left(22u32);
                                            rs ^= 1606404454u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        4172801196u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(112u8);
                                                rs = rs.wrapping_add(95723380u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(4036285108u32).rotate_left(5)
                                                ^ 3341346689u32;
                                            rs = rs.wrapping_sub(2725374467u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2141584276u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut out = Vec::with_capacity(data.len());
                                            for &b in &data {
                                                let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v != 255 {
                                                    out.push(v);
                                                }
                                            }
                                            data = out;
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(181u8);
                                                rs = rs.wrapping_add(1391995433u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(802972432u32).rotate_left(5)
                                                ^ 926442441u32;
                                            rs = rs.rotate_left(23u32);
                                            rs = rs.wrapping_sub(2512658049u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2344390855u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            aux.clear();
                                            aux.extend_from_slice(&0u32.to_ne_bytes());
                                            rs = rs.wrapping_add(885203312u32).rotate_left(5)
                                                ^ 1591755598u32;
                                            rs = rs.rotate_left(23u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        470208117u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let lz = data.iter().take_while(|&&x| x == 0).count();
                                            let mut res: Vec<u32> = aux
                                                .chunks_exact(4)
                                                .map(|c| {
                                                    let mut b = [0u8; 4];
                                                    b.copy_from_slice(c);
                                                    u32::from_ne_bytes(b)
                                                })
                                                .collect();
                                            data.iter()
                                                .skip(lz)
                                                .for_each(|&v| {
                                                    let mut carry = v as u64;
                                                    res.iter_mut()
                                                        .for_each(|digit| {
                                                            let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                            *digit = prod as u32;
                                                            carry = prod >> 32;
                                                        });
                                                    while carry > 0 {
                                                        res.push(carry as u32);
                                                        carry >>= 32;
                                                    }
                                                });
                                            aux.clear();
                                            res.iter()
                                                .for_each(|val| aux.extend_from_slice(&val.to_ne_bytes()));
                                            let mut next_aux = (lz as u64).to_ne_bytes().to_vec();
                                            next_aux.extend_from_slice(&aux);
                                            aux.clear();
                                            aux.extend(next_aux);
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(31u8);
                                                rs = rs.wrapping_add(2424666551u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(44u8);
                                                rs = rs.wrapping_add(2568834967u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(1208713351u32).rotate_left(5)
                                                ^ 3014322241u32;
                                            rs = rs.wrapping_add(1728181368u32);
                                            rs = rs.rotate_left(29u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2941057853u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            if aux.len() >= 8 {
                                                let mut lz_bytes = [0u8; 8];
                                                lz_bytes.copy_from_slice(&aux[0..8]);
                                                let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                let mut res = Vec::new();
                                                for chunk in aux[8..].chunks_exact(4) {
                                                    let mut bytes = [0u8; 4];
                                                    bytes.copy_from_slice(chunk);
                                                    res.push(u32::from_ne_bytes(bytes));
                                                }
                                                let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                if !(res.len() == 1 && res[0] == 0)
                                                    || (aux.len() - 8) / 4 == lz
                                                {
                                                    let mut bytes_out = Vec::new();
                                                    let rl = res.len();
                                                    for (idx, &val) in res.iter().enumerate().rev() {
                                                        let bytes = val.to_be_bytes();
                                                        if idx == rl - 1 {
                                                            let mut skip = 0;
                                                            while skip < 4 && bytes[skip] == 0 {
                                                                skip += 1;
                                                            }
                                                            bytes_out.extend_from_slice(&bytes[skip..]);
                                                        } else {
                                                            bytes_out.extend_from_slice(&bytes);
                                                        }
                                                    }
                                                    out.extend(bytes_out);
                                                }
                                                data = out;
                                            } else {
                                                data = Vec::new();
                                            }
                                            aux.clear();
                                            let mut offset_1853531891 = 1766521055u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_1853531891)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 141u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3144331401u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(3353764169u32).rotate_left(5)
                                                ^ 3411977286u32;
                                            rs = rs.wrapping_add(2225237179u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1974873243u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4180902094u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data.reverse();
                                            rs = rs.wrapping_add(816559877u32).rotate_left(5)
                                                ^ 1156398197u32;
                                            rs = rs.wrapping_sub(962941859u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3464312166u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                *b ^= 206u8;
                                            }
                                            rs = rs.wrapping_add(3239564453u32).rotate_left(5)
                                                ^ 311709142u32;
                                            rs = rs.wrapping_add(341391527u32);
                                            rs = rs.wrapping_sub(2353635308u32).rotate_right(7);
                                            rs = rs.rotate_left(25u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        761864509u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            data.reverse();
                                            rs = rs.wrapping_add(3573116972u32).rotate_left(5)
                                                ^ 3843931205u32;
                                            rs = rs.rotate_left(26u32);
                                            rs = rs.rotate_left(15u32);
                                            rs ^= 2606641937u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2855287913u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(222u8);
                                                rs = rs.wrapping_add(360403418u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(13u8);
                                                rs = rs.wrapping_add(1276988741u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            let mut offset_2851064067 = 2271140320u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_2851064067)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 83u8);
                                            }
                                            rs = rs.wrapping_add(2147285128u32).rotate_left(5)
                                                ^ 565825504u32;
                                            rs ^= 3711141207u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2946311173u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4180902094u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(671375382u32).rotate_left(5)
                                                ^ 160215728u32;
                                            rs = rs.wrapping_add(3805810867u32);
                                            rs = rs.wrapping_add(3040536783u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2375147401u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1849720850u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data = data
                                                .iter()
                                                .filter_map(|&b| {
                                                    let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                        as usize];
                                                    if v == 255 { None } else { Some(v) }
                                                })
                                                .collect();
                                            rs = rs.wrapping_add(116620392u32).rotate_left(5)
                                                ^ 581944507u32;
                                            rs ^= 1090665747u32;
                                            rs = rs.wrapping_sub(2525594675u32).rotate_right(7);
                                            rs = rs.wrapping_sub(2884174790u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3382861776u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            aux.clear();
                                            aux.extend_from_slice(&0u32.to_ne_bytes());
                                            let lz = data.iter().take_while(|&&x| x == 0).count();
                                            let mut res: Vec<u32> = aux
                                                .chunks_exact(4)
                                                .map(|c| {
                                                    let mut b = [0u8; 4];
                                                    b.copy_from_slice(c);
                                                    u32::from_ne_bytes(b)
                                                })
                                                .collect();
                                            data.iter()
                                                .skip(lz)
                                                .for_each(|&v| {
                                                    let mut carry = v as u64;
                                                    res.iter_mut()
                                                        .for_each(|digit| {
                                                            let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                            *digit = prod as u32;
                                                            carry = prod >> 32;
                                                        });
                                                    while carry > 0 {
                                                        res.push(carry as u32);
                                                        carry >>= 32;
                                                    }
                                                });
                                            aux.clear();
                                            res.iter()
                                                .for_each(|val| aux.extend_from_slice(&val.to_ne_bytes()));
                                            let mut next_aux = (lz as u64).to_ne_bytes().to_vec();
                                            next_aux.extend_from_slice(&aux);
                                            aux.clear();
                                            aux.extend(next_aux);
                                            rs = rs.wrapping_add(1299252058u32).rotate_left(5)
                                                ^ 3589899162u32;
                                            rs = rs.wrapping_sub(3675095550u32).rotate_right(7);
                                            rs = rs.wrapping_sub(1865424502u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3582618606u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            if aux.len() >= 8 {
                                                let mut lz_bytes = [0u8; 8];
                                                lz_bytes.copy_from_slice(&aux[0..8]);
                                                let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                let mut res = Vec::new();
                                                for chunk in aux[8..].chunks_exact(4) {
                                                    let mut bytes = [0u8; 4];
                                                    bytes.copy_from_slice(chunk);
                                                    res.push(u32::from_ne_bytes(bytes));
                                                }
                                                let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                if !(res.len() == 1 && res[0] == 0)
                                                    || (aux.len() - 8) / 4 == lz
                                                {
                                                    let mut bytes_out = Vec::new();
                                                    let rl = res.len();
                                                    for (idx, &val) in res.iter().enumerate().rev() {
                                                        let bytes = val.to_be_bytes();
                                                        if idx == rl - 1 {
                                                            let mut skip = 0;
                                                            while skip < 4 && bytes[skip] == 0 {
                                                                skip += 1;
                                                            }
                                                            bytes_out.extend_from_slice(&bytes[skip..]);
                                                        } else {
                                                            bytes_out.extend_from_slice(&bytes);
                                                        }
                                                    }
                                                    out.extend(bytes_out);
                                                }
                                                data = out;
                                            } else {
                                                data = Vec::new();
                                            }
                                            aux.clear();
                                            rs = rs.wrapping_add(2710242555u32).rotate_left(5)
                                                ^ 2755963998u32;
                                            rs ^= 3841931635u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        680498013u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(16u8);
                                                rs = rs.wrapping_add(1757607324u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            let mut offset_4190499547 = 2952933310u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_4190499547)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 128u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1849720850u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(1491246900u32).rotate_left(5)
                                                ^ 1176331023u32;
                                            rs ^= 1866233281u32;
                                            rs = rs.rotate_left(20u32);
                                            rs = rs.wrapping_add(1689475231u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        _ => (data.to_vec(), rs_in),
                                    }
                                };
                                let mut aux_2613639558 = Vec::new();
                                let mut rs_j_2613639558 = 0u32;
                                let mut db_2613639558 = {
                                    let mut rd = Vec::new();
                                    let mut ei = self.e.iter();
                                    let mut oi = self.o.iter();
                                    loop {
                                        match (ei.next(), oi.next()) {
                                            (Some(ev), Some(ov)) => {
                                                rd.push(*ev);
                                                rd.push(*ov);
                                            }
                                            (Some(ev), None) => {
                                                rd.push(*ev);
                                                break;
                                            }
                                            _ => break,
                                        }
                                    }
                                    let mut k_2694740393 = self.key;
                                    let mut db_2613639558: Vec<u8> = rd
                                        .iter()
                                        .map(|br_383065134| {
                                            let b_3821707565 = *br_383065134;
                                            let db = b_3821707565 ^ k_2694740393;
                                            k_2694740393 = k_2694740393.wrapping_add(b_3821707565);
                                            db
                                        })
                                        .collect();
                                    rs_j_2613639558 = rs_j_2613639558
                                        .wrapping_sub(1793729919u32)
                                        .rotate_right(7);
                                    rs_j_2613639558 = rs_j_2613639558
                                        .wrapping_sub(1679700009u32)
                                        .rotate_right(7);
                                    let lock_out_junk = (rs_j_2613639558
                                        ^ (rs_j_2613639558 >> 13) ^ (rs_j_2613639558 >> 21)) as u8;
                                    for b in db_2613639558.iter_mut() {
                                        *b ^= lock_out_junk;
                                    }
                                    db_2613639558
                                };
                                let mut ds_2613639558 = db_2613639558;
                                let mut s_2613639558 = 0usize;
                                let mut m_2613639558 = ds_2613639558.clone();
                                let mut rs_2613639558 = 0u32;
                                loop {
                                    match s_2613639558 {
                                        0usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                1048102338u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_527984736 = 2485047591u32;
                                        }
                                        1usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                2360320172u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_2302180200 = 1913575133u32;
                                        }
                                        2usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                3289209064u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_3945553157 = 1839037570u32;
                                        }
                                        3usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                403464801u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_2585096662 = 3397091385u32;
                                        }
                                        4usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                2596382668u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1521810381 = 1135004838u32;
                                        }
                                        5usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                4036285108u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_2330892619 = 2545103262u32;
                                        }
                                        6usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                802972432u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_2157055515 = 1521129868u32;
                                        }
                                        7usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                885203312u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_3377730619 = 2708615648u32;
                                        }
                                        8usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                1208713351u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_285850643 = 3342493875u32;
                                        }
                                        9usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                3353764169u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1401427115 = 3253460239u32;
                                        }
                                        10usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                816559877u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_4117031966 = 3779478924u32;
                                        }
                                        11usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                3239564453u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1729514922 = 2533726073u32;
                                        }
                                        12usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                3573116972u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_4062963470 = 2697327725u32;
                                        }
                                        13usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                2147285128u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_3742844154 = 2847131694u32;
                                        }
                                        14usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                671375382u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1066311497 = 779505428u32;
                                        }
                                        15usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                116620392u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_2698833699 = 633182019u32;
                                        }
                                        16usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                1299252058u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1059484602 = 127803385u32;
                                        }
                                        17usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                2710242555u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            m_2613639558 = res_data;
                                            rs_2613639558 = next_rs;
                                            s_2613639558 += 1;
                                            let j_1254533027 = 322813256u32;
                                        }
                                        18usize => {
                                            let (res_data, next_rs) = d_2613639558(
                                                1491246900u32 ^ rs_2613639558,
                                                &m_2613639558,
                                                rs_2613639558,
                                                &mut aux_2613639558,
                                            );
                                            let fb_2063893708 = res_data;
                                            let nr_2833828447 = next_rs;
                                            let fv = {
                                                let mut trs_1510039849 = nr_2833828447;
                                                struct S_3032597949(Vec<u8>, u32);
                                                impl ::std::fmt::Display for S_3032597949 {
                                                    fn fmt(
                                                        &self,
                                                        f: &mut ::std::fmt::Formatter<'_>,
                                                    ) -> ::std::fmt::Result {
                                                        let mut irs_2394787223 = self.1;
                                                        let lck_2910703755 = (irs_2394787223
                                                            ^ (irs_2394787223 >> 13) ^ (irs_2394787223 >> 21)) as u8;
                                                        let unlocked: Vec<u8> = self
                                                            .0
                                                            .iter()
                                                            .map(|&b_1026389127| {
                                                                ((b_1026389127 ^ (lck_2910703755 ^ 35u8)) ^ 35u8)
                                                            })
                                                            .collect();
                                                        for chunk in unlocked.chunks(5usize) {
                                                            let s: String = chunk
                                                                .iter()
                                                                .map(|&b_1026389127| {
                                                                    irs_2394787223 = irs_2394787223
                                                                        .wrapping_add(b_1026389127 as u32)
                                                                        .rotate_left(3);
                                                                    b_1026389127 as char
                                                                })
                                                                .collect();
                                                            f.write_str(&s)?;
                                                        }
                                                        Ok(())
                                                    }
                                                }
                                                let res_2419724478 = S_3032597949(
                                                        fb_2063893708.clone(),
                                                        trs_1510039849,
                                                    )
                                                    .to_string();
                                                for &b_1026389127 in &fb_2063893708 {
                                                    let lck_2910703755 = (trs_1510039849
                                                        ^ (trs_1510039849 >> 13) ^ (trs_1510039849 >> 21)) as u8;
                                                    let ub_875618984 = ((b_1026389127 ^ (lck_2910703755 ^ 98u8))
                                                        ^ 98u8);
                                                    trs_1510039849 = trs_1510039849
                                                        .wrapping_add(ub_875618984 as u32)
                                                        .rotate_left(3);
                                                }
                                                nr_2833828447 = trs_1510039849;
                                                res_2419724478
                                            };
                                            break fv;
                                        }
                                        _ => break String::new(),
                                    }
                                }
                            }
                        }
                        let mut inst = O_2613639558 {
                            e: b"ZI\xa3J\x1ax\xcf\x16**\xe2^\xb4\nz\x1a\xf6\x14\xacK\x92Fd\xb9\xc9\xbdgq\xa0\x94\xb1\xe4\xad\xb4\xa4\xd4<Q\xba\xc0\"\xe1\xc05\xe4-\x86CF\x15\xb3p\xb8\x89\xbd\x9am\xb3\x81w",
                            o: b"\xa7\xd3\x05\xa9-\xc5\xe8\x83\x10u\xbd\xf2\x8b\x04\x8e^\x9eD7\xda\x1e\xf4\xe2u\xca7\xa2\xeaBf{\xea^mQ\x8c\r\xf6n\x82Im\xa6C\x84X1\xac\x92u\x14\xd6rL\x1f1\xd5V\x0c\xb4",
                            key: 251u8,
                        };
                        inst.r_2613639558()
                    },
                ),
            );
        };
        let mut operator = String::new();
        io::stdin().read_line(&mut operator).expect("Failed to read line");
        let operator = operator.trim();
        {
            ::std::io::_print(
                format_args!(
                    "{0}\n",
                    {
                        struct O_2066585199<'a> {
                            j: &'a [u8],
                            key: u8,
                        }
                        impl<'a> O_2066585199<'a> {
                            fn r_2066585199(&mut self) -> String {
                                let mut d_2066585199 = |
                                    id: u32,
                                    data: &[u8],
                                    rs_in: u32,
                                    aux: &mut Vec<u8>,
                                | -> (Vec<u8>, u32) {
                                    match (((id ^ rs_in).wrapping_mul(1400396063u32)
                                        ^ 1543868096u32)
                                        .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                    {
                                        4242506229u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(247u8);
                                                rs = rs.wrapping_add(358334404u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1522729817u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            rs = rs.wrapping_add(1326930054u32).rotate_left(5)
                                                ^ 2088491100u32;
                                            rs ^= 1160215269u32;
                                            rs ^= 1966070535u32;
                                            rs = rs.wrapping_sub(2938075194u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1138257312u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(133u8);
                                                rs = rs.wrapping_add(3636965229u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(94u8);
                                                rs = rs.wrapping_add(971829532u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(2040257776u32).rotate_left(5)
                                                ^ 388571374u32;
                                            rs ^= 3457854860u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1559408943u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            if data.len() > 0 {
                                                let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                let mut idx = 0;
                                                for i in 0..4usize {
                                                    let mut j = i;
                                                    while j < data.len() {
                                                        out[j] = data[idx];
                                                        idx += 1;
                                                        j += 4usize;
                                                    }
                                                }
                                                data = out;
                                            }
                                            let mut offset_807791951 = 4243259261u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_807791951)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 112u8);
                                            }
                                            rs = rs.wrapping_add(2249444738u32).rotate_left(5)
                                                ^ 1598799200u32;
                                            rs = rs.rotate_left(11u32);
                                            rs ^= 2803668388u32;
                                            rs = rs.wrapping_add(3420858253u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        988745857u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1522729817u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3179456299u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            rs = rs.wrapping_add(1145070719u32).rotate_left(5)
                                                ^ 3563251601u32;
                                            rs = rs.rotate_left(7u32);
                                            rs = rs.wrapping_add(311602711u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3283617828u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            if data.len() > 0 {
                                                let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                let mut idx = 0;
                                                for i in 0..3usize {
                                                    let mut j = i;
                                                    while j < data.len() {
                                                        out[j] = data[idx];
                                                        idx += 1;
                                                        j += 3usize;
                                                    }
                                                }
                                                data = out;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(49u8);
                                                rs = rs.wrapping_add(1669578003u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(324672096u32).rotate_left(5)
                                                ^ 3751906281u32;
                                            rs ^= 2000120612u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1945551466u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_2275089602 = 2007767453u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_2275089602)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 183u8);
                                            }
                                            rs = rs.wrapping_add(832067282u32).rotate_left(5)
                                                ^ 1728183005u32;
                                            rs ^= 237585418u32;
                                            rs = rs.wrapping_add(1894202355u32);
                                            rs ^= 184882038u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3340468030u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3179456299u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1980651647u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(218u8);
                                                rs = rs.wrapping_add(222895895u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(79689429u32).rotate_left(5)
                                                ^ 2916907977u32;
                                            rs ^= 2975702143u32;
                                            rs = rs.wrapping_add(3820943921u32);
                                            rs = rs.wrapping_sub(1501472596u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        81943096u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut out = Vec::new();
                                            let mut acc = 0u128;
                                            let mut count = 0u32;
                                            let mut bc = 0u64;
                                            for &v in data.iter() {
                                                acc = (acc << 4u32) | (v as u128);
                                                count += 4u32;
                                                while count >= 8 {
                                                    count -= 8;
                                                    if bc < 400u64 {
                                                        out.push((acc >> count) as u8);
                                                        bc += 8;
                                                    }
                                                    acc &= (1 << count) - 1;
                                                }
                                            }
                                            data = out;
                                            let mut offset_1714601710 = 2324524349u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_1714601710)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 236u8);
                                            }
                                            rs = rs.wrapping_add(1448994562u32).rotate_left(5)
                                                ^ 305413955u32;
                                            rs = rs.wrapping_sub(930572998u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2027697336u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1980651647u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2419726615u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            if data.len() > 0 {
                                                let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                let mut idx = 0;
                                                for i in 0..5usize {
                                                    let mut j = i;
                                                    while j < data.len() {
                                                        out[j] = data[idx];
                                                        idx += 1;
                                                        j += 5usize;
                                                    }
                                                }
                                                data = out;
                                            }
                                            rs = rs.wrapping_add(111094880u32).rotate_left(5)
                                                ^ 3099655984u32;
                                            rs ^= 1690139054u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        130912073u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_3076334715 = 3320410570u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_3076334715)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 147u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2419726615u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(2684566164u32).rotate_left(5)
                                                ^ 1801904046u32;
                                            rs = rs.wrapping_add(250003402u32);
                                            rs = rs.rotate_left(12u32);
                                            rs = rs.wrapping_sub(3180460805u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3165728778u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2762802672u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data = data
                                                .iter()
                                                .filter_map(|&b| {
                                                    let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                        as usize];
                                                    if v == 255 {
                                                        None
                                                    } else {
                                                        v = v.wrapping_sub(178u8).wrapping_add(178u8);
                                                        Some(v)
                                                    }
                                                })
                                                .collect();
                                            rs = rs.wrapping_add(2811061862u32).rotate_left(5)
                                                ^ 1005116910u32;
                                            rs = rs.wrapping_add(3155211903u32);
                                            rs ^= 4258413855u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3514137062u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut out = Vec::new();
                                            let mut bc = 0u64;
                                            for chunk in data.chunks(8) {
                                                let mut val = 0u64;
                                                for (i, &idx) in chunk.iter().enumerate() {
                                                    val |= (idx as u64) << (35 - i * 5);
                                                }
                                                for i in (0..5).rev() {
                                                    if bc < 248u64 {
                                                        out.push(((val >> (i * 8)) & 0xff) as u8);
                                                        bc += 8;
                                                    }
                                                }
                                            }
                                            data = out;
                                            let mut offset_491308991 = 2308955289u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_491308991)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 31u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2762802672u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(1646659972u32).rotate_left(5)
                                                ^ 1544765418u32;
                                            rs = rs.rotate_left(2u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        285998652u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1114785836u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            rs = rs.wrapping_add(3014747789u32).rotate_left(5)
                                                ^ 3456873180u32;
                                            rs = rs.wrapping_add(1167320745u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1963917154u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(131u8);
                                                rs = rs.wrapping_add(643694930u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            rs = rs.wrapping_add(4093815492u32).rotate_left(5)
                                                ^ 1345168884u32;
                                            rs = rs.rotate_left(23u32);
                                            rs ^= 1460617649u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1915356941u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                let n = (rs >> 8) as u8;
                                                *b = b.wrapping_add(n).wrapping_sub(n);
                                                *b ^= 229u8;
                                            }
                                            rs = rs.wrapping_add(2412640789u32).rotate_left(5)
                                                ^ 2875958911u32;
                                            rs = rs.wrapping_add(973212237u32);
                                            rs = rs.wrapping_sub(3786550660u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2364264454u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                let n = (rs >> 8) as u8;
                                                *b = b.wrapping_add(n).wrapping_sub(n);
                                                *b ^= 30u8;
                                            }
                                            rs = rs.wrapping_add(4187494744u32).rotate_left(5)
                                                ^ 4028620776u32;
                                            rs = rs.rotate_left(4u32);
                                            rs = rs.wrapping_add(2273164901u32);
                                            rs = rs.wrapping_add(3843746154u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2552117546u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_3811757669 = 3129354917u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_3811757669)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 186u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 1114785836u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(1051138524u32).rotate_left(5)
                                                ^ 2289723703u32;
                                            rs = rs.wrapping_sub(2027946801u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        301436350u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(148u8);
                                                rs = rs.wrapping_add(3703969004u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(1104129177u32).rotate_left(5)
                                                ^ 2339191289u32;
                                            rs = rs.wrapping_sub(4283645953u32).rotate_right(7);
                                            rs ^= 2088107378u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        _ => (data.to_vec(), rs_in),
                                    }
                                };
                                let mut aux_2066585199 = Vec::new();
                                let mut rs_j_2066585199 = 0u32;
                                let mut db_2066585199 = {
                                    let mut rd: Vec<u8> = self
                                        .j
                                        .iter()
                                        .step_by(2)
                                        .cloned()
                                        .collect();
                                    let mut k_1761623481 = self.key;
                                    let mut db_2066585199: Vec<u8> = rd
                                        .iter()
                                        .map(|br_731032999| {
                                            let b_3187231769 = *br_731032999;
                                            let db = b_3187231769 ^ k_1761623481;
                                            k_1761623481 = k_1761623481.rotate_left(3);
                                            db
                                        })
                                        .collect();
                                    rs_j_2066585199 = rs_j_2066585199
                                        .wrapping_add(3458018413u32);
                                    let lock_out_junk = (rs_j_2066585199
                                        ^ (rs_j_2066585199 >> 13) ^ (rs_j_2066585199 >> 21)) as u8;
                                    for b in db_2066585199.iter_mut() {
                                        *b ^= lock_out_junk;
                                    }
                                    db_2066585199
                                };
                                let mut ds_2066585199 = db_2066585199;
                                {
                                    let mut nd_0_2066585199 = ds_2066585199.clone();
                                    let mut rs_2066585199 = 0u32;
                                    {
                                        let (res_data, next_rs_val) = d_2066585199(
                                            1326930054u32 ^ rs_2066585199,
                                            &nd_0_2066585199,
                                            rs_2066585199,
                                            &mut aux_2066585199,
                                        );
                                        let mut rs_2066585199 = next_rs_val;
                                        let nb_0_2066585199 = res_data;
                                        let j_2529905387 = 1552957995u32;
                                        let mut nd_1_2066585199 = nb_0_2066585199;
                                        {
                                            let (res_data, next_rs_val) = d_2066585199(
                                                2040257776u32 ^ rs_2066585199,
                                                &nd_1_2066585199,
                                                rs_2066585199,
                                                &mut aux_2066585199,
                                            );
                                            let mut rs_2066585199 = next_rs_val;
                                            let nb_1_2066585199 = res_data;
                                            let j_2400105236 = 590629475u32;
                                            let mut nd_2_2066585199 = nb_1_2066585199;
                                            {
                                                let (res_data, next_rs_val) = d_2066585199(
                                                    2249444738u32 ^ rs_2066585199,
                                                    &nd_2_2066585199,
                                                    rs_2066585199,
                                                    &mut aux_2066585199,
                                                );
                                                let mut rs_2066585199 = next_rs_val;
                                                let nb_2_2066585199 = res_data;
                                                let j_3977152276 = 2750024977u32;
                                                let mut nd_3_2066585199 = nb_2_2066585199;
                                                {
                                                    let (res_data, next_rs_val) = d_2066585199(
                                                        1145070719u32 ^ rs_2066585199,
                                                        &nd_3_2066585199,
                                                        rs_2066585199,
                                                        &mut aux_2066585199,
                                                    );
                                                    let mut rs_2066585199 = next_rs_val;
                                                    let nb_3_2066585199 = res_data;
                                                    let j_370707508 = 2842474867u32;
                                                    let mut nd_4_2066585199 = nb_3_2066585199;
                                                    {
                                                        let (res_data, next_rs_val) = d_2066585199(
                                                            324672096u32 ^ rs_2066585199,
                                                            &nd_4_2066585199,
                                                            rs_2066585199,
                                                            &mut aux_2066585199,
                                                        );
                                                        let mut rs_2066585199 = next_rs_val;
                                                        let nb_4_2066585199 = res_data;
                                                        let j_4238995124 = 3953941262u32;
                                                        let mut nd_5_2066585199 = nb_4_2066585199;
                                                        {
                                                            let (res_data, next_rs_val) = d_2066585199(
                                                                832067282u32 ^ rs_2066585199,
                                                                &nd_5_2066585199,
                                                                rs_2066585199,
                                                                &mut aux_2066585199,
                                                            );
                                                            let mut rs_2066585199 = next_rs_val;
                                                            let nb_5_2066585199 = res_data;
                                                            let j_1730050810 = 1474350600u32;
                                                            let mut nd_6_2066585199 = nb_5_2066585199;
                                                            {
                                                                let (res_data, next_rs_val) = d_2066585199(
                                                                    79689429u32 ^ rs_2066585199,
                                                                    &nd_6_2066585199,
                                                                    rs_2066585199,
                                                                    &mut aux_2066585199,
                                                                );
                                                                let mut rs_2066585199 = next_rs_val;
                                                                let nb_6_2066585199 = res_data;
                                                                let j_591575693 = 1970790093u32;
                                                                let mut nd_7_2066585199 = nb_6_2066585199;
                                                                {
                                                                    let (res_data, next_rs_val) = d_2066585199(
                                                                        1448994562u32 ^ rs_2066585199,
                                                                        &nd_7_2066585199,
                                                                        rs_2066585199,
                                                                        &mut aux_2066585199,
                                                                    );
                                                                    let mut rs_2066585199 = next_rs_val;
                                                                    let nb_7_2066585199 = res_data;
                                                                    let j_3475661643 = 2400673630u32;
                                                                    let mut nd_8_2066585199 = nb_7_2066585199;
                                                                    {
                                                                        let (res_data, next_rs_val) = d_2066585199(
                                                                            111094880u32 ^ rs_2066585199,
                                                                            &nd_8_2066585199,
                                                                            rs_2066585199,
                                                                            &mut aux_2066585199,
                                                                        );
                                                                        let mut rs_2066585199 = next_rs_val;
                                                                        let nb_8_2066585199 = res_data;
                                                                        let j_2505613870 = 3735941041u32;
                                                                        let mut nd_9_2066585199 = nb_8_2066585199;
                                                                        {
                                                                            let (res_data, next_rs_val) = d_2066585199(
                                                                                2684566164u32 ^ rs_2066585199,
                                                                                &nd_9_2066585199,
                                                                                rs_2066585199,
                                                                                &mut aux_2066585199,
                                                                            );
                                                                            let mut rs_2066585199 = next_rs_val;
                                                                            let nb_9_2066585199 = res_data;
                                                                            let j_4224531228 = 1231249445u32;
                                                                            let mut nd_10_2066585199 = nb_9_2066585199;
                                                                            {
                                                                                let (res_data, next_rs_val) = d_2066585199(
                                                                                    2811061862u32 ^ rs_2066585199,
                                                                                    &nd_10_2066585199,
                                                                                    rs_2066585199,
                                                                                    &mut aux_2066585199,
                                                                                );
                                                                                let mut rs_2066585199 = next_rs_val;
                                                                                let nb_10_2066585199 = res_data;
                                                                                let j_7018738 = 1622326473u32;
                                                                                let mut nd_11_2066585199 = nb_10_2066585199;
                                                                                {
                                                                                    let (res_data, next_rs_val) = d_2066585199(
                                                                                        1646659972u32 ^ rs_2066585199,
                                                                                        &nd_11_2066585199,
                                                                                        rs_2066585199,
                                                                                        &mut aux_2066585199,
                                                                                    );
                                                                                    let mut rs_2066585199 = next_rs_val;
                                                                                    let nb_11_2066585199 = res_data;
                                                                                    let j_101067241 = 2659792908u32;
                                                                                    let mut nd_12_2066585199 = nb_11_2066585199;
                                                                                    {
                                                                                        let (res_data, next_rs_val) = d_2066585199(
                                                                                            3014747789u32 ^ rs_2066585199,
                                                                                            &nd_12_2066585199,
                                                                                            rs_2066585199,
                                                                                            &mut aux_2066585199,
                                                                                        );
                                                                                        let mut rs_2066585199 = next_rs_val;
                                                                                        let nb_12_2066585199 = res_data;
                                                                                        let j_2925386745 = 227433692u32;
                                                                                        let mut nd_13_2066585199 = nb_12_2066585199;
                                                                                        {
                                                                                            let (res_data, next_rs_val) = d_2066585199(
                                                                                                4093815492u32 ^ rs_2066585199,
                                                                                                &nd_13_2066585199,
                                                                                                rs_2066585199,
                                                                                                &mut aux_2066585199,
                                                                                            );
                                                                                            let mut rs_2066585199 = next_rs_val;
                                                                                            let nb_13_2066585199 = res_data;
                                                                                            let j_3471417980 = 1251531158u32;
                                                                                            let mut nd_14_2066585199 = nb_13_2066585199;
                                                                                            {
                                                                                                let (res_data, next_rs_val) = d_2066585199(
                                                                                                    2412640789u32 ^ rs_2066585199,
                                                                                                    &nd_14_2066585199,
                                                                                                    rs_2066585199,
                                                                                                    &mut aux_2066585199,
                                                                                                );
                                                                                                let mut rs_2066585199 = next_rs_val;
                                                                                                let nb_14_2066585199 = res_data;
                                                                                                let j_488596486 = 2922026832u32;
                                                                                                let mut nd_15_2066585199 = nb_14_2066585199;
                                                                                                {
                                                                                                    let (res_data, next_rs_val) = d_2066585199(
                                                                                                        4187494744u32 ^ rs_2066585199,
                                                                                                        &nd_15_2066585199,
                                                                                                        rs_2066585199,
                                                                                                        &mut aux_2066585199,
                                                                                                    );
                                                                                                    let mut rs_2066585199 = next_rs_val;
                                                                                                    let nb_15_2066585199 = res_data;
                                                                                                    let j_1951216562 = 1368428163u32;
                                                                                                    let mut nd_16_2066585199 = nb_15_2066585199;
                                                                                                    {
                                                                                                        let (res_data, next_rs_val) = d_2066585199(
                                                                                                            1051138524u32 ^ rs_2066585199,
                                                                                                            &nd_16_2066585199,
                                                                                                            rs_2066585199,
                                                                                                            &mut aux_2066585199,
                                                                                                        );
                                                                                                        let mut rs_2066585199 = next_rs_val;
                                                                                                        let nb_16_2066585199 = res_data;
                                                                                                        let j_695214136 = 719320363u32;
                                                                                                        let mut nd_17_2066585199 = nb_16_2066585199;
                                                                                                        {
                                                                                                            let (res_data, next_rs) = d_2066585199(
                                                                                                                1104129177u32 ^ rs_2066585199,
                                                                                                                &nd_17_2066585199,
                                                                                                                rs_2066585199,
                                                                                                                &mut aux_2066585199,
                                                                                                            );
                                                                                                            let lb_2066585199 = res_data;
                                                                                                            let nr_last_2066585199 = next_rs;
                                                                                                            {
                                                                                                                let lck_651580704 = (nr_last_2066585199
                                                                                                                    ^ (nr_last_2066585199 >> 13) ^ (nr_last_2066585199 >> 21))
                                                                                                                    as u8;
                                                                                                                let mut res_1236582561 = String::with_capacity(
                                                                                                                    lb_2066585199.len(),
                                                                                                                );
                                                                                                                for &b_1146170929 in &lb_2066585199 {
                                                                                                                    let ub_1100813012 = (b_1146170929 ^ lck_651580704);
                                                                                                                    nr_last_2066585199 = nr_last_2066585199
                                                                                                                        .wrapping_add(ub_1100813012 as u32)
                                                                                                                        .rotate_left(3);
                                                                                                                    res_1236582561.push(ub_1100813012 as char);
                                                                                                                }
                                                                                                                res_1236582561
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let mut inst = O_2066585199 {
                            j: b"\xf6\xd2p\x0bMH\xaf[\xa1'\xda\xcb\x1bq\x01\x0c\xf7\x90n\x80I\x8a\xbf\xc3\xb9\x05\xcb\xf8\x14\x9c\0\x9c\xf1\xe6h\xbeL\x08\xb4\x02\xa6_\xca\x1e\x04\x8e\x02\xaa\xeb=j{Q/\xab\xfe\xbc\xaf\xdaB\x1ar\x04\x8c\xed\x13\x7f\xdbV\x96\xae-\xa7l\xd8\xc8\x1f\xa8\x087\xf2O}\x13MH\xa3\xee\xa5\x1a\xd5\xe0\x19\xe4\x0e\x9f\xf1\xd5\x7f\xa2Nn\xb31\xa5\x19\xc2\x0b\x14e\x1d\n\xf6\xeal\x98H\xdb\xbf\x0f\xa69\xca\x8e\x05!\x1fR\xeezb\x8dPZ\xb0n\xbcv\xc5\xef\x070\x19\x1a\xe4=v5P\\\xbb\x84\xb0\x1a\xf3\x19\x06\x12\x19$\xef\xcdZIJ\x04\xb6\xe0\xbbX\xc3\x15\x1f\x83\x1cM\xefMjiV\xae\xb0\x9d\xa4\x96\xc9r\x18\x9b\x1a\x8e\xec\x81l9Mg\xb3\xe3",
                            key: 54u8,
                        };
                        inst.r_2066585199()
                    },
                ),
            );
        };
        let mut num2 = String::new();
        io::stdin().read_line(&mut num2).expect("Failed to read line");
        let num2: f64 = match num2.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                {
                    ::std::io::_print(
                        format_args!(
                            "{0}\n",
                            {
                                struct O_1342797433<'a> {
                                    d: &'a [u8],
                                    key: u8,
                                }
                                impl<'a> O_1342797433<'a> {
                                    fn r_1342797433(&mut self) -> String {
                                        let mut d_1342797433 = |
                                            id: u32,
                                            data: &[u8],
                                            rs_in: u32,
                                            aux: &mut Vec<u8>,
                                        | -> (Vec<u8>, u32) {
                                            match (((id ^ rs_in).wrapping_mul(191695117u32)
                                                ^ 3830277238u32)
                                                .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                            {
                                                1646000843u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2160300982u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(168u8);
                                                        rs = rs.wrapping_add(798125646u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(2232771231u32).rotate_left(5)
                                                        ^ 1037414175u32;
                                                    rs = rs.wrapping_add(768217663u32);
                                                    rs = rs.wrapping_add(1784477389u32);
                                                    rs ^= 3159802754u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                952023291u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    data = data
                                                        .iter()
                                                        .filter_map(|&b| {
                                                            let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                as usize];
                                                            if v == 255 {
                                                                None
                                                            } else {
                                                                v = v.wrapping_add(135u8).wrapping_sub(135u8);
                                                                Some(v)
                                                            }
                                                        })
                                                        .collect();
                                                    let mut out = Vec::new();
                                                    let mut acc = 0u128;
                                                    let mut count = 0u32;
                                                    let mut bc = 0u64;
                                                    for &v in data.iter() {
                                                        acc = (acc << 5u32) | (v as u128);
                                                        count += 5u32;
                                                        while count >= 8 {
                                                            count -= 8;
                                                            if bc < 1128u64 {
                                                                out.push((acc >> count) as u8);
                                                                bc += 8;
                                                            }
                                                            acc &= (1 << count) - 1;
                                                        }
                                                    }
                                                    data = out;
                                                    rs = rs.wrapping_add(4158968022u32).rotate_left(5)
                                                        ^ 4180112319u32;
                                                    rs = rs.wrapping_add(2455332739u32);
                                                    rs = rs.wrapping_add(4206221963u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                498943938u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_1368806374 = 2472656112u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_1368806374)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 49u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2160300982u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 742756820u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(2428535354u32).rotate_left(5)
                                                        ^ 702854714u32;
                                                    rs = rs.wrapping_add(2083193361u32);
                                                    rs = rs.wrapping_add(2010567660u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3903655875u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut out = Vec::with_capacity(data.len());
                                                    for &b in &data {
                                                        let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                            as usize];
                                                        if v != 255 {
                                                            out.push(v);
                                                        }
                                                    }
                                                    data = out;
                                                    aux.clear();
                                                    aux.extend_from_slice(&0u32.to_ne_bytes());
                                                    rs = rs.wrapping_add(964005060u32).rotate_left(5)
                                                        ^ 1901493256u32;
                                                    rs = rs.wrapping_add(2403923568u32);
                                                    rs = rs.rotate_left(5u32);
                                                    rs ^= 1221374251u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1115223152u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(44u8);
                                                        rs = rs.wrapping_add(1970073866u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    let mut leading_zeros = 0;
                                                    for &v in &data {
                                                        if v == 0 {
                                                            leading_zeros += 1;
                                                        } else {
                                                            break;
                                                        }
                                                    }
                                                    let mut res = Vec::new();
                                                    for chunk in aux.chunks_exact(4) {
                                                        let mut bytes = [0u8; 4];
                                                        bytes.copy_from_slice(chunk);
                                                        res.push(u32::from_ne_bytes(bytes));
                                                    }
                                                    for &v in &data[leading_zeros..] {
                                                        let mut carry = v as u64;
                                                        for digit in res.iter_mut() {
                                                            let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                            *digit = prod as u32;
                                                            carry = prod >> 32;
                                                        }
                                                        while carry > 0 {
                                                            res.push(carry as u32);
                                                            carry >>= 32;
                                                        }
                                                    }
                                                    aux.clear();
                                                    for val in res {
                                                        aux.extend_from_slice(&val.to_ne_bytes());
                                                    }
                                                    let lz = leading_zeros as u64;
                                                    let mut next_aux = lz.to_ne_bytes().to_vec();
                                                    next_aux.extend_from_slice(&aux);
                                                    aux.clear();
                                                    aux.extend(next_aux);
                                                    rs = rs.wrapping_add(3118197910u32).rotate_left(5)
                                                        ^ 1960787485u32;
                                                    rs = rs.wrapping_add(1004487510u32);
                                                    rs ^= 2498632589u32;
                                                    rs ^= 887821437u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                552633886u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    if aux.len() >= 8 {
                                                        let mut lz_bytes = [0u8; 8];
                                                        lz_bytes.copy_from_slice(&aux[0..8]);
                                                        let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                        let mut res = Vec::new();
                                                        for chunk in aux[8..].chunks_exact(4) {
                                                            let mut bytes = [0u8; 4];
                                                            bytes.copy_from_slice(chunk);
                                                            res.push(u32::from_ne_bytes(bytes));
                                                        }
                                                        let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                        if !(res.len() == 1 && res[0] == 0)
                                                            || (aux.len() - 8) / 4 == lz
                                                        {
                                                            let mut bytes_out = Vec::new();
                                                            let rl = res.len();
                                                            for (idx, &val) in res.iter().enumerate().rev() {
                                                                let bytes = val.to_be_bytes();
                                                                if idx == rl - 1 {
                                                                    let mut skip = 0;
                                                                    while skip < 4 && bytes[skip] == 0 {
                                                                        skip += 1;
                                                                    }
                                                                    bytes_out.extend_from_slice(&bytes[skip..]);
                                                                } else {
                                                                    bytes_out.extend_from_slice(&bytes);
                                                                }
                                                            }
                                                            out.extend(bytes_out);
                                                        }
                                                        data = out;
                                                    } else {
                                                        data = Vec::new();
                                                    }
                                                    aux.clear();
                                                    let mut offset_2639475483 = 2530800054u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_2639475483)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 235u8);
                                                    }
                                                    rs = rs.wrapping_add(3626808416u32).rotate_left(5)
                                                        ^ 3938355957u32;
                                                    rs ^= 70529896u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3776741204u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 742756820u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(3846344085u32).rotate_left(5)
                                                        ^ 2221289878u32;
                                                    rs = rs.rotate_left(18u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3251559442u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(55u8);
                                                        rs = rs.wrapping_add(1466843395u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1083450505u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(2088219677u32).rotate_left(5)
                                                        ^ 615540212u32;
                                                    rs = rs.rotate_left(29u32);
                                                    rs ^= 3675349732u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3282250951u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut out = Vec::with_capacity(data.len());
                                                    for &b in &data {
                                                        let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                            as usize];
                                                        if v != 255 {
                                                            out.push(v);
                                                        }
                                                    }
                                                    data = out;
                                                    aux.clear();
                                                    aux.extend_from_slice(&0u32.to_ne_bytes());
                                                    let mut leading_zeros = 0;
                                                    for &v in &data {
                                                        if v == 0 {
                                                            leading_zeros += 1;
                                                        } else {
                                                            break;
                                                        }
                                                    }
                                                    let mut res = Vec::new();
                                                    for chunk in aux.chunks_exact(4) {
                                                        let mut bytes = [0u8; 4];
                                                        bytes.copy_from_slice(chunk);
                                                        res.push(u32::from_ne_bytes(bytes));
                                                    }
                                                    for &v in &data[leading_zeros..] {
                                                        let mut carry = v as u64;
                                                        for digit in res.iter_mut() {
                                                            let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                            *digit = prod as u32;
                                                            carry = prod >> 32;
                                                        }
                                                        while carry > 0 {
                                                            res.push(carry as u32);
                                                            carry >>= 32;
                                                        }
                                                    }
                                                    aux.clear();
                                                    for val in res {
                                                        aux.extend_from_slice(&val.to_ne_bytes());
                                                    }
                                                    let lz = leading_zeros as u64;
                                                    let mut next_aux = lz.to_ne_bytes().to_vec();
                                                    next_aux.extend_from_slice(&aux);
                                                    aux.clear();
                                                    aux.extend(next_aux);
                                                    rs = rs.wrapping_add(478963407u32).rotate_left(5)
                                                        ^ 3502616877u32;
                                                    rs = rs.wrapping_sub(1518588960u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1895020393u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(22u8);
                                                        rs = rs.wrapping_add(2352608754u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(4u8);
                                                        rs = rs.wrapping_add(2860159068u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(1522428786u32).rotate_left(5)
                                                        ^ 1483600098u32;
                                                    rs = rs.rotate_left(16u32);
                                                    rs = rs.wrapping_sub(2361219243u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                4196182181u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(213u8);
                                                        rs = rs.wrapping_add(2230123009u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    if aux.len() >= 8 {
                                                        let mut lz_bytes = [0u8; 8];
                                                        lz_bytes.copy_from_slice(&aux[0..8]);
                                                        let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                        let mut res = Vec::new();
                                                        for chunk in aux[8..].chunks_exact(4) {
                                                            let mut bytes = [0u8; 4];
                                                            bytes.copy_from_slice(chunk);
                                                            res.push(u32::from_ne_bytes(bytes));
                                                        }
                                                        let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                        if !(res.len() == 1 && res[0] == 0)
                                                            || (aux.len() - 8) / 4 == lz
                                                        {
                                                            let mut bytes_out = Vec::new();
                                                            let rl = res.len();
                                                            for (idx, &val) in res.iter().enumerate().rev() {
                                                                let bytes = val.to_be_bytes();
                                                                if idx == rl - 1 {
                                                                    let mut skip = 0;
                                                                    while skip < 4 && bytes[skip] == 0 {
                                                                        skip += 1;
                                                                    }
                                                                    bytes_out.extend_from_slice(&bytes[skip..]);
                                                                } else {
                                                                    bytes_out.extend_from_slice(&bytes);
                                                                }
                                                            }
                                                            out.extend(bytes_out);
                                                        }
                                                        data = out;
                                                    } else {
                                                        data = Vec::new();
                                                    }
                                                    aux.clear();
                                                    rs = rs.wrapping_add(2632901402u32).rotate_left(5)
                                                        ^ 3391963694u32;
                                                    rs = rs.wrapping_add(3836104056u32);
                                                    rs = rs.rotate_left(8u32);
                                                    rs = rs.wrapping_add(186872362u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3402698893u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_1116644696 = 3365336854u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_1116644696)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 69u8);
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(47u8);
                                                        rs = rs.wrapping_add(970899157u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(2420549059u32).rotate_left(5)
                                                        ^ 1833383184u32;
                                                    rs = rs.rotate_left(22u32);
                                                    rs = rs.wrapping_add(2240122462u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                4234038445u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1083450505u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(1777251902u32).rotate_left(5)
                                                        ^ 1035401161u32;
                                                    rs = rs.wrapping_add(149356985u32);
                                                    rs = rs.rotate_left(22u32);
                                                    rs = rs.rotate_left(28u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                468103982u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1898133088u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    let mut out = Vec::new();
                                                    let mut acc = 0u128;
                                                    let mut count = 0u32;
                                                    let mut bc = 0u64;
                                                    for &v in data.iter() {
                                                        acc = (acc << 4u32) | (v as u128);
                                                        count += 4u32;
                                                        while count >= 8 {
                                                            count -= 8;
                                                            if bc < 296u64 {
                                                                out.push((acc >> count) as u8);
                                                                bc += 8;
                                                            }
                                                            acc &= (1 << count) - 1;
                                                        }
                                                    }
                                                    data = out;
                                                    rs = rs.wrapping_add(2083425737u32).rotate_left(5)
                                                        ^ 4243404229u32;
                                                    rs = rs.wrapping_sub(3207756378u32).rotate_right(7);
                                                    rs = rs.wrapping_add(3292341404u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                399139243u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_3104160563 = 1606063193u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_3104160563)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 157u8);
                                                    }
                                                    rs = rs.wrapping_add(199150374u32).rotate_left(5)
                                                        ^ 3452700464u32;
                                                    rs = rs.wrapping_add(526385926u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1170543177u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1898133088u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(518169443u32).rotate_left(5)
                                                        ^ 1054460305u32;
                                                    rs ^= 376690721u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                _ => (data.to_vec(), rs_in),
                                            }
                                        };
                                        let mut aux_1342797433 = Vec::new();
                                        let mut rs_j_1342797433 = 0u32;
                                        let mut db_1342797433 = {
                                            let mut rd = self.d.to_vec();
                                            let mut k_1007893708 = self.key;
                                            let mut db_1342797433: Vec<u8> = rd
                                                .iter()
                                                .map(|br_3494861210| {
                                                    let b_3814474596 = *br_3494861210;
                                                    let db = b_3814474596 ^ k_1007893708;
                                                    k_1007893708 = k_1007893708.wrapping_sub(b_3814474596);
                                                    db
                                                })
                                                .collect();
                                            rs_j_1342797433 = rs_j_1342797433.rotate_left(20u32);
                                            rs_j_1342797433 = rs_j_1342797433
                                                .wrapping_sub(1835414117u32)
                                                .rotate_right(7);
                                            rs_j_1342797433 = rs_j_1342797433
                                                .wrapping_sub(2994778682u32)
                                                .rotate_right(7);
                                            let lock_out_junk = (rs_j_1342797433
                                                ^ (rs_j_1342797433 >> 13) ^ (rs_j_1342797433 >> 21)) as u8;
                                            for b in db_1342797433.iter_mut() {
                                                *b ^= lock_out_junk;
                                            }
                                            db_1342797433
                                        };
                                        let mut ds_1342797433 = db_1342797433;
                                        {
                                            let mut cv_1342797433 = ds_1342797433.clone();
                                            let mut rs_1342797433 = 0u32;
                                            let (rd_0_1342797433, nr_0_1342797433) = d_1342797433(
                                                2232771231u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_0_1342797433 = rd_0_1342797433;
                                            rs_1342797433 = nr_0_1342797433;
                                            let j_124554358 = 1250349418u32;
                                            cv_1342797433 = b_0_1342797433;
                                            let (rd_1_1342797433, nr_1_1342797433) = d_1342797433(
                                                4158968022u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_1_1342797433 = rd_1_1342797433;
                                            rs_1342797433 = nr_1_1342797433;
                                            let j_3083303164 = 3632004768u32;
                                            cv_1342797433 = b_1_1342797433;
                                            let (rd_2_1342797433, nr_2_1342797433) = d_1342797433(
                                                2428535354u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_2_1342797433 = rd_2_1342797433;
                                            rs_1342797433 = nr_2_1342797433;
                                            let j_641866923 = 604024717u32;
                                            cv_1342797433 = b_2_1342797433;
                                            let (rd_3_1342797433, nr_3_1342797433) = d_1342797433(
                                                964005060u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_3_1342797433 = rd_3_1342797433;
                                            rs_1342797433 = nr_3_1342797433;
                                            let j_189211261 = 371084449u32;
                                            cv_1342797433 = b_3_1342797433;
                                            let (rd_4_1342797433, nr_4_1342797433) = d_1342797433(
                                                3118197910u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_4_1342797433 = rd_4_1342797433;
                                            rs_1342797433 = nr_4_1342797433;
                                            let j_2505108814 = 3095376288u32;
                                            cv_1342797433 = b_4_1342797433;
                                            let (rd_5_1342797433, nr_5_1342797433) = d_1342797433(
                                                3626808416u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_5_1342797433 = rd_5_1342797433;
                                            rs_1342797433 = nr_5_1342797433;
                                            let j_3953810018 = 1270195319u32;
                                            cv_1342797433 = b_5_1342797433;
                                            let (rd_6_1342797433, nr_6_1342797433) = d_1342797433(
                                                3846344085u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_6_1342797433 = rd_6_1342797433;
                                            rs_1342797433 = nr_6_1342797433;
                                            let j_612828928 = 1904371115u32;
                                            cv_1342797433 = b_6_1342797433;
                                            let (rd_7_1342797433, nr_7_1342797433) = d_1342797433(
                                                2088219677u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_7_1342797433 = rd_7_1342797433;
                                            rs_1342797433 = nr_7_1342797433;
                                            let j_3625643581 = 1590538342u32;
                                            cv_1342797433 = b_7_1342797433;
                                            let (rd_8_1342797433, nr_8_1342797433) = d_1342797433(
                                                478963407u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_8_1342797433 = rd_8_1342797433;
                                            rs_1342797433 = nr_8_1342797433;
                                            let j_4202880734 = 3889136583u32;
                                            cv_1342797433 = b_8_1342797433;
                                            let (rd_9_1342797433, nr_9_1342797433) = d_1342797433(
                                                1522428786u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_9_1342797433 = rd_9_1342797433;
                                            rs_1342797433 = nr_9_1342797433;
                                            let j_374763079 = 4201401279u32;
                                            cv_1342797433 = b_9_1342797433;
                                            let (rd_10_1342797433, nr_10_1342797433) = d_1342797433(
                                                2632901402u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_10_1342797433 = rd_10_1342797433;
                                            rs_1342797433 = nr_10_1342797433;
                                            let j_2826696916 = 2936329116u32;
                                            cv_1342797433 = b_10_1342797433;
                                            let (rd_11_1342797433, nr_11_1342797433) = d_1342797433(
                                                2420549059u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_11_1342797433 = rd_11_1342797433;
                                            rs_1342797433 = nr_11_1342797433;
                                            let j_1314687070 = 306211990u32;
                                            cv_1342797433 = b_11_1342797433;
                                            let (rd_12_1342797433, nr_12_1342797433) = d_1342797433(
                                                1777251902u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_12_1342797433 = rd_12_1342797433;
                                            rs_1342797433 = nr_12_1342797433;
                                            let j_3515317579 = 3402422442u32;
                                            cv_1342797433 = b_12_1342797433;
                                            let (rd_13_1342797433, nr_13_1342797433) = d_1342797433(
                                                2083425737u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_13_1342797433 = rd_13_1342797433;
                                            rs_1342797433 = nr_13_1342797433;
                                            let j_3953035724 = 325088604u32;
                                            cv_1342797433 = b_13_1342797433;
                                            let (rd_14_1342797433, nr_14_1342797433) = d_1342797433(
                                                199150374u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_14_1342797433 = rd_14_1342797433;
                                            rs_1342797433 = nr_14_1342797433;
                                            let j_135569271 = 3872046660u32;
                                            cv_1342797433 = b_14_1342797433;
                                            let (rd_15_1342797433, nr_15_1342797433) = d_1342797433(
                                                518169443u32 ^ rs_1342797433,
                                                &cv_1342797433,
                                                rs_1342797433,
                                                &mut aux_1342797433,
                                            );
                                            let b_15_1342797433 = rd_15_1342797433;
                                            rs_1342797433 = nr_15_1342797433;
                                            let j_647328319 = 369681501u32;
                                            let mut fv_1342797433 = b_15_1342797433;
                                            let mid = fv_1342797433.len() / 2;
                                            let h1_2474619222 = fv_1342797433[..mid].to_vec();
                                            let h2_2496869481 = fv_1342797433[mid..].to_vec();
                                            let frs = ::alloc::__export::must_use({
                                                ::alloc::fmt::format(
                                                    format_args!(
                                                        "{0}{1}",
                                                        {
                                                            let lck_1410754467 = (rs_1342797433 ^ (rs_1342797433 >> 13)
                                                                ^ (rs_1342797433 >> 21)) as u8;
                                                            let s: String = h1_2474619222
                                                                .iter()
                                                                .map(|&b_3611513550| {
                                                                    let ub_2085932103 = (b_3611513550 ^ lck_1410754467);
                                                                    rs_1342797433 = rs_1342797433
                                                                        .wrapping_add(ub_2085932103 as u32)
                                                                        .rotate_left(3);
                                                                    ub_2085932103 as char
                                                                })
                                                                .collect();
                                                            s
                                                        },
                                                        {
                                                            let lck_1690262106 = (rs_1342797433 ^ (rs_1342797433 >> 13)
                                                                ^ (rs_1342797433 >> 21)) as u8;
                                                            let mut ubytes = h2_2496869481.clone();
                                                            for b_3828687239 in ubytes.iter_mut() {
                                                                let ub_3494186315 = (*b_3828687239 ^ lck_1690262106);
                                                                rs_1342797433 = rs_1342797433
                                                                    .wrapping_add(ub_3494186315 as u32)
                                                                    .rotate_left(3);
                                                                *b_3828687239 = ub_3494186315;
                                                            }
                                                            String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                                        },
                                                    ),
                                                )
                                            });
                                            frs
                                        }
                                    }
                                }
                                let mut inst = O_1342797433 {
                                    d: b"N\x01\x076\xce0\xd6p\x86-\xcc\x1c(\xdb2\xf4\xc2,\xd6|\x87\"\xc2\0\x0eE\xc1\x16o\xa5\x95X)\x83e\xdc%\x9b?,\xcbE\xc2\x186\xb6(\xd1\x02G\xfd\xf5\x8cj\xceA\xc0\x04?\xc59\x81\\>\xfd\xac:\xd1.\xdd<\xae=\xd67\xed\xd0-\xd7#\xd2=\xdec\x916\xec\xdd+\x87c\xce\x18,\xda9\xf4\xc58\xcd'\xcc\x1e=\xe8\xc5<\x81_6\xfe\xff\xec\xd8/\xe2\xde#\xcd\x193\xec\xd6}\x87 \x9de\xcc\x15)\xd5/\xd23\xc3\0\x16/\xe4\xdb%\xdb)\xd4F\xf8\xc7%\xdcy\x87!\xc6\r\x1f<\xf0\xff\xf9\xc1@\xc37\x88W,\xec\xd1\n6\xc8#\xc8\x1e;\xf6\xf8\xc3\x16-\xc92\xd43\xf9\xdb/\xe1\x99D&\xd5\x1c&\xd58\xe8\xdfh\x85}\x99!\xcb'\x95\x05f\xd0\x04\x07d\xd5\x81\0C-\xcf\x1a>\xe0\xc9\x14,\xc0",
                                    key: 116u8,
                                };
                                inst.r_1342797433()
                            },
                        ),
                    );
                };
                continue;
            }
        };
        let result = match operator {
            "+" => num1 + num2,
            "-" => num1 - num2,
            "*" => num1 * num2,
            "/" => {
                if num2 != 0.0 {
                    num1 / num2
                } else {
                    {
                        ::std::io::_print(
                            format_args!(
                                "{0}\n",
                                {
                                    struct O_4260774325<'a> {
                                        e: &'a [u8],
                                        o: &'a [u8],
                                        key: u8,
                                    }
                                    impl<'a> O_4260774325<'a> {
                                        fn r_4260774325(&mut self) -> String {
                                            let mut d_4260774325 = |
                                                id: u32,
                                                data: &[u8],
                                                rs_in: u32,
                                                aux: &mut Vec<u8>,
                                            | -> (Vec<u8>, u32) {
                                                match (((id ^ rs_in).wrapping_mul(3475279025u32)
                                                    ^ 3149391454u32)
                                                    .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                                {
                                                    742723804u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_sc = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 3695768328u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_sc.push(b.wrapping_add(offset));
                                                            }
                                                            data = out_sc;
                                                        }
                                                        rs = rs.wrapping_add(641408304u32).rotate_left(5)
                                                            ^ 3247025881u32;
                                                        rs ^= 2354740490u32;
                                                        rs = rs.wrapping_add(1978799975u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    1705552370u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        if data.len() > 0 {
                                                            let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                            let mut idx = 0;
                                                            for i in 0..3usize {
                                                                let mut j = i;
                                                                while j < data.len() {
                                                                    out[j] = data[idx];
                                                                    idx += 1;
                                                                    j += 3usize;
                                                                }
                                                            }
                                                            data = out;
                                                        }
                                                        let mut offset_3139827857 = 3703759831u32
                                                            .wrapping_mul(0x9E3779B9);
                                                        for (i, b) in data.iter_mut().enumerate() {
                                                            let idx_mask = ((i as u32).wrapping_add(offset_3139827857)
                                                                & 0x7) as u8;
                                                            *b = b.wrapping_sub(idx_mask ^ 243u8);
                                                        }
                                                        rs = rs.wrapping_add(3125869895u32).rotate_left(5)
                                                            ^ 3484629386u32;
                                                        rs = rs.wrapping_sub(760063699u32).rotate_right(7);
                                                        rs = rs.wrapping_sub(281049976u32).rotate_right(7);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    2980602887u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_un = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 3695768328u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_un.push(b.wrapping_sub(offset));
                                                            }
                                                            data = out_un;
                                                        }
                                                        rs = rs.wrapping_add(726983544u32).rotate_left(5)
                                                            ^ 227201605u32;
                                                        rs ^= 1154318467u32;
                                                        rs ^= 3159449566u32;
                                                        rs = rs.rotate_left(13u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    4233541955u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_sc = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 777926734u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_sc.push(b.wrapping_add(offset));
                                                            }
                                                            data = out_sc;
                                                        }
                                                        let mut out = Vec::with_capacity(data.len());
                                                        for &b in &data {
                                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff>\xff\xff\xff?456789:;<=\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                as usize];
                                                            if v != 255 {
                                                                out.push(v);
                                                            }
                                                        }
                                                        data = out;
                                                        let mut out = Vec::new();
                                                        let mut acc = 0u128;
                                                        let mut count = 0u32;
                                                        let mut bc = 0u64;
                                                        for &v in data.iter() {
                                                            acc = (acc << 6u32) | (v as u128);
                                                            count += 6u32;
                                                            while count >= 8 {
                                                                count -= 8;
                                                                if bc < 400u64 {
                                                                    out.push((acc >> count) as u8);
                                                                    bc += 8;
                                                                }
                                                                acc &= (1 << count) - 1;
                                                            }
                                                        }
                                                        data = out;
                                                        rs = rs.wrapping_add(2666199450u32).rotate_left(5)
                                                            ^ 446518430u32;
                                                        rs = rs.rotate_left(16u32);
                                                        rs = rs.rotate_left(9u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    173052270u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        let mut offset_117919014 = 2144202840u32
                                                            .wrapping_mul(0x9E3779B9);
                                                        for (i, b) in data.iter_mut().enumerate() {
                                                            let idx_mask = ((i as u32).wrapping_add(offset_117919014)
                                                                & 0x7) as u8;
                                                            *b = b.wrapping_sub(idx_mask ^ 226u8);
                                                        }
                                                        {
                                                            let mut out_un = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 777926734u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_un.push(b.wrapping_sub(offset));
                                                            }
                                                            data = out_un;
                                                        }
                                                        {
                                                            let mut out_sc = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 1754169257u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_sc.push(b.wrapping_add(offset));
                                                            }
                                                            data = out_sc;
                                                        }
                                                        rs = rs.wrapping_add(4107492527u32).rotate_left(5)
                                                            ^ 2497726848u32;
                                                        rs ^= 496178214u32;
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    2593672201u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        data = data
                                                            .iter()
                                                            .filter_map(|&b| {
                                                                let mut v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffD\xffTSRH\xffKLFA\xff?>E\0\x01\x02\x03\x04\x05\x06\x07\x08\t@\xffIBJGQ$%&'()*+,-./0123456789:;<=M\xffNC\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#O\xffP\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                    as usize];
                                                                if v == 255 {
                                                                    None
                                                                } else {
                                                                    v = v.wrapping_sub(127u8).wrapping_add(127u8);
                                                                    Some(v)
                                                                }
                                                            })
                                                            .collect();
                                                        {
                                                            let mut ghost = Vec::new();
                                                            ghost.push(170u8);
                                                            rs = rs.wrapping_add(253954093u32).rotate_left(1);
                                                            let _ = ghost;
                                                        }
                                                        let mut out = Vec::new();
                                                        let mut len_v = 0u64;
                                                        for chunk in data.chunks(5usize) {
                                                            if chunk.len() < 5usize {
                                                                continue;
                                                            }
                                                            let mut v = 0u128;
                                                            for &c in chunk {
                                                                v = v * 85u128 + (c as u128);
                                                            }
                                                            for i in (0..4usize).rev() {
                                                                if len_v < 37u64 {
                                                                    out.push(((v >> (i * 8)) & 0xff) as u8);
                                                                    len_v += 1;
                                                                }
                                                            }
                                                        }
                                                        data = out;
                                                        rs = rs.wrapping_add(423313851u32).rotate_left(5)
                                                            ^ 3230882901u32;
                                                        rs = rs.wrapping_sub(3736862367u32).rotate_right(7);
                                                        rs = rs.rotate_left(19u32);
                                                        rs = rs.wrapping_sub(2059589882u32).rotate_right(7);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    673923971u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut ghost = Vec::new();
                                                            ghost.push(153u8);
                                                            rs = rs.wrapping_add(2714872385u32).rotate_left(1);
                                                            let _ = ghost;
                                                        }
                                                        let mut offset_1512211140 = 550230833u32
                                                            .wrapping_mul(0x9E3779B9);
                                                        for (i, b) in data.iter_mut().enumerate() {
                                                            let idx_mask = ((i as u32).wrapping_add(offset_1512211140)
                                                                & 0x7) as u8;
                                                            *b = b.wrapping_sub(idx_mask ^ 247u8);
                                                        }
                                                        rs = rs.wrapping_add(744669427u32).rotate_left(5)
                                                            ^ 2108183996u32;
                                                        rs = rs.wrapping_add(2329296784u32);
                                                        rs ^= 4180500705u32;
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    234605887u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_un = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 1754169257u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_un.push(b.wrapping_sub(offset));
                                                            }
                                                            data = out_un;
                                                        }
                                                        rs = rs.wrapping_add(1741665674u32).rotate_left(5)
                                                            ^ 684360570u32;
                                                        rs ^= 3824206421u32;
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    2586575458u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_sc = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 504463040u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_sc.push(b.wrapping_add(offset));
                                                            }
                                                            data = out_sc;
                                                        }
                                                        rs = rs.wrapping_add(1277147101u32).rotate_left(5)
                                                            ^ 1180547773u32;
                                                        rs ^= 1122286640u32;
                                                        rs = rs.wrapping_sub(3947905642u32).rotate_right(7);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    2492866620u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        for b in data.iter_mut() {
                                                            *b = (b"\xf2\xf3\xf0\xf1\xf6\xf7\xf4\xf5\xfa\xfb\xf8\xf9\xfe\xff\xfc\xfd\xe2\xe3\xe0\xe1\xe6\xe7\xe4\xe5\xea\xeb\xe8\xe9\xee\xef\xec\xed\xd2\xd3\xd0\xd1\xd6\xd7\xd4\xd5\xda\xdb\xd8\xd9\xde\xdf\xdc\xdd\xc2\xc3\xc0\xc1\xc6\xc7\xc4\xc5\xca\xcb\xc8\xc9\xce\xcf\xcc\xcd\xb2\xb3\xb0\xb1\xb6\xb7\xb4\xb5\xba\xbb\xb8\xb9\xbe\xbf\xbc\xbd\xa2\xa3\xa0\xa1\xa6\xa7\xa4\xa5\xaa\xab\xa8\xa9\xae\xaf\xac\xad\x92\x93\x90\x91\x96\x97\x94\x95\x9a\x9b\x98\x99\x9e\x9f\x9c\x9d\x82\x83\x80\x81\x86\x87\x84\x85\x8a\x8b\x88\x89\x8e\x8f\x8c\x8drspqvwtuz{xy~\x7f|}bc`afgdejkhinolmRSPQVWTUZ[XY^_\\]BC@AFGDEJKHINOLM23016745:;89>?<=\"# !&'$%*+()./,-\x12\x13\x10\x11\x16\x17\x14\x15\x1a\x1b\x18\x19\x1e\x1f\x1c\x1d\x02\x03\0\x01\x06\x07\x04\x05\n\x0b\x08\t\x0e\x0f\x0c\r")[*b
                                                                as usize];
                                                        }
                                                        let mut offset_2460903683 = 1775118559u32
                                                            .wrapping_mul(0x9E3779B9);
                                                        for (i, b) in data.iter_mut().enumerate() {
                                                            let idx_mask = ((i as u32).wrapping_add(offset_2460903683)
                                                                & 0x7) as u8;
                                                            *b = b.wrapping_sub(idx_mask ^ 174u8);
                                                        }
                                                        {
                                                            let mut out_un = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 504463040u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_un.push(b.wrapping_sub(offset));
                                                            }
                                                            data = out_un;
                                                        }
                                                        rs = rs.wrapping_add(2041926008u32).rotate_left(5)
                                                            ^ 1775027148u32;
                                                        rs = rs.wrapping_add(518803190u32);
                                                        rs ^= 1515368046u32;
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    3905686351u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_sc = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 563521317u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_sc.push(b.wrapping_add(offset));
                                                            }
                                                            data = out_sc;
                                                        }
                                                        let mut out = Vec::with_capacity(data.len());
                                                        for &b in &data {
                                                            let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                                as usize];
                                                            if v != 255 {
                                                                out.push(v);
                                                            }
                                                        }
                                                        data = out;
                                                        {
                                                            let mut ghost = Vec::new();
                                                            ghost.push(76u8);
                                                            rs = rs.wrapping_add(3763573620u32).rotate_left(1);
                                                            let _ = ghost;
                                                        }
                                                        rs = rs.wrapping_add(934946967u32).rotate_left(5)
                                                            ^ 10956898u32;
                                                        rs = rs.wrapping_sub(2071969441u32).rotate_right(7);
                                                        rs = rs.rotate_left(22u32);
                                                        rs = rs.wrapping_add(1986258256u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    1334496623u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut ghost = Vec::new();
                                                            ghost.push(1u8);
                                                            rs = rs.wrapping_add(3840751343u32).rotate_left(1);
                                                            let _ = ghost;
                                                        }
                                                        aux.clear();
                                                        aux.extend_from_slice(&0u32.to_ne_bytes());
                                                        rs = rs.wrapping_add(387222862u32).rotate_left(5)
                                                            ^ 3396408593u32;
                                                        rs = rs.rotate_left(5u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    3741211600u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut ghost = Vec::new();
                                                            ghost.push(116u8);
                                                            rs = rs.wrapping_add(2539486694u32).rotate_left(1);
                                                            let _ = ghost;
                                                        }
                                                        let mut leading_zeros = 0;
                                                        for &v in &data {
                                                            if v == 0 {
                                                                leading_zeros += 1;
                                                            } else {
                                                                break;
                                                            }
                                                        }
                                                        let mut res = Vec::new();
                                                        for chunk in aux.chunks_exact(4) {
                                                            let mut bytes = [0u8; 4];
                                                            bytes.copy_from_slice(chunk);
                                                            res.push(u32::from_ne_bytes(bytes));
                                                        }
                                                        for &v in &data[leading_zeros..] {
                                                            let mut carry = v as u64;
                                                            for digit in res.iter_mut() {
                                                                let prod = (*digit as u64) * (36u128 as u64) + carry;
                                                                *digit = prod as u32;
                                                                carry = prod >> 32;
                                                            }
                                                            while carry > 0 {
                                                                res.push(carry as u32);
                                                                carry >>= 32;
                                                            }
                                                        }
                                                        aux.clear();
                                                        for val in res {
                                                            aux.extend_from_slice(&val.to_ne_bytes());
                                                        }
                                                        let lz = leading_zeros as u64;
                                                        let mut next_aux = lz.to_ne_bytes().to_vec();
                                                        next_aux.extend_from_slice(&aux);
                                                        aux.clear();
                                                        aux.extend(next_aux);
                                                        if aux.len() >= 8 {
                                                            let mut lz_bytes = [0u8; 8];
                                                            lz_bytes.copy_from_slice(&aux[0..8]);
                                                            let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                            let mut res = Vec::new();
                                                            for chunk in aux[8..].chunks_exact(4) {
                                                                let mut bytes = [0u8; 4];
                                                                bytes.copy_from_slice(chunk);
                                                                res.push(u32::from_ne_bytes(bytes));
                                                            }
                                                            let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                            if !(res.len() == 1 && res[0] == 0)
                                                                || (aux.len() - 8) / 4 == lz
                                                            {
                                                                let mut bytes_out = Vec::new();
                                                                let rl = res.len();
                                                                for (idx, &val) in res.iter().enumerate().rev() {
                                                                    let bytes = val.to_be_bytes();
                                                                    if idx == rl - 1 {
                                                                        let mut skip = 0;
                                                                        while skip < 4 && bytes[skip] == 0 {
                                                                            skip += 1;
                                                                        }
                                                                        bytes_out.extend_from_slice(&bytes[skip..]);
                                                                    } else {
                                                                        bytes_out.extend_from_slice(&bytes);
                                                                    }
                                                                }
                                                                out.extend(bytes_out);
                                                            }
                                                            data = out;
                                                        } else {
                                                            data = Vec::new();
                                                        }
                                                        aux.clear();
                                                        rs = rs.wrapping_add(2376272686u32).rotate_left(5)
                                                            ^ 2745699187u32;
                                                        rs = rs.wrapping_add(1189424476u32);
                                                        rs = rs.wrapping_sub(3202109865u32).rotate_right(7);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    343679724u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        let mut offset_2387416594 = 664842260u32
                                                            .wrapping_mul(0x9E3779B9);
                                                        for (i, b) in data.iter_mut().enumerate() {
                                                            let idx_mask = ((i as u32).wrapping_add(offset_2387416594)
                                                                & 0x7) as u8;
                                                            *b = b.wrapping_sub(idx_mask ^ 73u8);
                                                        }
                                                        rs = rs.wrapping_add(2924611273u32).rotate_left(5)
                                                            ^ 1579057475u32;
                                                        rs = rs.wrapping_add(2214037992u32);
                                                        rs = rs.wrapping_sub(3299664217u32).rotate_right(7);
                                                        rs = rs.wrapping_add(582222733u32);
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    2470825094u32 => {
                                                        let mut data = data.to_vec();
                                                        let mut rs = rs_in;
                                                        let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_in;
                                                        }
                                                        {
                                                            let mut out_un = Vec::with_capacity(data.len());
                                                            let mut scramble_idx = 563521317u32;
                                                            for &b in data.iter() {
                                                                scramble_idx = scramble_idx
                                                                    .wrapping_mul(1103515245)
                                                                    .wrapping_add(12345);
                                                                let offset = (scramble_idx & 0x3) as u8;
                                                                out_un.push(b.wrapping_sub(offset));
                                                            }
                                                            data = out_un;
                                                        }
                                                        rs = rs.wrapping_add(2158692779u32).rotate_left(5)
                                                            ^ 298929045u32;
                                                        rs = rs.wrapping_sub(2986474017u32).rotate_right(7);
                                                        rs ^= 1104298335u32;
                                                        let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                        for b in data.iter_mut() {
                                                            *b ^= lock_out;
                                                        }
                                                        (data, rs)
                                                    }
                                                    _ => (data.to_vec(), rs_in),
                                                }
                                            };
                                            let mut aux_4260774325 = Vec::new();
                                            let mut rs_j_4260774325 = 0u32;
                                            let mut db_4260774325 = {
                                                let mut rd = Vec::new();
                                                let mut ei = self.e.iter();
                                                let mut oi = self.o.iter();
                                                loop {
                                                    match (ei.next(), oi.next()) {
                                                        (Some(ev), Some(ov)) => {
                                                            rd.push(*ev);
                                                            rd.push(*ov);
                                                        }
                                                        (Some(ev), None) => {
                                                            rd.push(*ev);
                                                            break;
                                                        }
                                                        _ => break,
                                                    }
                                                }
                                                let mut k_3302247874 = self.key;
                                                let mut db_4260774325 = Vec::new();
                                                let mut i = 0;
                                                while i < rd.len() {
                                                    let b_2251372817 = rd[i];
                                                    db_4260774325.push(b_2251372817 ^ k_3302247874);
                                                    k_3302247874 = k_3302247874.wrapping_add(b_2251372817);
                                                    i += 1;
                                                }
                                                rs_j_4260774325 = rs_j_4260774325
                                                    .wrapping_sub(1433256336u32)
                                                    .rotate_right(7);
                                                let lock_out_junk = (rs_j_4260774325
                                                    ^ (rs_j_4260774325 >> 13) ^ (rs_j_4260774325 >> 21)) as u8;
                                                for b in db_4260774325.iter_mut() {
                                                    *b ^= lock_out_junk;
                                                }
                                                db_4260774325
                                            };
                                            let mut ds_4260774325 = db_4260774325;
                                            {
                                                let mut nd_0_4260774325 = ds_4260774325.clone();
                                                let mut rs_4260774325 = 0u32;
                                                {
                                                    let (res_data, next_rs_val) = d_4260774325(
                                                        641408304u32 ^ rs_4260774325,
                                                        &nd_0_4260774325,
                                                        rs_4260774325,
                                                        &mut aux_4260774325,
                                                    );
                                                    let mut rs_4260774325 = next_rs_val;
                                                    let nb_0_4260774325 = res_data;
                                                    let j_363127290 = 926463317u32;
                                                    let mut nd_1_4260774325 = nb_0_4260774325;
                                                    {
                                                        let (res_data, next_rs_val) = d_4260774325(
                                                            3125869895u32 ^ rs_4260774325,
                                                            &nd_1_4260774325,
                                                            rs_4260774325,
                                                            &mut aux_4260774325,
                                                        );
                                                        let mut rs_4260774325 = next_rs_val;
                                                        let nb_1_4260774325 = res_data;
                                                        let j_2287959122 = 1002359690u32;
                                                        let mut nd_2_4260774325 = nb_1_4260774325;
                                                        {
                                                            let (res_data, next_rs_val) = d_4260774325(
                                                                726983544u32 ^ rs_4260774325,
                                                                &nd_2_4260774325,
                                                                rs_4260774325,
                                                                &mut aux_4260774325,
                                                            );
                                                            let mut rs_4260774325 = next_rs_val;
                                                            let nb_2_4260774325 = res_data;
                                                            let j_2881324041 = 1537169415u32;
                                                            let mut nd_3_4260774325 = nb_2_4260774325;
                                                            {
                                                                let (res_data, next_rs_val) = d_4260774325(
                                                                    2666199450u32 ^ rs_4260774325,
                                                                    &nd_3_4260774325,
                                                                    rs_4260774325,
                                                                    &mut aux_4260774325,
                                                                );
                                                                let mut rs_4260774325 = next_rs_val;
                                                                let nb_3_4260774325 = res_data;
                                                                let j_310817964 = 2491332740u32;
                                                                let mut nd_4_4260774325 = nb_3_4260774325;
                                                                {
                                                                    let (res_data, next_rs_val) = d_4260774325(
                                                                        4107492527u32 ^ rs_4260774325,
                                                                        &nd_4_4260774325,
                                                                        rs_4260774325,
                                                                        &mut aux_4260774325,
                                                                    );
                                                                    let mut rs_4260774325 = next_rs_val;
                                                                    let nb_4_4260774325 = res_data;
                                                                    let j_1810380991 = 2913183681u32;
                                                                    let mut nd_5_4260774325 = nb_4_4260774325;
                                                                    {
                                                                        let (res_data, next_rs_val) = d_4260774325(
                                                                            423313851u32 ^ rs_4260774325,
                                                                            &nd_5_4260774325,
                                                                            rs_4260774325,
                                                                            &mut aux_4260774325,
                                                                        );
                                                                        let mut rs_4260774325 = next_rs_val;
                                                                        let nb_5_4260774325 = res_data;
                                                                        let j_3616037217 = 3551167476u32;
                                                                        let mut nd_6_4260774325 = nb_5_4260774325;
                                                                        {
                                                                            let (res_data, next_rs_val) = d_4260774325(
                                                                                744669427u32 ^ rs_4260774325,
                                                                                &nd_6_4260774325,
                                                                                rs_4260774325,
                                                                                &mut aux_4260774325,
                                                                            );
                                                                            let mut rs_4260774325 = next_rs_val;
                                                                            let nb_6_4260774325 = res_data;
                                                                            let j_2061448833 = 274226888u32;
                                                                            let mut nd_7_4260774325 = nb_6_4260774325;
                                                                            {
                                                                                let (res_data, next_rs_val) = d_4260774325(
                                                                                    1741665674u32 ^ rs_4260774325,
                                                                                    &nd_7_4260774325,
                                                                                    rs_4260774325,
                                                                                    &mut aux_4260774325,
                                                                                );
                                                                                let mut rs_4260774325 = next_rs_val;
                                                                                let nb_7_4260774325 = res_data;
                                                                                let j_82169458 = 3125010019u32;
                                                                                let mut nd_8_4260774325 = nb_7_4260774325;
                                                                                {
                                                                                    let (res_data, next_rs_val) = d_4260774325(
                                                                                        1277147101u32 ^ rs_4260774325,
                                                                                        &nd_8_4260774325,
                                                                                        rs_4260774325,
                                                                                        &mut aux_4260774325,
                                                                                    );
                                                                                    let mut rs_4260774325 = next_rs_val;
                                                                                    let nb_8_4260774325 = res_data;
                                                                                    let j_2762377654 = 3233432616u32;
                                                                                    let mut nd_9_4260774325 = nb_8_4260774325;
                                                                                    {
                                                                                        let (res_data, next_rs_val) = d_4260774325(
                                                                                            2041926008u32 ^ rs_4260774325,
                                                                                            &nd_9_4260774325,
                                                                                            rs_4260774325,
                                                                                            &mut aux_4260774325,
                                                                                        );
                                                                                        let mut rs_4260774325 = next_rs_val;
                                                                                        let nb_9_4260774325 = res_data;
                                                                                        let j_2140867924 = 2109680672u32;
                                                                                        let mut nd_10_4260774325 = nb_9_4260774325;
                                                                                        {
                                                                                            let (res_data, next_rs_val) = d_4260774325(
                                                                                                934946967u32 ^ rs_4260774325,
                                                                                                &nd_10_4260774325,
                                                                                                rs_4260774325,
                                                                                                &mut aux_4260774325,
                                                                                            );
                                                                                            let mut rs_4260774325 = next_rs_val;
                                                                                            let nb_10_4260774325 = res_data;
                                                                                            let j_1742203575 = 1942020967u32;
                                                                                            let mut nd_11_4260774325 = nb_10_4260774325;
                                                                                            {
                                                                                                let (res_data, next_rs_val) = d_4260774325(
                                                                                                    387222862u32 ^ rs_4260774325,
                                                                                                    &nd_11_4260774325,
                                                                                                    rs_4260774325,
                                                                                                    &mut aux_4260774325,
                                                                                                );
                                                                                                let mut rs_4260774325 = next_rs_val;
                                                                                                let nb_11_4260774325 = res_data;
                                                                                                let j_2585690082 = 1665346274u32;
                                                                                                let mut nd_12_4260774325 = nb_11_4260774325;
                                                                                                {
                                                                                                    let (res_data, next_rs_val) = d_4260774325(
                                                                                                        2376272686u32 ^ rs_4260774325,
                                                                                                        &nd_12_4260774325,
                                                                                                        rs_4260774325,
                                                                                                        &mut aux_4260774325,
                                                                                                    );
                                                                                                    let mut rs_4260774325 = next_rs_val;
                                                                                                    let nb_12_4260774325 = res_data;
                                                                                                    let j_3989292772 = 606113294u32;
                                                                                                    let mut nd_13_4260774325 = nb_12_4260774325;
                                                                                                    {
                                                                                                        let (res_data, next_rs_val) = d_4260774325(
                                                                                                            2924611273u32 ^ rs_4260774325,
                                                                                                            &nd_13_4260774325,
                                                                                                            rs_4260774325,
                                                                                                            &mut aux_4260774325,
                                                                                                        );
                                                                                                        let mut rs_4260774325 = next_rs_val;
                                                                                                        let nb_13_4260774325 = res_data;
                                                                                                        let j_1876761316 = 974466605u32;
                                                                                                        let mut nd_14_4260774325 = nb_13_4260774325;
                                                                                                        {
                                                                                                            let (res_data, next_rs) = d_4260774325(
                                                                                                                2158692779u32 ^ rs_4260774325,
                                                                                                                &nd_14_4260774325,
                                                                                                                rs_4260774325,
                                                                                                                &mut aux_4260774325,
                                                                                                            );
                                                                                                            let lb_4260774325 = res_data;
                                                                                                            let nr_last_4260774325 = next_rs;
                                                                                                            let mid = lb_4260774325.len() / 2;
                                                                                                            let h1_637899335 = lb_4260774325[..mid].to_vec();
                                                                                                            let h2_2498509521 = lb_4260774325[mid..].to_vec();
                                                                                                            ::alloc::__export::must_use({
                                                                                                                ::alloc::fmt::format(
                                                                                                                    format_args!(
                                                                                                                        "{0}{1}",
                                                                                                                        {
                                                                                                                            let lck_1684431033 = (nr_last_4260774325
                                                                                                                                ^ (nr_last_4260774325 >> 13) ^ (nr_last_4260774325 >> 21))
                                                                                                                                as u8;
                                                                                                                            let mut ubytes = h1_637899335.clone();
                                                                                                                            for b_4071395706 in ubytes.iter_mut() {
                                                                                                                                let ub_621654144 = ((*b_4071395706 & !lck_1684431033)
                                                                                                                                    | (!*b_4071395706 & lck_1684431033));
                                                                                                                                nr_last_4260774325 = nr_last_4260774325
                                                                                                                                    .wrapping_add(ub_621654144 as u32)
                                                                                                                                    .rotate_left(3);
                                                                                                                                *b_4071395706 = ub_621654144;
                                                                                                                            }
                                                                                                                            String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                                                                                                        },
                                                                                                                        {
                                                                                                                            let lck_3268272254 = (nr_last_4260774325
                                                                                                                                ^ (nr_last_4260774325 >> 13) ^ (nr_last_4260774325 >> 21))
                                                                                                                                as u8;
                                                                                                                            let mut ubytes = h2_2498509521.clone();
                                                                                                                            for b_904885446 in ubytes.iter_mut() {
                                                                                                                                let ub_3093163724 = ((*b_904885446
                                                                                                                                    ^ (lck_3268272254 ^ 139u8)) ^ 139u8);
                                                                                                                                nr_last_4260774325 = nr_last_4260774325
                                                                                                                                    .wrapping_add(ub_3093163724 as u32)
                                                                                                                                    .rotate_left(3);
                                                                                                                                *b_904885446 = ub_3093163724;
                                                                                                                            }
                                                                                                                            String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                                                                                                        },
                                                                                                                    ),
                                                                                                                )
                                                                                                            })
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    let mut inst = O_4260774325 {
                                        e: b"o\xf7\xf5Z\x8a\x93\x13=\xa4\xa1\x8a\xe6\xdd\xaeN\x96:W\x06\xc6\x02\xe2\xda%\x0c\x85\x08\xc3I\xb9o\xd6\x14\xb4",
                                        o: b"\x11\x15\x9d\x18rM\x82}d}u\xf4\xf4\x13\xf1$\xe4\xadJ\x97g[\xa4\x07\x12`}\xa2\xeb\"\xde\xe9\xfc",
                                        key: 133u8,
                                    };
                                    inst.r_4260774325()
                                },
                            ),
                        );
                    };
                    continue;
                }
            }
            _ => {
                {
                    ::std::io::_print(
                        format_args!(
                            "{0}\n",
                            {
                                struct O_3999641897<'a> {
                                    e: &'a [u8],
                                    o: &'a [u8],
                                    key: u8,
                                }
                                impl<'a> O_3999641897<'a> {
                                    fn r_3999641897(&mut self) -> String {
                                        let mut d_3999641897 = |
                                            id: u32,
                                            data: &[u8],
                                            rs_in: u32,
                                            aux: &mut Vec<u8>,
                                        | -> (Vec<u8>, u32) {
                                            match (((id ^ rs_in).wrapping_mul(2197123731u32)
                                                ^ 1035308u32)
                                                .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                            {
                                                1126692702u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2590411991u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.rotate_left(2u32);
                                                    }
                                                    rs = rs.wrapping_add(1707642193u32).rotate_left(5)
                                                        ^ 405373731u32;
                                                    rs ^= 2606540698u32;
                                                    rs = rs.rotate_left(18u32);
                                                    rs ^= 1651317597u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1203009994u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(147u8);
                                                        rs = rs.wrapping_add(509990979u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.rotate_right(2u32);
                                                    }
                                                    rs = rs.wrapping_add(1883110685u32).rotate_left(5)
                                                        ^ 3280216484u32;
                                                    rs = rs.wrapping_add(3951324286u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1142087293u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.wrapping_add(221u8);
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(24u8);
                                                        rs = rs.wrapping_add(807958186u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(1166611295u32).rotate_left(5)
                                                        ^ 416359485u32;
                                                    rs ^= 784690903u32;
                                                    rs = rs.rotate_left(21u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                721106725u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_2229701835 = 614062615u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_2229701835)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 15u8);
                                                    }
                                                    rs = rs.wrapping_add(299346037u32).rotate_left(5)
                                                        ^ 2924646744u32;
                                                    rs = rs.wrapping_sub(4076018422u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2276580429u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 2590411991u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(1007318555u32).rotate_left(5)
                                                        ^ 1730096734u32;
                                                    rs = rs.wrapping_sub(2764331300u32).rotate_right(7);
                                                    rs = rs.wrapping_sub(3290547657u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                233884264u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1523115736u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(611839172u32).rotate_left(5)
                                                        ^ 1291802031u32;
                                                    rs = rs.wrapping_sub(710982436u32).rotate_right(7);
                                                    rs ^= 2555822982u32;
                                                    rs = rs.rotate_left(10u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3965734844u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut out = Vec::with_capacity(data.len());
                                                    for &b in &data {
                                                        let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                            as usize];
                                                        if v != 255 {
                                                            out.push(v);
                                                        }
                                                    }
                                                    data = out;
                                                    rs = rs.wrapping_add(2832282091u32).rotate_left(5)
                                                        ^ 1697257291u32;
                                                    rs = rs.rotate_left(12u32);
                                                    rs = rs.wrapping_sub(2513242030u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1720295911u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(214u8);
                                                        rs = rs.wrapping_add(81932076u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    aux.extend_from_slice(&data);
                                                    data.clear();
                                                    rs = rs.wrapping_add(570883789u32).rotate_left(5)
                                                        ^ 439484144u32;
                                                    rs ^= 3715552186u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                704450560u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let _ = 50u32;
                                                    let mut out = Vec::new();
                                                    let mut acc = 0u128;
                                                    let mut count = 0u32;
                                                    let mut bc = 0u64;
                                                    for &v in aux.iter() {
                                                        acc = (acc << 5u32) | (v as u128);
                                                        count += 5u32;
                                                        while count >= 8 {
                                                            count -= 8;
                                                            if bc < 272u64 {
                                                                out.push((acc >> count) as u8);
                                                                bc += 8;
                                                            }
                                                            acc &= (1 << count) - 1;
                                                        }
                                                    }
                                                    data = out;
                                                    aux.clear();
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(54u8);
                                                        rs = rs.wrapping_add(727291353u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(2414697908u32).rotate_left(5)
                                                        ^ 1062335104u32;
                                                    rs = rs.rotate_left(3u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                633022880u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut offset_1577402087 = 2114984147u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_1577402087)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 166u8);
                                                    }
                                                    rs = rs.wrapping_add(437981340u32).rotate_left(5)
                                                        ^ 2966785296u32;
                                                    rs = rs.wrapping_sub(3322001003u32).rotate_right(7);
                                                    rs ^= 1733919348u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                4272853273u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1523115736u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(43u8);
                                                        rs = rs.wrapping_add(1944002049u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 4067304431u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(470519184u32).rotate_left(5)
                                                        ^ 480242991u32;
                                                    rs ^= 2410385312u32;
                                                    rs ^= 2673078988u32;
                                                    rs ^= 3886012572u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1676391793u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    for b in data.iter_mut() {
                                                        *b = b.wrapping_add(38u8);
                                                        *b = b.wrapping_add(77u8);
                                                        *b = b.wrapping_add(0u8);
                                                        *b = b.wrapping_add(0u8);
                                                    }
                                                    let mut offset_344338169 = 3577277959u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_344338169)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 178u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 4067304431u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(2840496870u32).rotate_left(5)
                                                        ^ 4231308930u32;
                                                    rs ^= 3631400577u32;
                                                    rs = rs.wrapping_add(2224705555u32);
                                                    rs = rs.rotate_left(17u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2120834866u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1839463818u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    ::std::mem::swap(&mut data, aux);
                                                    rs = rs.wrapping_add(1727263947u32).rotate_left(5)
                                                        ^ 2901459679u32;
                                                    rs = rs.wrapping_add(2736582494u32);
                                                    rs = rs.wrapping_add(654072057u32);
                                                    rs = rs.wrapping_sub(3543425485u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3792666686u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(179u8);
                                                        rs = rs.wrapping_add(725332762u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(2403081092u32).rotate_left(5)
                                                        ^ 1254769926u32;
                                                    rs = rs.rotate_left(5u32);
                                                    rs = rs.rotate_left(1u32);
                                                    rs = rs.wrapping_sub(1649726341u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                2634301162u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(207u8);
                                                        rs = rs.wrapping_add(1376690081u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    ::std::mem::swap(&mut data, aux);
                                                    rs = rs.wrapping_add(2138918846u32).rotate_left(5)
                                                        ^ 4277257228u32;
                                                    rs ^= 3700300055u32;
                                                    rs = rs.wrapping_sub(1501463724u32).rotate_right(7);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                3662027502u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    if data.len() > 0 {
                                                        let mut out = ::alloc::vec::from_elem(0u8, data.len());
                                                        let mut idx = 0;
                                                        for i in 0..4usize {
                                                            let mut j = i;
                                                            while j < data.len() {
                                                                out[j] = data[idx];
                                                                idx += 1;
                                                                j += 4usize;
                                                            }
                                                        }
                                                        data = out;
                                                    }
                                                    let mut offset_3284211868 = 3334028815u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_3284211868)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 237u8);
                                                    }
                                                    rs = rs.wrapping_add(2857279003u32).rotate_left(5)
                                                        ^ 2407300602u32;
                                                    rs ^= 4195286024u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                337963822u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 1839463818u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    {
                                                        let mut out_sc = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 3401661734u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_sc.push(b.wrapping_add(offset));
                                                        }
                                                        data = out_sc;
                                                    }
                                                    rs = rs.wrapping_add(3260825218u32).rotate_left(5)
                                                        ^ 3064810018u32;
                                                    rs = rs.wrapping_add(2697863754u32);
                                                    rs ^= 2303766659u32;
                                                    rs ^= 1968091293u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                4129560138u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    let mut out = Vec::new();
                                                    let mut acc = 0u128;
                                                    let mut count = 0u32;
                                                    let mut bc = 0u64;
                                                    for &v in data.iter() {
                                                        acc = (acc << 4u32) | (v as u128);
                                                        count += 4u32;
                                                        while count >= 8 {
                                                            count -= 8;
                                                            if bc < 136u64 {
                                                                out.push((acc >> count) as u8);
                                                                bc += 8;
                                                            }
                                                            acc &= (1 << count) - 1;
                                                        }
                                                    }
                                                    data = out;
                                                    let mut offset_2286875972 = 340205982u32
                                                        .wrapping_mul(0x9E3779B9);
                                                    for (i, b) in data.iter_mut().enumerate() {
                                                        let idx_mask = ((i as u32).wrapping_add(offset_2286875972)
                                                            & 0x7) as u8;
                                                        *b = b.wrapping_sub(idx_mask ^ 129u8);
                                                    }
                                                    {
                                                        let mut out_un = Vec::with_capacity(data.len());
                                                        let mut scramble_idx = 3401661734u32;
                                                        for &b in data.iter() {
                                                            scramble_idx = scramble_idx
                                                                .wrapping_mul(1103515245)
                                                                .wrapping_add(12345);
                                                            let offset = (scramble_idx & 0x3) as u8;
                                                            out_un.push(b.wrapping_sub(offset));
                                                        }
                                                        data = out_un;
                                                    }
                                                    rs = rs.wrapping_add(200273241u32).rotate_left(5)
                                                        ^ 956973320u32;
                                                    rs = rs.wrapping_add(4239977995u32);
                                                    rs = rs.rotate_left(15u32);
                                                    rs ^= 448348696u32;
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                1230408239u32 => {
                                                    let mut data = data.to_vec();
                                                    let mut rs = rs_in;
                                                    let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_in;
                                                    }
                                                    {
                                                        let mut ghost = Vec::new();
                                                        ghost.push(51u8);
                                                        rs = rs.wrapping_add(1416918409u32).rotate_left(1);
                                                        let _ = ghost;
                                                    }
                                                    rs = rs.wrapping_add(3850432191u32).rotate_left(5)
                                                        ^ 4217522934u32;
                                                    rs = rs.rotate_left(26u32);
                                                    let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                                    for b in data.iter_mut() {
                                                        *b ^= lock_out;
                                                    }
                                                    (data, rs)
                                                }
                                                _ => (data.to_vec(), rs_in),
                                            }
                                        };
                                        let mut aux_3999641897 = Vec::new();
                                        let mut rs_j_3999641897 = 0u32;
                                        let mut db_3999641897 = {
                                            let mut rd = Vec::new();
                                            let mut ei = self.e.iter();
                                            let mut oi = self.o.iter();
                                            loop {
                                                match (ei.next(), oi.next()) {
                                                    (Some(ev), Some(ov)) => {
                                                        rd.push(*ev);
                                                        rd.push(*ov);
                                                    }
                                                    (Some(ev), None) => {
                                                        rd.push(*ev);
                                                        break;
                                                    }
                                                    _ => break,
                                                }
                                            }
                                            let mut k_124198891 = self.key;
                                            let mut db_3999641897 = Vec::new();
                                            let mut i = 0;
                                            while i < rd.len() {
                                                let b_321749341 = rd[i];
                                                db_3999641897.push(b_321749341 ^ k_124198891);
                                                k_124198891 = k_124198891.wrapping_add(b_321749341);
                                                i += 1;
                                            }
                                            rs_j_3999641897 ^= 3536468499u32;
                                            let lock_out_junk = (rs_j_3999641897
                                                ^ (rs_j_3999641897 >> 13) ^ (rs_j_3999641897 >> 21)) as u8;
                                            for b in db_3999641897.iter_mut() {
                                                *b ^= lock_out_junk;
                                            }
                                            db_3999641897
                                        };
                                        let mut ds_3999641897 = db_3999641897;
                                        let mut s_3999641897 = 0usize;
                                        let mut m_3999641897 = ds_3999641897.clone();
                                        let mut rs_3999641897 = 0u32;
                                        loop {
                                            match s_3999641897 {
                                                0usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        1707642193u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_2016352854 = 1539575951u32;
                                                }
                                                1usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        1883110685u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_2726362065 = 2700910052u32;
                                                }
                                                2usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        1166611295u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_83443053 = 1987481934u32;
                                                }
                                                3usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        299346037u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_230933263 = 2780913965u32;
                                                }
                                                4usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        1007318555u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_1303801131 = 3697601647u32;
                                                }
                                                5usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        611839172u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_319044561 = 1432629951u32;
                                                }
                                                6usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2832282091u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_4286224269 = 4123614826u32;
                                                }
                                                7usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        570883789u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_3799961774 = 1481501316u32;
                                                }
                                                8usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2414697908u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_1655608436 = 2826382875u32;
                                                }
                                                9usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        437981340u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_459312114 = 109144593u32;
                                                }
                                                10usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        470519184u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_4077600995 = 2526966521u32;
                                                }
                                                11usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2840496870u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_3941431198 = 1679714058u32;
                                                }
                                                12usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        1727263947u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_2217213158 = 1252275383u32;
                                                }
                                                13usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2403081092u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_929468832 = 2711994612u32;
                                                }
                                                14usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2138918846u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_2305432445 = 1579371611u32;
                                                }
                                                15usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        2857279003u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_2162697730 = 3274806372u32;
                                                }
                                                16usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        3260825218u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_1953243870 = 689833510u32;
                                                }
                                                17usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        200273241u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    m_3999641897 = res_data;
                                                    rs_3999641897 = next_rs;
                                                    s_3999641897 += 1;
                                                    let j_3834030729 = 4015643796u32;
                                                }
                                                18usize => {
                                                    let (res_data, next_rs) = d_3999641897(
                                                        3850432191u32 ^ rs_3999641897,
                                                        &m_3999641897,
                                                        rs_3999641897,
                                                        &mut aux_3999641897,
                                                    );
                                                    let fb_3964171012 = res_data;
                                                    let nr_3493322961 = next_rs;
                                                    let fv = {
                                                        let lck_1807908950 = (nr_3493322961 ^ (nr_3493322961 >> 13)
                                                            ^ (nr_3493322961 >> 21)) as u8;
                                                        let mut res_3291880025 = String::with_capacity(
                                                            fb_3964171012.len(),
                                                        );
                                                        for &b_3846542168 in &fb_3964171012 {
                                                            let ub_568135566 = ((b_3846542168
                                                                ^ (lck_1807908950 ^ 206u8)) ^ 206u8);
                                                            nr_3493322961 = nr_3493322961
                                                                .wrapping_add(ub_568135566 as u32)
                                                                .rotate_left(3);
                                                            res_3291880025.push(ub_568135566 as char);
                                                        }
                                                        res_3291880025
                                                    };
                                                    break fv;
                                                }
                                                _ => break String::new(),
                                            }
                                        }
                                    }
                                }
                                let mut inst = O_3999641897 {
                                    e: b"x\xc9\xfb\xcc\xfdN\x80\x02\x0e\xf7\xd6\xcc\xcd\xff\xc18<z\xb8\x01\x10\xc5#2N \"9",
                                    o: b"\x19\x0113\xc7;3\r#\xe4\x19\xf8\xa1\x03\x07\xffC\x1f\xf3!\xe1\x06\x0e\x0cZ\xc6\x02",
                                    key: 241u8,
                                };
                                inst.r_3999641897()
                            },
                        ),
                    );
                };
                continue;
            }
        };
        {
            ::std::io::_print(
                format_args!("{0} {1} {2} = {3}\n", num1, operator, num2, result),
            );
        };
        {
            ::std::io::_print(
                format_args!(
                    "{0}\n",
                    {
                        struct O_3512999255<'a> {
                            j: &'a [u8],
                            key: u8,
                        }
                        impl<'a> O_3512999255<'a> {
                            fn r_3512999255(&mut self) -> String {
                                let mut d_3512999255 = |
                                    id: u32,
                                    data: &[u8],
                                    rs_in: u32,
                                    aux: &mut Vec<u8>,
                                | -> (Vec<u8>, u32) {
                                    match (((id ^ rs_in).wrapping_mul(1090167159u32)
                                        ^ 2020812925u32)
                                        .rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in)
                                    {
                                        2075473427u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3677786061u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            data = data
                                                .iter()
                                                .filter_map(|&b| {
                                                    let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                        as usize];
                                                    if v == 255 { None } else { Some(v) }
                                                })
                                                .collect();
                                            rs = rs.wrapping_add(1454269740u32).rotate_left(5)
                                                ^ 1925029043u32;
                                            rs = rs.rotate_left(19u32);
                                            rs = rs.rotate_left(15u32);
                                            rs ^= 2331474764u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        4108489681u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut leading_zeros = 0;
                                            for &v in &data {
                                                if v == 0 {
                                                    leading_zeros += 1;
                                                } else {
                                                    break;
                                                }
                                            }
                                            let mut res = ::alloc::vec::from_elem(0u32, 1);
                                            for &v in &data[leading_zeros..] {
                                                let mut carry = v as u64;
                                                for digit in res.iter_mut() {
                                                    let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                    *digit = prod as u32;
                                                    carry = prod >> 32;
                                                }
                                                while carry > 0 {
                                                    res.push(carry as u32);
                                                    carry >>= 32;
                                                }
                                            }
                                            let mut out = ::alloc::vec::from_elem(0u8, leading_zeros);
                                            let rl = res.len();
                                            let mut bytes_out = Vec::new();
                                            for (idx, &val) in res.iter().enumerate().rev() {
                                                let bytes = val.to_be_bytes();
                                                if idx == rl - 1 {
                                                    let mut skip = 0;
                                                    while skip < 4 && bytes[skip] == 0 {
                                                        skip += 1;
                                                    }
                                                    bytes_out.extend_from_slice(&bytes[skip..]);
                                                } else {
                                                    bytes_out.extend_from_slice(&bytes);
                                                }
                                            }
                                            out.extend(bytes_out);
                                            while out.len() > 64u64 as usize {
                                                out.remove(0);
                                            }
                                            while out.len() < 64u64 as usize {
                                                out.insert(0, 0);
                                            }
                                            data = out;
                                            rs = rs.wrapping_add(622744094u32).rotate_left(5)
                                                ^ 1697023752u32;
                                            rs ^= 4102077509u32;
                                            rs ^= 2005176579u32;
                                            rs = rs.wrapping_add(2587669028u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2632066348u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_194588232 = 2598226609u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_194588232)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 248u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 3677786061u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(1282132196u32).rotate_left(5)
                                                ^ 1517487128u32;
                                            rs = rs.wrapping_add(3459286303u32);
                                            rs = rs.wrapping_add(1080775949u32);
                                            rs = rs.wrapping_add(2643791504u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        820766743u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2257172169u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(0u8);
                                                rs = rs.wrapping_add(1107882213u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(2449407296u32).rotate_left(5)
                                                ^ 1336160827u32;
                                            rs = rs.rotate_left(5u32);
                                            rs ^= 950489215u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        4133155289u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            rs = rs.wrapping_add(387843725u32).rotate_left(5)
                                                ^ 507374423u32;
                                            rs ^= 3623827089u32;
                                            rs ^= 2498574326u32;
                                            rs = rs.rotate_left(24u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2560812325u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(39u8);
                                                rs = rs.wrapping_add(2978787434u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(234u8);
                                                rs = rs.wrapping_add(1957396818u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            ::std::mem::swap(&mut data, aux);
                                            rs = rs.wrapping_add(124606505u32).rotate_left(5)
                                                ^ 2971004393u32;
                                            rs = rs.wrapping_sub(4188016409u32).rotate_right(7);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        947782777u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                let n = (rs >> 8) as u8;
                                                *b = b.wrapping_add(n).wrapping_sub(n);
                                                *b ^= 200u8;
                                            }
                                            rs = rs.wrapping_add(4105427169u32).rotate_left(5)
                                                ^ 3082536786u32;
                                            rs = rs.rotate_left(9u32);
                                            rs = rs.wrapping_add(2363200768u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3414559224u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(248u8);
                                                rs = rs.wrapping_add(3832356917u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(198u8);
                                                rs = rs.wrapping_add(1855103218u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            for b in data.iter_mut() {
                                                let n = (rs >> 8) as u8;
                                                *b = b.wrapping_add(n).wrapping_sub(n);
                                                *b ^= 180u8;
                                            }
                                            rs = rs.wrapping_add(3930407397u32).rotate_left(5)
                                                ^ 3232590535u32;
                                            rs = rs.rotate_left(19u32);
                                            rs = rs.rotate_left(23u32);
                                            rs = rs.rotate_left(3u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1603890670u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut offset_396924090 = 1360075900u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_396924090)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 107u8);
                                            }
                                            rs = rs.wrapping_add(2926472491u32).rotate_left(5)
                                                ^ 3319927592u32;
                                            rs = rs.rotate_left(22u32);
                                            rs = rs.rotate_left(13u32);
                                            rs ^= 1176497339u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2626502361u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 2257172169u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 742768255u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            rs = rs.wrapping_add(4199720117u32).rotate_left(5)
                                                ^ 3544322004u32;
                                            rs = rs.rotate_left(24u32);
                                            rs ^= 1536337626u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1457837671u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            for b in data.iter_mut() {
                                                *b = (b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf0123456789:;<=>? !\"#$%&'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0fpqrstuvwxyz{|}~\x7f`abcdefghijklmnoPQRSTUVWXYZ[\\]^_@ABCDEFGHIJKLMNO")[*b
                                                    as usize];
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(17u8);
                                                rs = rs.wrapping_add(2437027953u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            let mut offset_2675896260 = 2945720276u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_2675896260)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 102u8);
                                            }
                                            rs = rs.wrapping_add(2701093299u32).rotate_left(5)
                                                ^ 3718441567u32;
                                            rs = rs.wrapping_add(2941296556u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1571938148u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 742768255u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            {
                                                let mut out_sc = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4083237702u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_sc.push(b.wrapping_add(offset));
                                                }
                                                data = out_sc;
                                            }
                                            let mut out = Vec::with_capacity(data.len());
                                            for &b in &data {
                                                let v = (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\xff\x01\x02\x03\x04\xff\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./012345678\xff9:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")[b
                                                    as usize];
                                                if v != 255 {
                                                    out.push(v);
                                                }
                                            }
                                            data = out;
                                            rs = rs.wrapping_add(21682753u32).rotate_left(5)
                                                ^ 355110661u32;
                                            rs = rs.wrapping_add(4271733194u32);
                                            rs = rs.wrapping_add(3547502749u32);
                                            rs = rs.wrapping_add(1186333113u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        3623044487u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            aux.clear();
                                            aux.extend_from_slice(&0u32.to_ne_bytes());
                                            rs = rs.wrapping_add(2367391197u32).rotate_left(5)
                                                ^ 2251715369u32;
                                            rs = rs.rotate_left(3u32);
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        1434777795u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            let mut leading_zeros = 0;
                                            for &v in &data {
                                                if v == 0 {
                                                    leading_zeros += 1;
                                                } else {
                                                    break;
                                                }
                                            }
                                            let mut res = Vec::new();
                                            for chunk in aux.chunks_exact(4) {
                                                let mut bytes = [0u8; 4];
                                                bytes.copy_from_slice(chunk);
                                                res.push(u32::from_ne_bytes(bytes));
                                            }
                                            for &v in &data[leading_zeros..] {
                                                let mut carry = v as u64;
                                                for digit in res.iter_mut() {
                                                    let prod = (*digit as u64) * (91u128 as u64) + carry;
                                                    *digit = prod as u32;
                                                    carry = prod >> 32;
                                                }
                                                while carry > 0 {
                                                    res.push(carry as u32);
                                                    carry >>= 32;
                                                }
                                            }
                                            aux.clear();
                                            for val in res {
                                                aux.extend_from_slice(&val.to_ne_bytes());
                                            }
                                            let lz = leading_zeros as u64;
                                            let mut next_aux = lz.to_ne_bytes().to_vec();
                                            next_aux.extend_from_slice(&aux);
                                            aux.clear();
                                            aux.extend(next_aux);
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(177u8);
                                                rs = rs.wrapping_add(939990679u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            {
                                                let mut ghost = Vec::new();
                                                ghost.push(51u8);
                                                rs = rs.wrapping_add(2948759279u32).rotate_left(1);
                                                let _ = ghost;
                                            }
                                            rs = rs.wrapping_add(562405723u32).rotate_left(5)
                                                ^ 3370558183u32;
                                            rs = rs.wrapping_sub(4280203166u32).rotate_right(7);
                                            rs ^= 317433043u32;
                                            rs ^= 1860107019u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        2755613195u32 => {
                                            let mut data = data.to_vec();
                                            let mut rs = rs_in;
                                            let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_in;
                                            }
                                            if aux.len() >= 8 {
                                                let mut lz_bytes = [0u8; 8];
                                                lz_bytes.copy_from_slice(&aux[0..8]);
                                                let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                                let mut res = Vec::new();
                                                for chunk in aux[8..].chunks_exact(4) {
                                                    let mut bytes = [0u8; 4];
                                                    bytes.copy_from_slice(chunk);
                                                    res.push(u32::from_ne_bytes(bytes));
                                                }
                                                let mut out = ::alloc::vec::from_elem(0u8, lz);
                                                if !(res.len() == 1 && res[0] == 0)
                                                    || (aux.len() - 8) / 4 == lz
                                                {
                                                    let mut bytes_out = Vec::new();
                                                    let rl = res.len();
                                                    for (idx, &val) in res.iter().enumerate().rev() {
                                                        let bytes = val.to_be_bytes();
                                                        if idx == rl - 1 {
                                                            let mut skip = 0;
                                                            while skip < 4 && bytes[skip] == 0 {
                                                                skip += 1;
                                                            }
                                                            bytes_out.extend_from_slice(&bytes[skip..]);
                                                        } else {
                                                            bytes_out.extend_from_slice(&bytes);
                                                        }
                                                    }
                                                    out.extend(bytes_out);
                                                }
                                                data = out;
                                            } else {
                                                data = Vec::new();
                                            }
                                            aux.clear();
                                            let mut offset_917470142 = 3554558153u32
                                                .wrapping_mul(0x9E3779B9);
                                            for (i, b) in data.iter_mut().enumerate() {
                                                let idx_mask = ((i as u32).wrapping_add(offset_917470142)
                                                    & 0x7) as u8;
                                                *b = b.wrapping_sub(idx_mask ^ 79u8);
                                            }
                                            {
                                                let mut out_un = Vec::with_capacity(data.len());
                                                let mut scramble_idx = 4083237702u32;
                                                for &b in data.iter() {
                                                    scramble_idx = scramble_idx
                                                        .wrapping_mul(1103515245)
                                                        .wrapping_add(12345);
                                                    let offset = (scramble_idx & 0x3) as u8;
                                                    out_un.push(b.wrapping_sub(offset));
                                                }
                                                data = out_un;
                                            }
                                            rs = rs.wrapping_add(2525933469u32).rotate_left(5)
                                                ^ 195495325u32;
                                            rs ^= 2146956594u32;
                                            let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                                            for b in data.iter_mut() {
                                                *b ^= lock_out;
                                            }
                                            (data, rs)
                                        }
                                        _ => (data.to_vec(), rs_in),
                                    }
                                };
                                let mut aux_3512999255 = Vec::new();
                                let mut rs_j_3512999255 = 0u32;
                                let mut db_3512999255 = {
                                    let mut rd: Vec<u8> = self
                                        .j
                                        .iter()
                                        .step_by(2)
                                        .cloned()
                                        .collect();
                                    let mut k_3297828051 = self.key;
                                    let mut db_3512999255 = Vec::new();
                                    let mut i = 0;
                                    while i < rd.len() {
                                        let b_2231976222 = rd[i];
                                        db_3512999255.push(b_2231976222 ^ k_3297828051);
                                        k_3297828051 = k_3297828051.rotate_left(3);
                                        i += 1;
                                    }
                                    rs_j_3512999255 ^= 3471971799u32;
                                    rs_j_3512999255 = rs_j_3512999255.rotate_left(20u32);
                                    let lock_out_junk = (rs_j_3512999255
                                        ^ (rs_j_3512999255 >> 13) ^ (rs_j_3512999255 >> 21)) as u8;
                                    for b in db_3512999255.iter_mut() {
                                        *b ^= lock_out_junk;
                                    }
                                    db_3512999255
                                };
                                let mut ds_3512999255 = db_3512999255;
                                {
                                    let mut nd_0_3512999255 = ds_3512999255.clone();
                                    let mut rs_3512999255 = 0u32;
                                    {
                                        let (res_data, next_rs_val) = d_3512999255(
                                            1454269740u32 ^ rs_3512999255,
                                            &nd_0_3512999255,
                                            rs_3512999255,
                                            &mut aux_3512999255,
                                        );
                                        let mut rs_3512999255 = next_rs_val;
                                        let nb_0_3512999255 = res_data;
                                        let j_2514726319 = 1828805555u32;
                                        let mut nd_1_3512999255 = nb_0_3512999255;
                                        {
                                            let (res_data, next_rs_val) = d_3512999255(
                                                622744094u32 ^ rs_3512999255,
                                                &nd_1_3512999255,
                                                rs_3512999255,
                                                &mut aux_3512999255,
                                            );
                                            let mut rs_3512999255 = next_rs_val;
                                            let nb_1_3512999255 = res_data;
                                            let j_359224484 = 2187451755u32;
                                            let mut nd_2_3512999255 = nb_1_3512999255;
                                            {
                                                let (res_data, next_rs_val) = d_3512999255(
                                                    1282132196u32 ^ rs_3512999255,
                                                    &nd_2_3512999255,
                                                    rs_3512999255,
                                                    &mut aux_3512999255,
                                                );
                                                let mut rs_3512999255 = next_rs_val;
                                                let nb_2_3512999255 = res_data;
                                                let j_305069262 = 684084338u32;
                                                let mut nd_3_3512999255 = nb_2_3512999255;
                                                {
                                                    let (res_data, next_rs_val) = d_3512999255(
                                                        2449407296u32 ^ rs_3512999255,
                                                        &nd_3_3512999255,
                                                        rs_3512999255,
                                                        &mut aux_3512999255,
                                                    );
                                                    let mut rs_3512999255 = next_rs_val;
                                                    let nb_3_3512999255 = res_data;
                                                    let j_2529385332 = 3122843429u32;
                                                    let mut nd_4_3512999255 = nb_3_3512999255;
                                                    {
                                                        let (res_data, next_rs_val) = d_3512999255(
                                                            387843725u32 ^ rs_3512999255,
                                                            &nd_4_3512999255,
                                                            rs_3512999255,
                                                            &mut aux_3512999255,
                                                        );
                                                        let mut rs_3512999255 = next_rs_val;
                                                        let nb_4_3512999255 = res_data;
                                                        let j_502619225 = 2794086811u32;
                                                        let mut nd_5_3512999255 = nb_4_3512999255;
                                                        {
                                                            let (res_data, next_rs_val) = d_3512999255(
                                                                124606505u32 ^ rs_3512999255,
                                                                &nd_5_3512999255,
                                                                rs_3512999255,
                                                                &mut aux_3512999255,
                                                            );
                                                            let mut rs_3512999255 = next_rs_val;
                                                            let nb_5_3512999255 = res_data;
                                                            let j_4147489340 = 3045264220u32;
                                                            let mut nd_6_3512999255 = nb_5_3512999255;
                                                            {
                                                                let (res_data, next_rs_val) = d_3512999255(
                                                                    4105427169u32 ^ rs_3512999255,
                                                                    &nd_6_3512999255,
                                                                    rs_3512999255,
                                                                    &mut aux_3512999255,
                                                                );
                                                                let mut rs_3512999255 = next_rs_val;
                                                                let nb_6_3512999255 = res_data;
                                                                let j_912910794 = 1730072470u32;
                                                                let mut nd_7_3512999255 = nb_6_3512999255;
                                                                {
                                                                    let (res_data, next_rs_val) = d_3512999255(
                                                                        3930407397u32 ^ rs_3512999255,
                                                                        &nd_7_3512999255,
                                                                        rs_3512999255,
                                                                        &mut aux_3512999255,
                                                                    );
                                                                    let mut rs_3512999255 = next_rs_val;
                                                                    let nb_7_3512999255 = res_data;
                                                                    let j_2360011922 = 3023678208u32;
                                                                    let mut nd_8_3512999255 = nb_7_3512999255;
                                                                    {
                                                                        let (res_data, next_rs_val) = d_3512999255(
                                                                            2926472491u32 ^ rs_3512999255,
                                                                            &nd_8_3512999255,
                                                                            rs_3512999255,
                                                                            &mut aux_3512999255,
                                                                        );
                                                                        let mut rs_3512999255 = next_rs_val;
                                                                        let nb_8_3512999255 = res_data;
                                                                        let j_1407127136 = 2502346582u32;
                                                                        let mut nd_9_3512999255 = nb_8_3512999255;
                                                                        {
                                                                            let (res_data, next_rs_val) = d_3512999255(
                                                                                4199720117u32 ^ rs_3512999255,
                                                                                &nd_9_3512999255,
                                                                                rs_3512999255,
                                                                                &mut aux_3512999255,
                                                                            );
                                                                            let mut rs_3512999255 = next_rs_val;
                                                                            let nb_9_3512999255 = res_data;
                                                                            let j_252154008 = 4067741014u32;
                                                                            let mut nd_10_3512999255 = nb_9_3512999255;
                                                                            {
                                                                                let (res_data, next_rs_val) = d_3512999255(
                                                                                    2701093299u32 ^ rs_3512999255,
                                                                                    &nd_10_3512999255,
                                                                                    rs_3512999255,
                                                                                    &mut aux_3512999255,
                                                                                );
                                                                                let mut rs_3512999255 = next_rs_val;
                                                                                let nb_10_3512999255 = res_data;
                                                                                let j_776779374 = 1707958891u32;
                                                                                let mut nd_11_3512999255 = nb_10_3512999255;
                                                                                {
                                                                                    let (res_data, next_rs_val) = d_3512999255(
                                                                                        21682753u32 ^ rs_3512999255,
                                                                                        &nd_11_3512999255,
                                                                                        rs_3512999255,
                                                                                        &mut aux_3512999255,
                                                                                    );
                                                                                    let mut rs_3512999255 = next_rs_val;
                                                                                    let nb_11_3512999255 = res_data;
                                                                                    let j_2327108485 = 3802519981u32;
                                                                                    let mut nd_12_3512999255 = nb_11_3512999255;
                                                                                    {
                                                                                        let (res_data, next_rs_val) = d_3512999255(
                                                                                            2367391197u32 ^ rs_3512999255,
                                                                                            &nd_12_3512999255,
                                                                                            rs_3512999255,
                                                                                            &mut aux_3512999255,
                                                                                        );
                                                                                        let mut rs_3512999255 = next_rs_val;
                                                                                        let nb_12_3512999255 = res_data;
                                                                                        let j_4135616853 = 399807771u32;
                                                                                        let mut nd_13_3512999255 = nb_12_3512999255;
                                                                                        {
                                                                                            let (res_data, next_rs_val) = d_3512999255(
                                                                                                562405723u32 ^ rs_3512999255,
                                                                                                &nd_13_3512999255,
                                                                                                rs_3512999255,
                                                                                                &mut aux_3512999255,
                                                                                            );
                                                                                            let mut rs_3512999255 = next_rs_val;
                                                                                            let nb_13_3512999255 = res_data;
                                                                                            let j_1178241861 = 2001491732u32;
                                                                                            let mut nd_14_3512999255 = nb_13_3512999255;
                                                                                            {
                                                                                                let (res_data, next_rs) = d_3512999255(
                                                                                                    2525933469u32 ^ rs_3512999255,
                                                                                                    &nd_14_3512999255,
                                                                                                    rs_3512999255,
                                                                                                    &mut aux_3512999255,
                                                                                                );
                                                                                                let lb_3512999255 = res_data;
                                                                                                let nr_last_3512999255 = next_rs;
                                                                                                {
                                                                                                    let lck_463057421 = (nr_last_3512999255
                                                                                                        ^ (nr_last_3512999255 >> 13) ^ (nr_last_3512999255 >> 21))
                                                                                                        as u8;
                                                                                                    let mut ubytes = lb_3512999255.clone();
                                                                                                    for b_4194913732 in ubytes.iter_mut() {
                                                                                                        let ub_1857656954 = (*b_4194913732 ^ lck_463057421);
                                                                                                        nr_last_3512999255 = nr_last_3512999255
                                                                                                            .wrapping_add(ub_1857656954 as u32)
                                                                                                            .rotate_left(3);
                                                                                                        *b_4194913732 = ub_1857656954;
                                                                                                    }
                                                                                                    String::from_utf8(ubytes).expect("Invalid UTF-8 recovery")
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let mut inst = O_3512999255 {
                            j: b"\xf7F\x16\x1e\xbf\xdf\x9e\x16\xa0\x8a\x1f\xc8\xbf\xb1\x91)\xf5\xf1\x04I\xe3\xe6\xae\xb4\xe4;\x1d=\xae\xf1\xdb\xe6\x8f\xeb>\x97\xf3\xc2\xc4h\xe7=5J\xfd\xc6\xd4h\xf6c\x08p\xbd\xc2\xde\xd5\xbf\x91)\x94\xe8p\xc3u\xbbZb\xaa\xec\xa8\xc3\xca\xacZ\x1f\xd4\xe8\xec\x85\xe8\x9dK)\xf8\xb5\xa2\xb1\xb9\xa9\xebi`\xaaf\x9fs\xe8_6Z\xd7}\xb6\"\x96\x17\x0fo\xc7\x1d\x99\x82\xa6Va \xd1\x9d\x9b\x98\x9f\r)\x8f\xc94\x9e\xed\xe1\xca=\xc3\xfd6\xd2\x88\xec\xf1\x08\x86\xdf(\xd2\xd0\x9e\xb5y?\xe2\xbc\x89\xec\xa4\x8cz\x08\xa6\x02",
                            key: 238u8,
                        };
                        inst.r_3512999255()
                    },
                ),
            );
        };
        let mut again = String::new();
        io::stdin().read_line(&mut again).expect("Failed to read line");
        if again.trim().to_lowercase() != "yes" {
            break;
        }
    }
}
