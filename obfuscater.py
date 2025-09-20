#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rust_obfer_best.py
Basit ama gelişmiş özellikleri olan tek dosya Rust obfuscator.
Sadece iki argüman alır: -i input -o output
Varsayılanlar: fn name length = 12, garbage injection = açık
"""

import argparse
import random
import re
import string
from typing import List, Tuple, Optional

# ---------- Ayarlar (kullanıcı tarafından değil, "en iyi" varsayılanlar) ----------
DEFAULT_FN_LEN = 12
LETTERS = string.ascii_lowercase

# ---------- Yardımcı fonksiyonlar ----------
def random_ident(length: int) -> str:
    """snake_case rastgele isim. 1..3 parçaya bölünür."""
    words = random.randint(1, 3)
    remaining = length
    parts = []
    for i in range(words):
        if i == words - 1:
            wlen = remaining if remaining > 0 else 1
        else:
            max_possible = remaining - (words - i - 1)
            wlen = random.randint(1, max(1, max_possible))
        remaining -= wlen
        parts.append(''.join(random.choice(LETTERS) for _ in range(max(1, wlen))))
    return '_'.join(parts)

def make_junk_block(fn_len: int) -> str:
    """Junk/gereksiz kod bloğu üretir (Rust uyumlu)."""
    parts = []
    r1 = random.randint(1, 2**31-1)
    r2 = random.randint(1, 2**31-1)
    parts.append(f"if ({r1}u32.wrapping_mul({r2}u32) ^ {r1}u32) % 2 == 1 {{}} else {{}}")
    dname = random_ident(max(4, fn_len // 2))
    parts.append(f"fn {dname}(x: i32) -> i32 {{ x ^ ({r2} as i32) }}")
    parts.append(f"let _ = {dname}({r1} as i32);")
    choice = random.randint(0, 4)
    arms = []
    for i in range(5):
        arms.append(f"{i}usize => {{ let _ = {i}usize; }},")
    match_block = "match {choice} {{\n        {arms}\n        _ => {{}}\n    }}".format(choice=choice, arms="\n        ".join(arms))
    parts.append(match_block)
    junk_count = random.randint(2, 4)
    for _ in range(junk_count):
        v = random.randint(0, 255)
        parts.append(f"let _junk = {v}u8;")
    # girinti uygula
    return "\n    ".join(parts)

# ---------- Blok (brace) tarayıcı: { ... } bloklarını toplayıp hangi keyword ile açıldığını tahmin eder ----------
def find_brace_blocks(src: str) -> List[Tuple[int,int,Optional[str]]]:
    """
    Kaynakta tüm { ... } bloklarını eşleştirir.
    Döner: liste (start_index_of_{, end_index_of_}, maybe_keyword)
    maybe_keyword: eğer '{'dan hemen önce 'impl', 'mod', 'trait', 'struct', 'enum', 'extern' gibi bir keyword görünürse
    o keyword döner; aksi halde None.
    """
    keywords = ("impl", "mod", "trait", "struct", "enum", "extern", "unsafe")
    blocks = []
    stack = []
    i = 0
    L = len(src)
    while i < L:
        c = src[i]
        if c == '{':
            # look backwards up to 200 chars to find a keyword immediately before this block
            scan_start = max(0, i-200)
            prefix = src[scan_start:i]
            # remove trailing whitespace
            m = re.search(r'(\b(?:' + '|'.join(keywords) + r')\b[^\{;]*)\s*$', prefix, re.S)
            kw = m.group(1).split()[0] if m else None
            stack.append((i, kw))
            i += 1
            continue
        elif c == '}':
            if stack:
                start, kw = stack.pop()
                blocks.append((start, i, kw))
            i += 1
            continue
        else:
            i += 1
            continue
    # blocks listesi start->end sırasına göre; döndür
    return blocks

# ---------- Fonksiyon yakalayıcı (daha geniş destek) ----------
FN_HEADER_RE = re.compile(
    r'(?:^|\n)'                                   # satır başı
    r'(?P<prefix>\s*(?:pub(?:\s*\([^\)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?'  # opsiyonel prefixler
    r'(?:const\s+)?fn\s+)'                        # fn anahtar kelimesi
    r'(?P<name>[A-Za-z_]\w*)'                     # fonksiyon ismi
    r'\s*(?P<generics>\<[^>{}]*\>)?\s*'           # opsiyonel generics
    r'\('                                         # param başı
    , re.M
)

def find_functions(src: str) -> List[Tuple[int,int,str,int]]:
    """
    Daha sağlam fonksiyon bulucu.
    Döner: liste (header_start_idx, fn_open_brace_idx, matched_header_text, name_start_idx)
    - header_start_idx: başından itibaren header'ın başladığı indeks
    - fn_open_brace_idx: '{' karakterinin indeksi (gövde başlangıcı)
    - matched_header_text: header kısmı (parantez başlangıcına kadar)
    - name_start_idx: fonksiyon isminin başlama indeksi (kullanışlı)
    """
    results = []
    for m in FN_HEADER_RE.finditer(src):
        header_start = m.start(1)
        name = m.group('name')
        # find the matching ')' for the parameters, starting from m.end()
        params_start = src.find('(', m.end()-1)
        if params_start == -1:
            continue
        idx = params_start + 1
        depth = 1
        L = len(src)
        while idx < L:
            ch = src[idx]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    break
            elif ch == '"':  # skip string
                # rudimentary skip string literal
                idx2 = idx+1
                while idx2 < L:
                    if src[idx2] == '"' and src[idx2-1] != '\\':
                        break
                    idx2 += 1
                idx = idx2
            idx += 1
        if idx >= L:
            continue
        params_end = idx
        # after params may come generics/where/return-type — so we need to find the next '{'
        # search from params_end forward to the next '{' that isn't inside <> or quotes
        j = params_end + 1
        depth_angle = 0
        while j < L:
            ch = src[j]
            if ch == '<':
                depth_angle += 1
            elif ch == '>':
                depth_angle = max(0, depth_angle-1)
            elif ch == '{' and depth_angle == 0:
                # found open brace for function body
                # header text is from header_start up to this '{'
                header_text = src[header_start:j].strip()
                results.append((header_start, j, header_text, m.start('name')))
                break
            elif ch == '"' :
                # skip string
                j2 = j+1
                while j2 < L:
                    if src[j2] == '"' and src[j2-1] != '\\':
                        break
                    j2 += 1
                j = j2
            j += 1
    return results

# ---------- Parametre isimleri çıkarıcı ----------
def extract_arg_names(param_text: str) -> List[str]:
    """
    Parametre metninden isimleri çıkarır. Basit ama geniş destek.
    param_text: iç parantez içi (örn "self, a: i32, (x, y): (i32, i32), mut b: &str")
    """
    txt = param_text.strip()
    if txt == "":
        return []
    parts = []
    cur = ""
    depth = 0
    i = 0
    L = len(txt)
    while i < L:
        ch = txt[i]
        if ch == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ""
            i += 1
            continue
        cur += ch
        if ch in '([{<':
            depth += 1
        elif ch in ')]}>':
            depth = max(0, depth-1)
        elif ch == '"' :
            # skip string
            j = i+1
            while j < L:
                if txt[j] == '"' and txt[j-1] != '\\':
                    break
                j += 1
            cur += txt[i+1:j+1]
            i = j
        i += 1
    if cur.strip():
        parts.append(cur.strip())
    names = []
    for p in parts:
        p = p.strip()
        if p == "":
            continue
        # match common patterns: "mut x: T", "x: T", "_: T", "self", "&self", "self: &Self"
        m = re.match(r'^(?:mut\s+)?((?:&)?self|[A-Za-z_]\w*|_)\b', p)
        if m:
            names.append(m.group(1))
        else:
            # destructuring or complex pattern: use "_" placeholder
            names.append("_")
    return names

# ---------- Ana obfuscation fonksiyonu ----------
def obfuscate_source(src: str, fn_len: int = DEFAULT_FN_LEN, do_garbage: bool = True) -> str:
    blocks = find_brace_blocks(src)
    # prepare parent block lookup: for any index, find smallest block that contains it (useful to know impl)
    # sort blocks by start ascending, length descending
    block_containment = []
    for s,e,kw in blocks:
        block_containment.append((s,e,kw))
    # find functions
    fns = find_functions(src)
    if not fns:
        return src
    out = src
    offset = 0
    # We'll prepare insertions to put wrappers inside impl blocks: map impl_end_index -> list of wrappers to insert before that end
    impl_inserts = {}  # impl_end_idx -> list of (insertion_text, insertion_pos_relative)
    # process functions from end -> start
    for header_start, brace_idx, header_text, name_idx in reversed(fns):
        # adapt indices with offset
        real_header_start = header_start + offset
        real_brace_idx = brace_idx + offset
        # find function body matching } starting from real_brace_idx
        i = real_brace_idx
        L = len(out)
        depth = 0
        while i < L:
            ch = out[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    fn_end = i  # index of matching '}'
                    break
            i += 1
        else:
            # unbalanced, skip
            continue
        fn_block = out[real_header_start:fn_end+1]
        # extract function name
        mname = re.search(r'\bfn\s+([A-Za-z_]\w*)', fn_block)
        if not mname:
            continue
        name = mname.group(1)
        # extract param text (between first '(' after 'fn name')
        m_paren = re.search(r'\bfn\s+' + re.escape(name) + r'\s*(?:<[^>]*>\s*)?\s*\(', fn_block)
        if not m_paren:
            continue
        paren_pos = real_header_start + m_paren.end() - 1  # position of '(' in out
        # find matching ')'
        j = paren_pos + 1
        depth_p = 1
        while j < len(out):
            ch = out[j]
            if ch == '(':
                depth_p += 1
            elif ch == ')':
                depth_p -= 1
                if depth_p == 0:
                    params_end_pos = j
                    break
            elif ch == '"' :
                # naive string skip
                k = j+1
                while k < len(out):
                    if out[k] == '"' and out[k-1] != '\\':
                        break
                    k += 1
                j = k
            j += 1
        else:
            continue
        param_text = out[paren_pos+1:params_end_pos]
        arg_names = extract_arg_names(param_text)
        # determine parent block (impl?) by finding the smallest block that contains real_header_start
        parent_block = None
        parent_end = None
        for s,e,kw in block_containment:
            if (s <= header_start) and (e >= fn_end - offset):
                # candidate: contains original indices
                # choose the smallest span (tightest)
                if parent_block is None or (e - s) < (parent_end[1] - parent_end[0]):
                    parent_block = (s,e,kw)
                    parent_end = (s,e)
        # But block_containment used original indices; we need to map to out indices.
        # Simpler approach: find the innermost '{...}' block in 'out' that contains real_header_start by rescanning blocks in 'out'
        # We'll compute fresh blocks for 'out' now (cheap because few functions)
        fresh_blocks = find_brace_blocks(out)
        impl_parent = None
        for s,e,kw in fresh_blocks:
            if s <= real_header_start and e >= fn_end+offset:
                if kw == 'impl':
                    impl_parent = (s,e,kw)
                    break
        # decide where to place wrapper
        is_method = False
        has_self = False
        if arg_names and arg_names[0] in ("self", "&self", "&mut self", "mut self"):
            is_method = True
            has_self = True
        # produce obfuscated function text: rename function and optionally inject junk at top of body
        new_name = random_ident(fn_len)
        # create header with renamed fn: replace first occurrence of "fn name" in fn_block
        obf_block = fn_block
        obf_block = re.sub(r'\bfn\s+' + re.escape(name) + r'\b', 'fn ' + new_name, obf_block, count=1)
        # inject junk at top of body if requested
        if do_garbage:
            # insert just after the first '{' of obf_block
            idx_first_brace = obf_block.find('{')
            if idx_first_brace != -1:
                junk = make_junk_block(fn_len)
                obf_block = obf_block[:idx_first_brace+1] + "\n    " + junk + "\n" + obf_block[idx_first_brace+1:]
        # build wrapper text: same header signature as original (we'll extract header line up to '{')
        header_up_to_brace = out[real_header_start:real_brace_idx].rstrip()
        # ensure wrapper ends with space before '{'
        wrapper_sig = header_up_to_brace
        # construct call args: replace any '_' with a placeholder, but if '_' present we still pass '_'
        call_args = ", ".join(arg_names) if arg_names else ""
        # For methods: call new_name either as method on self (self.new_name(...)) or as associated fn (new_name(...))
        if is_method or impl_parent:
            # wrapper will be inserted in the same impl block if possible
            if has_self:
                call_line = f"self.{new_name}({', '.join([a for a in arg_names if a != 'self' and a != '&self' and a != '&mut self' and a != 'mut self'])});"
            else:
                # static method in impl: call directly
                call_line = f"{new_name}({call_args});" if call_args else f"{new_name}();"
        else:
            call_line = f"{new_name}({call_args});" if call_args else f"{new_name}();"
        # wrapper body: for non-() return types we just call and return if needed.
        # Try to detect if original fn had '->' return type in header_up_to_brace
        ret_match = re.search(r'->\s*([^ \t\n{]+)', header_up_to_brace)
        if ret_match:
            # return type present -> return the call
            if call_line.endswith(';'):
                call_stmt = call_line[:-1]  # remove ;
            else:
                call_stmt = call_line
            wrapper_body = f"    return {call_stmt};"
        else:
            wrapper_body = f"    {call_line}"
        # construct wrapper text (same signature)
        wrapper_text = wrapper_sig + " {\n" + wrapper_body + "\n}\n\n"
        # Now replace original function block in out with obf_block + wrapper or only obf_block and add wrapper elsewhere
        # If we are inside an impl block (detect via fresh_blocks), we'll keep obf_block in place and schedule wrapper to be inserted before impl closing '}'.
        inserted = False
        if impl_parent:
            impl_start, impl_end, kw = impl_parent
            # Replace original fn (real_header_start .. fn_end+1) with obf_block only, and queue wrapper insertion before impl_end
            out = out[:real_header_start] + obf_block + out[fn_end+1:]
            inserted = True
            offset += len(obf_block) - (fn_end+1 - real_header_start)
            # find current impl_end in 'out' (might have shifted). We'll search for the matching '}' starting from impl_start.
            # For simplicity, we'll append wrapper just before the impl's closing brace by finding the last '}' index at or after impl_start that balances.
            # Find impl matching brace:
            idx_scan = impl_start
            depth = 0
            L2 = len(out)
            while idx_scan < L2:
                ch = out[idx_scan]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        impl_close_idx = idx_scan
                        break
                idx_scan += 1
            else:
                # fallback: append at end of file
                impl_close_idx = len(out)
            # schedule insertion before impl_close_idx
            impl_inserts.setdefault(impl_close_idx, []).append(wrapper_text)
            # offset affects subsequent replacements: but since we haven't inserted wrappers yet, keep track when we do.
        else:
            # top-level function: replace with obf_block + wrapper immediately after
            replacement = obf_block + "\n" + wrapper_text
            out = out[:real_header_start] + replacement + out[fn_end+1:]
            offset += len(replacement) - (fn_end+1 - real_header_start)
            inserted = True

    # After processing all functions, apply impl_inserts (note: their indices are for the current 'out')
    if impl_inserts:
        # sort impl_inserts keys descending so indices remain valid
        for impl_close_idx in sorted(impl_inserts.keys(), reverse=True):
            inserts = impl_inserts[impl_close_idx]
            insertion_text = "\n".join(inserts) + "\n"
            out = out[:impl_close_idx] + insertion_text + out[impl_close_idx:]
    return out

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Rust obfuscator (sadece -i ve -o). Varsayılanlar: uzun rastgele isim, garbage ekleme.")
    p.add_argument("-i", "--input", required=True, help="Girdi Rust dosyası")
    p.add_argument("-o", "--output", required=True, help="Çıktı Rust dosyası")
    args = p.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        src = f.read()

    random.seed()  # sistem saatine göre
    out = obfuscate_source(src, fn_len=DEFAULT_FN_LEN, do_garbage=True)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(out)

    print("Obfuscation tamamlandı:", args.output)

if __name__ == "__main__":
    main()
