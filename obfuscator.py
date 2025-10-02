import re
import random
import string
import sys

def get_random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def obfuscate_strings(code):
    decoder_functions = []
    string_literal_regex = re.compile(r'(L)?"((?:[^"\\]|\\.)*)"')
    string_map = {}

    def replacer(match):
        is_wide_char = match.group(1)
        original_string = match.group(2)

        # Check if the match is on a line with a preprocessor directive
        last_newline = code.rfind('\n', 0, match.start())
        line_start = last_newline + 1 if last_newline != -1 else 0
        line = code[line_start:match.start()]
        if line.strip().startswith('#'):
            return match.group(0)

        if original_string in string_map:
            return string_map[original_string] + "()"

        if len(original_string) < 2 or is_wide_char:
            return match.group(0)

        var_name = "enc_str_" + get_random_string(5)
        function_name = "get_" + var_name

        key = random.randint(1, 255)
        encrypted_chars = [ord(c) ^ key for c in original_string]

        cpp_array = f"unsigned char {var_name}[] = {{ {', '.join(map(str, encrypted_chars))}, 0 }};"

        decoder_function = f"""
const char* {function_name}() {{
    static {cpp_array}
    static bool decrypted = false;
    if (!decrypted) {{
        for (unsigned int i = 0; i < sizeof({var_name}) - 1; i++) {{
            {var_name}[i] ^= {key};
        }}
        decrypted = true;
    }}
    return (const char*){var_name};
}}
"""
        decoder_functions.append(decoder_function)
        string_map[original_string] = function_name
        return function_name + "()"

    # Process the entire code block at once
    obfuscated_code = string_literal_regex.sub(replacer, code)
    all_decoders = "\n\n" + "\n".join(decoder_functions)

    return obfuscated_code, all_decoders

def add_junk_code(code):
    junk_functions = []
    num_junk_functions = random.randint(3, 5)
    for _ in range(num_junk_functions):
        func_name = "junk_func_" + get_random_string(6)
        ret_type = random.choice(["void", "int", "bool"])
        param = "int " + get_random_string(3)

        junk_var = get_random_string(4)
        junk_op = random.choice(["+", "-", "*", "/"])
        junk_val1 = random.randint(1, 100)
        junk_val2 = random.randint(1, 100)

        func_body = f"int {junk_var} = {junk_val1} {junk_op} {junk_val2 if junk_op != '/' or junk_val2 != 0 else 1};"
        if ret_type == "int":
            func_body += f" return {junk_var};"
        elif ret_type == "bool":
            func_body += f" return {junk_var} > 0;"

        junk_functions.append(f"{ret_type} {func_name}({param}) {{{func_body}}}")

    return "\n".join(junk_functions) + "\n\n" + code

def main():
    input_file = "main.cpp"
    output_file = "main_obfuscated.cpp"

    # Handle command-line arguments
    if len(sys.argv) > 2 and (sys.argv[1] == '-i'):
        input_file = sys.argv[2]

    with open(input_file, "r") as f:
        code = f.read()

    # === PRE-PROCESSING STEP TO FIX THE ROOT CAUSE OF THE COMPILATION ERROR ===
    # The C++ code uses adjacent string literals for the base64_chars variable.
    # The regex-based obfuscator cannot handle this syntax correctly.
    # To fix this, pre-process the code to merge this specific string
    # into a single line BEFORE obfuscating. This is a targeted and robust fix.
    b64_pattern = re.compile(r'std::string\s+base64_chars\s*=\s*[^;]+;', re.DOTALL)
    single_line_b64_string = 'std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";'
    code = b64_pattern.sub(single_line_b64_string, code, count=1)


    # Apply obfuscations
    code = add_junk_code(code)
    code, string_decoder = obfuscate_strings(code)

    # Inject decoders after the last preprocessor directive
    lines = code.split('\n')
    injection_point = 0
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if stripped_line.startswith('#') or stripped_line.startswith('//'):
            injection_point = i + 1

    lines.insert(injection_point, string_decoder)
    code = '\n'.join(lines)

    with open(output_file, "w") as f:
        f.write(code)

    print(f"Obfuscation complete. Output written to {output_file}")

if __name__ == "__main__":
    main()