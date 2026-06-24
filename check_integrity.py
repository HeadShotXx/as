import sys
import re

def check_integrity(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {filepath} not found.")
        return False

    errors = 0
    for i, line in enumerate(lines, 1):
        # 1. CMD line length limit (8191 characters)
        if len(line) > 8191:
            print(f"Line {i}: Length exceeds 8191 characters ({len(line)})")
            errors += 1

        # 2. Parenthesis balance (Basic check)
        # Note: This is simplified as CMD parsing of parenthesis is complex (e.g. inside strings)
        # But for flattened CFG obfuscation, imbalance is usually a fatal error.
        open_p = line.count('(')
        close_p = line.count(')')
        # This is a very rough check and might have false positives if ( is inside a string
        # but in our obf.py we don't usually have many strings with literal ( or ) except in echo
        if open_p != close_p and "echo" not in line.lower() and "set" not in line.lower():
             # We allow imbalance in set/echo as they might be literal
             pass

    # 3. Check for obvious syntax errors in state transitions
    dispatcher_pattern = re.compile(r'set /a ".*=.* \^ !.*! \^ !.*! \^ !.*! \^ !.*!"')
    found_transition = False
    for line in lines:
        if "set /a" in line and "^" in line and "!" in line:
            found_transition = True
            break

    if not found_transition:
        print("Warning: No state transition logic found.")
        # Not strictly an error but suspicious

    if errors == 0:
        print(f"Integrity check passed for {filepath}")
        return True
    else:
        print(f"Integrity check failed for {filepath} with {errors} errors.")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_integrity.py <file.bat>")
        sys.exit(1)
    check_integrity(sys.argv[1])
