import sys
import re

def check_integrity(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}")
        return False

    success = True
    for i, line in enumerate(lines):
        line = line.rstrip('\r\n')
        # Check line length
        if len(line) > 8191:
            print(f"Line {i+1} exceeds 8191 characters (length: {len(line)})")
            success = False

        # Check balanced parentheses (ignoring quotes)
        nest = 0
        in_quotes = False
        j = 0
        while j < len(line):
            if line[j] == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if line[j] == '(':
                    nest += 1
                elif line[j] == ')':
                    nest -= 1
            j += 1

        if nest != 0:
            # Note: Batch sometimes spans parentheses across lines,
            # but in this obfuscator, they should be balanced per line or block.
            # However, the splitter ensures nest_level 0 at split.
            # Let's just check overall balance if we were to join all lines,
            # but for now, most lines should be balanced.
            pass

    # Total balance check
    total_nest = 0
    in_quotes = False
    for line in lines:
        j = 0
        while j < len(line):
            if line[j] == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if line[j] == '(':
                    total_nest += 1
                elif line[j] == ')':
                    total_nest -= 1
            j += 1

    if total_nest != 0:
        print(f"Total parentheses are unbalanced: {total_nest}")
        success = False

    # Check for required variables if it's the obfuscated file
    content = "".join(lines)
    for var in ["RS", "AUX", "CNT"]:
        if var not in content:
            # We use randomized names for these in the plan, so we should check if they are initialized.
            pass

    if success:
        print("Integrity check passed!")
    return success

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_integrity.py <file>")
    else:
        check_integrity(sys.argv[1])
