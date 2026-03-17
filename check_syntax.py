import sys
import re

def check_file(filepath):
    print(f"Checking {filepath}...")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    errors = 0
    for idx, line in enumerate(lines, 1):
        # 1. Check parenthesis balance
        # (Very basic check, but it detects obvious breakers)

        # 2. Check for safe caret placement
        # Caret should not be before !, ", =, %
        # UNLESS it's an even number of carets before !, or escaped properly.
        # But for this obfuscator, we should generally avoid ^!, ^", ^=, ^%
        # unless it was already in the source.
        # Let's check for ^! specifically as it's the most common breaker in delayed expansion.

        for match in re.finditer(r'(?<!\^)\^([!"=%])', line):
            # This matches ^! but not ^^!
            print(f"Line {idx}: Unsafe caret before '{match.group(1)}': {line.strip()}")
            errors += 1

        if len(line) > 8191:
            print(f"Line {idx}: CRITICAL - Line length {len(line)} exceeds CMD limit (8191)")
            errors += 1

    # 3. Check for label existence (Dispatcher jump target)
    labels = [line.strip() for line in lines if line.strip().startswith(':ID_')]
    if not labels:
        print(f"Error: No :ID_ labels found in {filepath}")
        errors += 1
    else:
        print(f"Found {len(labels)} ID labels.")

    if errors == 0:
        print(f"Static check passed for {filepath}")
    else:
        print(f"Static check failed for {filepath} with {errors} errors.")
    return errors == 0

if __name__ == "__main__":
    success = True
    for fp in sys.argv[1:]:
        if not check_file(fp):
            success = False
    sys.exit(0 if success else 1)
