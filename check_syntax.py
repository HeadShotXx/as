import sys

def check_batch_syntax(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # Check for unbalanced parentheses in lines that aren't purely comments
        if line.strip().startswith('rem') or line.strip().startswith('::'):
            continue

        # Very basic check: balance of ( and )
        # Note: This is complex in Batch due to quotes and carets.

        # Check for ] that might be problematic
        # In Batch, ] is usually only problematic if it's interpreted as a closing bracket
        # for something that didn't open. But Batch doesn't use [] for grouping.

        # However, if ] is used in a SET /A expression inappropriately...
        if 'set /a' in line.lower() and ']' in line:
            print(f"Potential issue on line {i+1}: ] in set /a")
            print(line.strip())

        # Check for ] outside of quotes in sensitive commands
        if 'if ' in line.lower() or 'for ' in line.lower():
             if ']' in line:
                 print(f"Possible issue on line {i+1}: ] in IF/FOR")
                 print(line.strip())

check_batch_syntax('obf_example.bat')
