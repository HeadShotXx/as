content = open('builder.go').read()
stack = []
for i, char in enumerate(content):
    if char == '{':
        stack.append(i)
    elif char == '}':
        if not stack:
            print(f"Extra closing brace at index {i}")
        else:
            stack.pop()
if stack:
    for pos in stack:
        print(f"Unclosed opening brace at index {pos}")
        # Print surrounding context
        start = max(0, pos - 20)
        end = min(len(content), pos + 20)
        print(f"Context: {content[start:end]!r}")
else:
    print("Braces are balanced")
