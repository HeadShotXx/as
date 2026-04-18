content = open('builder.go').read().splitlines()
level = 0
for i, line in enumerate(content):
    delta = line.count('{') - line.count('}')
    level += delta
    print(f"{i+1:3} {level:2} {line}")
