def sanitize(lines):
    result = []
    for l in lines:
        l = l.strip()
        if l and not l.startswith("#"):
            result.append(l)
    return list(set(result))
