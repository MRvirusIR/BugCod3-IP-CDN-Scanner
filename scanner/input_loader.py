from scanner.sanitize import sanitize
from scanner.cidr import expand_cidr
import socket

def load_targets(file_path):

    with open(file_path, "r") as f:
        raw = f.readlines()

    # 1. sanitize
    cleaned = sanitize(raw)

    # 2. expand cidr
    expanded = list(expand_cidr(cleaned))

    final = []

    for t in expanded:

        t = t.strip()

        if not t:
            continue

        try:
            # domain → ip
            ip = socket.gethostbyname(t)
            final.append(ip)

        except:

            # اگر IP بود یا fail شد
            final.append(t)

    # 3. remove duplicates
    return list(set(final))
