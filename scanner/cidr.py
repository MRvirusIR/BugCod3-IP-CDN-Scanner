import ipaddress

MAX_IPS = 65536

def expand_cidr(targets):

    for t in targets:

        try:

            if "/" in t:

                net = ipaddress.ip_network(
                    t,
                    strict=False
                )

                if net.num_addresses > MAX_IPS:

                    print(
                        f"[WARNING] "
                        f"CIDR too large skipped: {t}"
                    )

                    continue

                for ip in net.hosts():
                    yield str(ip)

            else:
                yield t

        except:
            continue
