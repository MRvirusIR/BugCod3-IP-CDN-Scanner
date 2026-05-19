from scanner.cdn_db import CDN_RANGES
import ipaddress

def detect_cdn(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        for name, color, ranges in CDN_RANGES:
            for r in ranges:
                net = ipaddress.ip_network(r)
                if ip_obj in net:
                    return {
                        "cdn": name,
                        "color": color
                    }

        return {
            "cdn": "Unknown",
            "color": "#9ca3af"
        }

    except:
        return {
            "cdn": "Unknown",
            "color": "#9ca3af"
        }
