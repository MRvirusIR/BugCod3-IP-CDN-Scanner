import socket

def get_asn_info(ip):

    try:

        host = socket.gethostbyaddr(ip)

        return {
            "asn": "N/A",
            "isp": host[0],
            "country": "N/A"
        }

    except:

        return {
            "asn": "unknown",
            "isp": "unknown",
            "country": "unknown"
        }
