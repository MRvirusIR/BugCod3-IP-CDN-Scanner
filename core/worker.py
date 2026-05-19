import asyncio
import socket

from scanner.cdn import detect_cdn
from scanner.asn import get_asn_info
from scanner.verifier import verify_http
from scanner.ping import tcp_ping

from core.limiter import semaphore
from config import TIMEOUT, RETRIES


class Worker:

    def __init__(
        self,
        queue,
        ports,
        results,
        progress,
        task,
        stats
    ):

        self.queue = queue
        self.ports = ports
        self.results = results
        self.progress = progress
        self.task = task
        self.stats = stats

    async def run(self):

        while not self.queue.empty():

            try:

                target = await self.queue.get()

                result = await self.scan(target)

                self.stats.scanned += 1

                if result:

                    safe = {

                        "host": str(
                            result.get("host", "N/A")
                        ),

                        "domain": str(
                            result.get("domain", "N/A")
                        ),

                        "ping": result.get(
                            "ping",
                            -1
                        ),

                        "open_ports": list(
                            result.get(
                                "open_ports",
                                []
                            )
                        ),

                        "asn": result.get("asn")
                        if isinstance(
                            result.get("asn"),
                            dict
                        ) else {
                            "asn": "N/A",
                            "isp": "N/A",
                            "country": "N/A"
                        },

                        "cdn": result.get("cdn")
                        if isinstance(
                            result.get("cdn"),
                            dict
                        ) else {
                            "cdn": "Unknown",
                            "color": "#64748b"
                        }
                    }

                    self.results.append(safe)

                    self.stats.open_hosts += 1

                    try:
                        self.stats.add_cdn(
                            safe["cdn"]["cdn"]
                        )
                    except:
                        pass

                try:

                    self.progress.update(
                        self.task,
                        completed=self.stats.scanned
                    )

                except:
                    pass

            except Exception as e:

                print(f"[WORKER ERROR] {e}")

                continue

    async def scan(self, host):

        open_ports = []

        for port in self.ports:

            ok = await self.check_port(
                host,
                port
            )

            if ok:

                verify = await verify_http(
                    host,
                    port
                )

                if verify["alive"]:

                    open_ports.append({

                        "port": port,

                        "latency": verify.get(
                            "latency",
                            0
                        ),

                        "banner": verify.get(
                            "banner",
                            "unknown"
                        )
                    })

        if not open_ports:
            return None

        try:

            asn = get_asn_info(host)

        except:

            asn = {
                "asn": "N/A",
                "isp": "N/A",
                "country": "N/A"
            }

        try:

            cdn = detect_cdn(host)

        except:

            cdn = {
                "cdn": "Unknown",
                "color": "#64748b"
            }

        try:

            domain = socket.gethostbyaddr(
                host
            )[0]

        except:

            domain = "N/A"

        try:

            ping = await tcp_ping(host)

        except:

            ping = -1

        return {

            "host": host,

            "domain": domain,

            "ping": ping,

            "open_ports": open_ports,

            "asn": asn,

            "cdn": cdn
        }

    async def check_port(self, host, port):

        async with semaphore:

            for _ in range(RETRIES):

                writer = None

                try:

                    conn = asyncio.open_connection(
                        host,
                        port
                    )

                    reader, writer = await asyncio.wait_for(
                        conn,
                        timeout=TIMEOUT
                    )

                    return True

                except (
                    asyncio.TimeoutError,
                    ConnectionRefusedError,
                    OSError
                ):
                    continue

                except Exception:
                    continue

                finally:

                    try:

                        if writer:

                            writer.close()

                            await writer.wait_closed()

                    except:
                        pass

        return False
