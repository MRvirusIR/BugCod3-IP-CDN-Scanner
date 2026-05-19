import asyncio
import socket

async def fast_check(host, port, timeout=1.5):

    loop = asyncio.get_event_loop()

    def _check():

        try:
            s = socket.socket()
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
        except:
            return False
        finally:
            try:
                s.close()
            except:
                pass

    return await loop.run_in_executor(None, _check)
