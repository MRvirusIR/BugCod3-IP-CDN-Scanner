import asyncio
import ssl
import time


async def verify_http(host, port, timeout=1.5):

    start = time.time()

    try:

        # HTTPS
        if port == 443:

            ssl_ctx = ssl.create_default_context()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=ssl_ctx,
                    server_hostname=host
                ),
                timeout=timeout
            )

        # HTTP
        else:

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port
                ),
                timeout=timeout
            )

        latency = round(
            (time.time() - start) * 1000,
            2
        )

        # 🔥 فقط connect موفق کافیست
        # دیگه HEAD request نمیفرستیم
        # چون خیلی CDN ها بلاک میکنن

        writer.close()

        await writer.wait_closed()

        return {
            "alive": True,
            "latency": latency,
            "banner": f"TCP/{port} OPEN"
        }

    except ssl.SSLError:

        # 🔥 حتی SSL ERROR هم usable حساب کن
        return {
            "alive": True,
            "latency": 0,
            "banner": "SSL HANDSHAKE FAILED"
        }

    except:

        return {
            "alive": False,
            "latency": 0,
            "banner": "Connection Failed"
        }
