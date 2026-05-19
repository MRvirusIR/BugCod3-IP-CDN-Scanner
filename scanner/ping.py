import asyncio
import time


async def tcp_ping(host, port=443, timeout=2):

    start = time.time()

    try:

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        latency = round(
            (time.time() - start) * 1000,
            2
        )

        writer.close()
        await writer.wait_closed()

        return latency

    except:
        return -1
