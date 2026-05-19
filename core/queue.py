import asyncio

class TargetQueue:

    def __init__(self):
        self._q = asyncio.Queue()

    def fill(self, items):
        for item in items:
            self._q.put_nowait(item)

    async def get(self):
        return await self._q.get()

    def empty(self):
        return self._q.empty()

    # ✅ SAFE stop mechanism
    def stop(self, workers: int):
        for _ in range(workers):
            self._q.put_nowait(None)
