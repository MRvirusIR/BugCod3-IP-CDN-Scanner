import asyncio
from config import SEMAPHORE_LIMIT

semaphore = asyncio.Semaphore(
    SEMAPHORE_LIMIT
)
