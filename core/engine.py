import asyncio
import time

from rich.live import Live
from rich.table import Table

from scanner.input_loader import load_targets
from core.queue import TargetQueue
from core.worker import Worker
from core.stats import Stats

from output.json_report import save_json
from output.html_report import save_html

from config import MAX_WORKERS, BATCH_SIZE, PORTS


class ScanEngine:

    def __init__(self, input_file):

        self.input_file = input_file
        self.results = []
        self.stats = Stats()

        self.start_time = time.time()
        self.last_scanned = 0
        self.last_time = time.time()

    def chunked(self, data, size):
        for i in range(0, len(data), size):
            yield data[i:i + size]

    def render(self):

        now = time.time()
        elapsed = now - self.start_time

        avg_cps = self.stats.scanned / elapsed if elapsed > 0 else 0

        delta = now - self.last_time
        live_cps = 0

        if delta > 0:
            live_cps = (self.stats.scanned - self.last_scanned) / delta

        self.last_scanned = self.stats.scanned
        self.last_time = now

        table = Table(title="🧠 BugCod3 Live Scanner (Stable)")

        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Elapsed Time", f"{elapsed:.2f}s")
        table.add_row("Total Scanned", str(self.stats.scanned))
        table.add_row("Avg CPS", f"{avg_cps:.2f}")
        table.add_row("Live CPS", f"{live_cps:.2f}")
        table.add_row("Open Hosts", str(self.stats.open_hosts))

        table.add_row("Cloudflare", str(self.stats.cdns.get("Cloudflare", 0)))
        table.add_row("Google", str(self.stats.cdns.get("Google", 0)))
        table.add_row("Fastly", str(self.stats.cdns.get("Fastly", 0)))
        table.add_row("Akamai", str(self.stats.cdns.get("Akamai", 0)))

        return table

    def run(self):
        asyncio.run(self._start())

    async def _start(self):

        targets = list(load_targets(self.input_file))
        self.stats.total = len(targets)

        queue = TargetQueue()
        queue.fill(targets)
 

        with Live(self.render(), refresh_per_second=4) as live:

            worker = Worker(
                queue,
                PORTS,
                self.results,
                live,
                None,
                self.stats
            )

            tasks = [
                asyncio.create_task(worker.run())
                for _ in range(MAX_WORKERS)
            ]

            async def updater():
                while any(not t.done() for t in tasks):
                    try:
                        live.update(self.render())  # ✅ FIXED
                    except Exception:
                        pass
                    await asyncio.sleep(0.3)

            updater_task = asyncio.create_task(
                updater()
            )

            await asyncio.gather(*tasks)

            updater_task.cancel()

        save_json(self.results)
        save_html(self.results)

        print("\n[✓] Scan Completed")
        print(f"[✓] Results: {len(self.results)}")
