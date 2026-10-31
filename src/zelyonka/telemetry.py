from __future__ import annotations

import asyncio
import time
from typing import Any

from .db import Database


class Recorder:
    def __init__(self, db: Database):
        self.db = db
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
        self.dropped = 0

    def record(self, **event: Any) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    def flush(self, rows: list[dict[str, Any]]) -> None:
        now = int(time.time())
        with self.db.connect() as db:
            db.executemany(
                "INSERT INTO dns_events(account_id,at,domain,qtype,result,service_id,exit_id,elapsed_ms) VALUES(:account_id,:at,:domain,:qtype,:result,:service_id,:exit_id,:elapsed_ms)",
                rows,
            )
            for row in rows:
                db.execute(
                    "INSERT INTO dns_buckets VALUES(?,?,1,?,?,?) ON CONFLICT(account_id,bucket) DO UPDATE SET total=total+1,blocked=blocked+excluded.blocked,proxied=proxied+excluded.proxied,errors=errors+excluded.errors",
                    (
                        row["account_id"],
                        row["at"] // 300 * 300,
                        int(row["result"] == "blocked"),
                        int(row["result"] == "proxied"),
                        int(row["result"] == "error"),
                    ),
                )
                db.execute("UPDATE accounts SET last_dns=? WHERE id=?", (row["at"], row["account_id"]))
            db.execute("DELETE FROM dns_events WHERE at<?", (now - 86400,))
            db.execute("DELETE FROM dns_buckets WHERE bucket<?", (now - 7 * 86400,))
            # Bound event storage under sustained abusive traffic.
            db.execute("DELETE FROM dns_events WHERE id < (SELECT MAX(id)-500000 FROM dns_events)")

    async def run(self) -> None:
        last_cleanup = 0.0
        while True:
            await asyncio.sleep(0.5)
            rows: list[dict[str, Any]] = []
            while not self.queue.empty() and len(rows) < 1000:
                rows.append(self.queue.get_nowait())
            if rows or not last_cleanup or time.monotonic() - last_cleanup >= 60:
                try:
                    await asyncio.to_thread(self.flush, rows)
                    last_cleanup = time.monotonic()
                except Exception:
                    self.dropped += len(rows)
