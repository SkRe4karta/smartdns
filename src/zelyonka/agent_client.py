from __future__ import annotations

import time

import httpx

from .config import Settings


class AgentClient:
    def __init__(self, settings: Settings):
        self._health_until = 0.0
        self._healthy = False
        self._exit_health: dict = {}
        self.client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(settings.agent_socket)),
            base_url="http://agent",
            timeout=8,
        )

    async def grant(self, account_id: str, ip: str, exit_id: str, generation: int) -> bool:
        try:
            response = await self.client.post(
                "/grant",
                json={"account_id": account_id, "ip": ip, "exit_id": exit_id, "generation": generation},
            )
            return response.status_code == 200 and response.json().get("ready") is True
        except httpx.HTTPError, ValueError:
            return False

    async def reconcile(self) -> bool:
        try:
            response = await self.client.post("/reconcile")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def status(self) -> dict:
        try:
            response = await self.client.get("/status")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError, ValueError:
            return {"ready": False, "error": "Агент недоступен"}

    async def is_ready(self, exit_id: str | None = None) -> bool:
        if time.monotonic() >= self._health_until:
            status = await self.status()
            self._healthy = status.get("ready") is True
            self._exit_health = status.get("exits", {})
            self._health_until = time.monotonic() + 1
        return self._healthy and (
            exit_id in (None, "fi-primary") or self._exit_health.get(exit_id, {}).get("ready") is True
        )

    async def check_exit(self, exit_id: str) -> dict:
        response = await self.client.post("/check-exit", json={"exit_id": exit_id})
        response.raise_for_status()
        return response.json()

    async def preview(self, patterns: list[str]) -> bool:
        try:
            response = await self.client.post("/preview", json={"patterns": patterns})
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self.client.aclose()
