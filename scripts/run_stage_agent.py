"""Private staging harness: real host adapter, separate HAProxy/nftables namespace."""

import asyncio

import uvicorn
from fastapi import FastAPI, Response

from smartdns.agent import AgentEngine, HostAdapter, create_agent
from smartdns.config import Settings


async def serve():
    settings = Settings.load()
    state = settings.data_dir.parent / "agent-state"
    engine = AgentEngine(settings, HostAdapter(state, node=True), state_dir=state)
    health = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @health.get("/health")
    async def check():
        return Response(status_code=200 if engine.ready() else 503)

    settings.agent_socket.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.gather(
        uvicorn.Server(
            uvicorn.Config(
                create_agent(engine), uds=str(settings.agent_socket), access_log=False, log_level="warning"
            )
        ).serve(),
        uvicorn.Server(
            uvicorn.Config(health, host="127.0.0.1", port=19118, access_log=False, log_level="warning")
        ).serve(),
    )


if __name__ == "__main__":
    asyncio.run(serve())
