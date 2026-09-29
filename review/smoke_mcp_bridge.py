"""Run after installing both sibling projects into this interpreter's venv."""

import asyncio
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from autheo_agent_environment.demo import run


def payload(result):
    assert not result.isError, result
    return result.structuredContent or json.loads(result.content[0].text)


async def main():
    with TemporaryDirectory(prefix="autheo-trust-bridge-") as temporary:
        output = Path(temporary)
        demo = run(output)
        env = {key: value for key, value in os.environ.items() if not key.startswith("AUTHEO_")}
        env.update(demo["mcp_environment"])
        console = str(Path(sys.executable).parent / ("autheo-mcp.exe" if os.name == "nt" else "autheo-mcp"))
        for name, command, args in [
            ("module", sys.executable, ["-m", "autheo_mcp.server"]),
            ("console", console, []),
        ]:
            async with stdio_client(StdioServerParameters(command=command, args=args, env=env)) as (
                read,
                write,
            ):
                async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=15)) as client:
                    await client.initialize()
                    assert len((await client.list_tools()).tools) == 44
                    for tool, section in [
                        ("autheo_agent_get_passport", "passport"),
                        ("autheo_agent_get_mandate", "mandate"),
                        ("autheo_agent_list_receipts", "receipts"),
                        ("autheo_agent_trust_status", "audit"),
                    ]:
                        data = payload(await client.call_tool(tool, {}))
                        assert data["status"] == "verified_snapshot", data
                        assert data["execution_authorized"] is False and section in data
                        if section == "mandate":
                            assert data[section]["remaining_minor"] == 60 and data[section]["asset"] == "DEMO"
                    assert (
                        payload(await client.call_tool("autheo_agent_trust_guide", {}))[
                            "execution_authorized"
                        ]
                        is False
                    )
                    assert (await client.read_resource("autheo://agent-trust")).contents
                    assert (await client.call_tool("autheo_agent_list_receipts", {"limit": 21})).isError
                    token_path = output / "trust-snapshot.jwt"
                    original = token_path.read_text()
                    token_path.write_text("invalid-snapshot")
                    assert (
                        payload(await client.call_tool("autheo_agent_trust_status", {}))["status"]
                        == "invalid_snapshot"
                    )
                    token_path.write_text(original)
            print(f"{name}: five trust tools, resource, budget, invalid limit, and tampering verified")


if __name__ == "__main__":
    asyncio.run(main())
