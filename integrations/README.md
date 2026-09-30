# MCP integration

Use current main of [ThothDivision/autheo-mcp](https://github.com/ThothDivision/autheo-mcp) with the optional `trust` dependencies. See the main README for installation and the bridge smoke test. No connector is automatically activated in OpenClaw.

## Historical review patch

`autheo-mcp-agent-trust.patch` records the original implementation against upstream base `374546e662b953e1fd918456253195f635559fa4`. It is an archival review artifact, not an update to apply on current main (which already includes these changes). It does not include later publication documentation or CI updates.

The separate Agent Environment owns issuer and policy logic; MCP consumes a bounded signed summary for read-only inspection.
