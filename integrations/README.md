# MCP review branch

The supplied `autheo-mcp-agent-trust.patch` applies on the inspected upstream base
`374546e662b953e1fd918456253195f635559fa4` of ThothDivision/autheo-mcp.
A full source sibling `autheo-mcp-agent-trust` is also delivered locally.

Use a separate clean checkout; preserve your existing project and local edits.
Create a review branch, then apply with `git am /path/to/autheo-mcp-agent-trust.patch`.
Install `.[dev,trust]`, run the documented checks, and configure fresh demo exports
only if you want to inspect them through an MCP client. Nothing was automatically
published to GitHub or activated in OpenClaw.
