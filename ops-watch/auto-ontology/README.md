# NVIDIA Auto-Ontology Integration for ops-watch

This directory configures and documents the integration of [NVIDIA Auto-Ontology](https://github.com/NVIDIA/auto-ontology) with `ops-watch` and Antigravity.

## Architecture

```text
+-------------------------------------------------------------+
|                      Antigravity CLI                        |
|  (Subscribed Models: gemini-3.8-flash-medium / Pro)        |
+------------------------------+------------------------------+
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
+-----------------------+             +-----------------------+
|  Operational Memory   |             |  NVIDIA Auto-Ontology |
|  & Background Context |             |  (Semantic Layer)     |
|  (ops-watch.db)       |             |                       |
|  - Precedents         |             |  - Terms & Entities   |
|  - Past Approvals     |             |  - Relationships      |
|  - Operator Notes     |             |  - FastMCP / REST API |
+-----------------------+             +-----------------------+
```

## Agent Skills Installed

The following NVIDIA Auto-Ontology skills have been placed into Antigravity/agent skills directories:
- `nvidia-ontology-setup`: Bring up Auto-Ontology stack via Docker Compose or Helm.
- `nvidia-ontology-management`: Inspect, model, modify, and publish semantic terms and definitions.
- `nvidia-ontology-query`: Run grounded text-to-SQL questions and query semantic definitions via MCP.

Installed locations:
- `.agents/skills/`
- `.gemini/skills/`
- `antigravity-cli/skills/`

## Running Local NVIDIA Auto-Ontology Stack

To launch the full Auto-Ontology stack (PostgreSQL 17 with pgvector, Web UI on port 3000, MCP server on port 3003):

```bash
git clone https://github.com/NVIDIA/auto-ontology.git /Users/hongmartin/orca/projects/linux-machine-4090/ops-watch/auto-ontology/stack
cd /Users/hongmartin/orca/projects/linux-machine-4090/ops-watch/auto-ontology/stack
cp .env.example .env
# Edit .env with your desired passwords and DEFAULT_MODELS_API_KEY
docker compose up -d
```

### FastMCP Server Configuration

For MCP-enabled agents (Cursor, Claude Desktop, Antigravity MCP):
```json
{
  "mcpServers": {
    "auto-ontology": {
      "url": "http://localhost:3003/mcp"
    }
  }
}
```

## CLI Usage in ops-watch

```bash
# Check connection to NVIDIA Auto-Ontology (or local fallback)
python3 ops_watch.py ontology

# Export current security ontology as Apache Ossie / Auto-Ontology standard model
python3 ops_watch.py ontology --export-ossie

# Query operational memory
python3 ops_watch.py memory

# View or update durable worklog
python3 ops_watch.py worklog
python3 ops_watch.py worklog --export

# Record operator decision or rationale into memory
python3 ops_watch.py note 1 "Verified: legitimate student access to personal environment"
```
