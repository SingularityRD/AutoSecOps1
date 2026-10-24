<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="img/banner-light.svg">
    <img src="img/banner-light.svg" alt="The AI-native security automation platform." width="85%">
  </picture>
  <p align="center">
    The agentic security automation platform.
  </p>

  <br>
</div>

## Introduction

AutoSecOps is the AI-native security automation platform for teams and AI agents, built and owned by [SingularityRD](https://github.com/SingularityRD). A unified platform with everything AI-native security teams need to build agents and automate cyber defense.

## Core Features

<p align="center">Unlimited agents, cases, lookup tables, and workflows.</p>

<table>
  <tr>
    <td width="50%" valign="top">
      <img src="img/readme/agents.gif" alt="Building an agent preset in AutoSecOps: adding VirusTotal tools with an approval gate, reviewing subagents, attaching a skill, and publishing a new version" width="100%"/>
      <p align="center"><b>Agents and skills</b> — build custom agents with prompts, tools, MCP, subagents, and skills</p>
    </td>
    <td width="50%" valign="top">
      <img src="img/readme/cases.gif" alt="The AutoSecOps case list, then a case with an agent-written verdict, timeline, IoCs, and evidence" width="100%"/>
      <p align="center"><b>Case management</b> — track, automate, and resolve incidents with agents</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="img/readme/workflows.gif" alt="A workflow DAG in the AutoSecOps builder, zoomed out to show every step, then an agent step opened for editing" width="100%"/>
      <p align="center"><b>Workflows</b> — execute deterministic logic with resilience and scale on Temporal</p>
    </td>
    <td width="50%" valign="top">
      <img src="img/readme/tables.gif" alt="AutoSecOps workspace tables, opening an entities table and an entity observations table" width="100%"/>
      <p align="center"><b>Tables</b> — store and query structured data</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="img/readme/mcp.gif" alt="A Claude Code session that calls AutoSecOps MCP tools to list and summarize the open critical cases" width="100%"/>
      <p align="center"><b>AutoSecOps MCP</b> — turn prompts into automations from Claude Code, Codex, Copilot, and more</p>
    </td>
    <td width="50%" valign="top">
      <img src="img/readme/integrations.gif" alt="AutoSecOps credentials, OAuth integrations, and the hosted MCP server catalog" width="100%"/>
      <p align="center"><b>Integrations</b> — 100+ pre-built connectors and 50+ hosted MCP servers for security tools</p>
    </td>
  </tr>
</table>

## Other Highlights

- **Pre-built MCP servers**: 50+ AutoSecOps-hosted MCP servers for security operations
- **MCP client**: connect custom agents to any MCP server (remote HTTP / OAuth or local via `npx` / `uvx` commands)
- **Custom registry**: sync custom Python scripts from your Git repo into AutoSecOps
- **Sandboxed**: run untrusted code and agents within `nsjail` sandboxes or `pid` runtimes
- **Durable execution**: built on [Temporal](https://temporal.io) for resilience and scale
- **Variables**: reuse values across workflows and agents
- **No SSO tax**: SAML / OIDC support
- **Free audit logs**: exportable into your SIEM
- **Deploy anywhere**: self-host with Docker Compose, AWS Fargate, or Kubernetes. Runs fully [air-gapped](https://github.com/SingularityRD/AutoSecOps1/blob/main/docs/self-hosting/air-gapped.mdx).

## Enterprise Features

- **Multi-tenant**: isolate different teams and dev / prod environments into workspaces
- **Fine-grained access control**: RBAC, ABAC, OAuth2.0 scopes for humans and agents
- **Human-in-the-loop**: review and approve sensitive tool calls from a unified inbox, Slack, or email
- **Workspace version control**: sync workflows, agents, and table schemas to GitHub, GitLab, Bitbucket, etc.
- **Metrics and monitoring**: for workflows, agents, and cases

> [!NOTE]
> AutoSecOps is deployed self-hosted on your own infrastructure with Docker Compose, AWS Fargate, or Kubernetes. See the [self-hosting docs](https://github.com/SingularityRD/AutoSecOps1/tree/main/docs/self-hosting).
> Contact [SingularityRD](https://github.com/SingularityRD) for licensing and deployment options.

## Tech Stack

- Backend: Python with FastAPI, SQLAlchemy, Pydantic, uv
- Frontend: Next.js with TypeScript, React Query, Shadcn UI
- Durable workflows and jobs: Temporal
- Sandbox: nsjail
- Database: PostgreSQL
- Object store: S3-compatible

## Contributing

Check out the [Contribution Guide](CONTRIBUTING.md) for development setup and conventions.

## License

AutoSecOps is proprietary software owned by SingularityRD. All rights reserved.
The entire repository, including `packages/tracecat-ee`, is covered by the single SingularityRD proprietary license in [LICENSE](LICENSE).
Use, copying, modification, or distribution requires a written license agreement with SingularityRD.
Third-party components remain under their respective licenses.

<br>

<div align="center">

  <sub>**`AutoSecOps`** &copy; SingularityRD. All rights reserved.</sub>

</div>
