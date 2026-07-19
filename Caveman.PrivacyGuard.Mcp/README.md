# Caveman.PrivacyGuard.Mcp

MCP (Model Context Protocol) server for [Caveman.PrivacyGuard](https://www.nuget.org/packages/Caveman.PrivacyGuard) — exposes PII detection/masking, session-based restore, AI-transparency notices, and prompt-injection screening as MCP tools for Claude Code, OpenCode, Cursor, and any MCP-compatible agent.

## Tools

| Tool | Description |
|------|-------------|
| `analyze_text` | Detects and scores PII/sensitive data (32 countries), returns compliance flags (GDPR/AI Act/NIS2/PCI-DSS/NIST) |
| `mask_text` | Masks sensitive data; pass a `sessionId` to get unique `[PG_N]` placeholders restorable later |
| `restore_text` | Restores original values in a model response, given the `sessionId` used to mask it |
| `check_prompt_injection` | Heuristically screens untrusted text for prompt-injection attempts before it reaches an LLM |
| `get_ai_transparency_notice` | Returns a configurable, localized disclosure that the user is talking to an AI system |

## Usage

Add to your MCP client config (e.g. Claude Code, Cursor):

```json
{
  "mcpServers": {
    "caveman-privacyguard": {
      "command": "dotnet",
      "args": ["path/to/caveman-privacyguard-mcp.dll"]
    }
  }
}
```

Each conversation should use a distinct `sessionId` when calling `mask_text` / `restore_text`, so different conversations never share (or leak into) each other's placeholder mappings — see `PrivacySessionManager` in the core library.

## Disclaimer

`analyze_text`, `check_prompt_injection`, and `get_ai_transparency_notice` are technical aids, not a compliance or security guarantee. GDPR, AI Act, and NIS2 obligations require contextual legal assessment; prompt-injection screening is heuristic and should be one layer among several defenses (system-prompt hardening, output filtering, least-privilege tool access).

## License

MIT — see [LICENSE](https://github.com/francescopaolopassaro/Caveman.PrivacyGuard/blob/main/Caveman.PrivacyGuard/LICENSE).
