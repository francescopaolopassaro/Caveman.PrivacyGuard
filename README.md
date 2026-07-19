# Caveman.PrivacyGuard 🛡️🇪🇺

<img width="638" height="408" alt="Caveman.PrivacyGuard" src="https://github.com/user-attachments/assets/5a8e3193-b7d3-4a41-90e6-e672467ce6cb" />

[![NuGet](https://img.shields.io/nuget/v/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![Downloads](https://img.shields.io/nuget/dt/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![License](https://img.shields.io/github/license/francescopaolopassaro/Caveman.PrivacyGuard.svg)](Caveman.PrivacyGuard/LICENSE)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-blueviolet)](https://dotnet.microsoft.com)
[![.NET Standard 2.0](https://img.shields.io/badge/.NET_Standard-2.0-purple)](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)
[![GDPR Ready](https://img.shields.io/badge/GDPR-Compliant-green)](https://gdpr.eu)

**Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows.**
Detects, scores, and automatically masks sensitive data across **32 countries** (27 EU + UK, Switzerland, China, Russia, Ukraine), with GDPR/AI Act/NIS2/PCI-DSS/NIST compliance mapping and seamless integration with any AI pipeline — including multi-session scenarios for services running multiple chatbots or acting as an AI-provider gateway.

This repository contains three projects:

| Project | Description |
|---|---|
| [`Caveman.PrivacyGuard`](Caveman.PrivacyGuard) | The core library — PII detection, scoring, masking, session restore, compliance flags. Full documentation and API reference: [Caveman.PrivacyGuard/README.md](Caveman.PrivacyGuard/README.md) |
| [`Caveman.PrivacyGuard.Mcp`](Caveman.PrivacyGuard.Mcp) | An MCP (Model Context Protocol) server exposing the library's detection, masking, session-restore, AI-transparency-notice, and prompt-injection-screening features as tools for Claude Code, Cursor, and any MCP-compatible agent. See [Caveman.PrivacyGuard.Mcp/README.md](Caveman.PrivacyGuard.Mcp/README.md) |
| [`Caveman.PrivacyGuard.Demo`](Caveman.PrivacyGuard.Demo) | An interactive console demo (mask/restore round-trip, whitelist, batch dashboard, rule inspection) |

## Quick Start

```bash
dotnet add package Caveman.PrivacyGuard
```

```csharp
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };
var result = analyzer.Analyze("Customer: Mario Rossi, email mario@company.it, IBAN: IT60X0542811101000000123456");

Console.WriteLine(result.MaskedText);
// Customer: Mario Rossi, email [EMAIL], IBAN: [IBAN]
```

Full quick start, session-restore walkthrough, multi-session (multi-chatbot) setup, AI-transparency notices, and the complete API reference live in [Caveman.PrivacyGuard/README.md](Caveman.PrivacyGuard/README.md).

## Highlights

- 🌍 **32 countries**, each with a real algorithmic validator (checksum), not just regex
- 🔐 **Compliance flags** for GDPR, EU AI Act, NIS2, PCI-DSS, NIST 800-53
- 🔄 **Session Restore** — placeholder-based masking so sensitive data never has to leave the client
- 🧑‍🤝‍🧑 **Multi-Session** — `PrivacySessionManager` isolates conversations for multi-chatbot / AI-provider backends
- 🛡️ **Prompt Injection Guard** — heuristic screening of untrusted text before it reaches an LLM's context
- 💬 **AI Transparency Notice** — configurable, localized "you're talking to an AI" disclosure
- ⚙️ **YAML/JSON-driven rules**, loadable from a file, a string, or a remote URL, with hot-reload
- 🧵 Thread-safe, zero required external dependencies, targets both `net8.0` and `netstandard2.0`

See the [CHANGELOG](Caveman.PrivacyGuard/CHANGELOG.md) for full version history.

## ⚠️ Disclaimer

This library is a technical support tool. It does not replace a Data Protection Impact Assessment (DPIA) or the advice of a DPO. GDPR, AI Act, and NIS2 compliance require contextual legal assessment, a documented legal basis, and organizational processes that no library can substitute for.

## Contributing

Fork the repo, add rules to `rules.yaml` + validators to `ValidatorRegistry.cs`, add tests, and open a PR. See [Caveman.PrivacyGuard/README.md](Caveman.PrivacyGuard/README.md#-contributing) for details on adding a new country.

## License

MIT — see [LICENSE](Caveman.PrivacyGuard/LICENSE).

## Technology Partnership

<img src="https://www.digitalsolutions.it/img/partners/novaroutelogo.png" alt="NovaRouteAI" height="180" style="max-width: 100%; height: auto; min-height: 180px; max-height: 190px;">

**[NovaRouteAI](https://novarouteai.com/?ref=synthelion)** — Build with Chinese AI models through one simple API.

NovaRouteAI helps developers and AI SaaS teams test, compare, and run models like DeepSeek, Qwen, Doubao, Kimi, and GLM without managing multiple provider accounts. Start with test credits and optimize your cost per successful task.

[Click here to know NovaRouteAI](https://novarouteai.com/?ref=synthelion)

---

# 🛡️ Protect data, enable AI. Compliance by design.
