# Release Notes — Caveman.PrivacyGuard

Latest release: **v1.2.2**

> Cumulative summary of all changes from v1.0.0 to v1.2.2. See [Caveman.PrivacyGuard/CHANGELOG.md](Caveman.PrivacyGuard/CHANGELOG.md) for the canonical, version-by-version changelog shipped inside the NuGet package.

---

## v1.2.2 (2026-07-19) — New Countries, AI Act/NIS2 Compliance, Multi-Session, MCP Server

### 🆕 Added

- 🌍 5 new countries, each with a real algorithmic validator (not just regex): UK NINO, Swiss AHV/AVS, Chinese Resident ID (GB 11643-1999 checksum), Russian INN (two-stage weighted checksum), Ukrainian RNOKPP — bringing total coverage to 32 countries
- 🛡️ NuGet package icon restored — `caveman-icon.png` is now packed and referenced via `PackageIcon`
- ⚖️ EU AI Act compliance-flag mapping (Art.5 vulnerable groups, Annex III employment/credit-scoring/justice) and NIS2 Art.21 flag for detected credentials/secrets, alongside the existing GDPR/PCI-DSS/NIST tags
- `PrivacySessionManager` — thread-safe registry of `PrivacySession` instances keyed by an arbitrary id (conversation/user/tenant), with idle-session pruning, for services running multiple chatbots or acting as an AI-provider gateway with many concurrent conversations
- `AiTransparencyNotice` — configurable, localized (EN/IT/DE/FR/ES) disclosure informing end users they're interacting with an AI system and that sensitive data is masked
- `ChatIntentRouter` — minimal command router for chatbot backends, routing commands (e.g. `/reset`) before they reach the analyzer
- `PromptInjectionGuard` — heuristic scanner for prompt-injection attempts (instruction override, system-prompt exfiltration, role-hijack/jailbreak framing, delimiter injection, credential-exfiltration coercion) in untrusted text before it reaches an LLM
- `LoadCustomYamlFromUrlAsync` — load detection rules from a remote YAML source
- `AnalyzeStreamAsync` — stream analysis results one at a time for large batches or progressive UI updates
- **Caveman.PrivacyGuard.Mcp** — a new MCP (Model Context Protocol) server project exposing `analyze_text`, `mask_text`, `restore_text`, `check_prompt_injection`, and `get_ai_transparency_notice` as tools for Claude Code, Cursor, and any MCP-compatible agent
- Demo: `/dashboard` command — aggregate PII stats (category frequency, average score, risk-level distribution) over a multi-country sample batch

### 🐛 Fixed

- 🛑 Cross-country false positive: the "German ID Card" rule matched *any* 9-character alphanumeric string, including a Spanish NIF or the new UK NINO. It's now a structurally distinct 1-letter + 8-digit pattern with its own checksum validator, eliminating the overlap instead of just down-weighting it
- All nullable-reference-type build warnings across both target frameworks — `net8.0` and `netstandard2.0` now build with zero warnings

### 🧪 Testing

- 67 new regression tests (248/248 total, up from 181) covering the new validators, cross-country conflict checks, session-manager isolation/concurrency, transparency notice, intent router, prompt-injection guard, remote YAML loading, and result streaming

---

## v1.2.1 (2026-06-01) — Critical Bugfix Hotfix

### 🛑 Fixed

- **Critical: German ID Card false positives** — the pattern `\b[A-Z0-9]{9}\b` combined with a global `RegexOptions.IgnoreCase` caused false positives on **any 9-character word** (e.g. "francesco", "contratto", "password"), misclassifying it as a "German ID Card". Added an inline `(?-i)` to restore case-sensitivity.

### 🆕 Added

- Demo: `/restore` command — interactive restoration of placeholders from an AI response
- Demo: `/roundtrip` command — full demonstration of the mask → AI → client-side restore flow

---

## v1.2.0 (2026-06-02) — Session Persistence & JSON Config

### 🆕 New Features

- `ThrowIfDisposed()` — all public methods throw an explicit `ObjectDisposedException`
- `GetWhitelist()` → `IReadOnlySet<string>` — whitelist inspection
- `IsWhitelisted(value)` → `bool` — quick whitelist check
- `AnalyzeAsync` — 4 overloads with `CancellationToken` for UI/web
- `AnalyzeBatch` / `AnalyzeBatchAsync` — in-memory batch analysis
- `PrivacySession.Count` — O(1) count without copying the dictionary
- `NormalizeNewlines(StringBuilder)` — zero extra allocation on `\r\n` / `\r`
- `LoadCustomJson` / `LoadCustomJsonFromString` — rule loading from JSON
- `WatchConfig` / `StopWatching` / `ConfigReloaded` — hot-reload on JSON files
- `PrivacySession.ToJson` / `FromJson` / `ImportFromJson` — session export/persistence
- `IReadOnlySession` — read-only interface for sessions
- `PrivacyAnalyzer.Logger` — `ILogger` integration for diagnostics
- `PrivacyAnalyzer.ValidateRules()` — validates loaded rules
- `GetRule()` — O(1) cache via `ConcurrentDictionary`
- `netstandard2.0` target — extended .NET Framework compatibility
- Demo: `/export`, `/validate` commands

### 🐛 Fixed

- `Dispose()` — crash if the lock was in use: `catch(SynchronizationLockException)`, lock left to the GC
- Nullable warnings: `ValidatorRegistry.TryGet` → `Func<string, bool>?`, `ContextKeywords` → `!`
- `System.Index` / `Math.Clamp` / `RegexParseException` — netstandard2.0 incompatibilities resolved

### 🔧 Improved

- Demo: new `/whitelist`, `/rules`, `/export`, `/validate` commands
- `RegexHelper` unified class for multi-targeting
- `RegexOptions` harmonized between net8.0 and netstandard2.0

---

## v1.1.0 (2026-05-21) — Placeholder Session System

### 🆕 New Features

- **`PrivacySession`** — session-based mapping from placeholder to original values
- **Unique `[PG_N]` placeholders** — replaces the old `[CATEGORY]` format, enabling client-side restore
- `session.Restore(text)` — restores original values in an AI response
- `session.RestoreDetailed(text)` — restore with a replacement count
- `session.MergeFrom(other)` — merge sessions by original value
- `session.AddOrGet(category, value)` — public placeholder registration
- `analyzer.Analyze(input, session)` — overload with an explicit session
- `analyzer.RestoreText(text)` — instance method on `CurrentSession`
- `PrivacyAnalyzer.RestoreText(text, session)` — static helper
- `EnableAutoMasking ? Session : null` — session is null when masking is disabled

### 🐛 Fixed

- `CurrentSession` — property was ignored by `Analyze()` overloads
- `ReaderWriterLockSlim` — resource leak; `PrivacyAnalyzer` now implements `IDisposable`
- `AddEntry` — O(n) lookup → O(1) via a secondary `ConcurrentDictionary`
- `Analyze(input, session)` — now correctly updates `CurrentSession`

### 🔧 Improved

- `CompiledRule` — record type replaces a 7-field tuple
- `GetLoadedCategories()` / `GetRule(category)` / `RemoveRule(category)` — rule lifecycle
- `LoadCustomYaml(path, replace: true)` — replace rules instead of appending
- `ClearRules()` — removes all rules
- `AddToWhitelist` / `RemoveFromWhitelist` / `ClearWhitelist` — full whitelist lifecycle
- `ValidatorRegistry.Unregister(name)` / `Reset()` — validator lifecycle
- `LoadCustomYamlFromString(yaml)` / `LoadCustomYaml(path)` — fully implemented
- `compliance_tags` from YAML now included in `ComplianceFlags`
- 3-second regex timeout — defense-in-depth against ReDoS
- Regex parse errors include rule category and country context
- XML doc comments on all public API surfaces
- Demo: `/status` command with placeholder count display

---

## v1.0.0 (2026-05-01) — Initial Release

### 🆕 Added

- 27 EU countries, PII detection
- Privacy scoring (0-100) with 5 risk levels
- Auto-masking with `[CATEGORY]` placeholders
- Compliance flags (GDPR, PCI-DSS, NIST 800-53)
- YAML-driven embedded rules
- Multi-language support (EN, IT, DE, FR, ES)
- Context-boost scoring
- Whitelist support
- Thread-safe with `ReaderWriterLockSlim`
- Algorithmic validators (IBAN MOD97, Luhn, national checksums)
- Entropy analysis for confidence scoring

---

## Installation

```bash
dotnet add package Caveman.PrivacyGuard --version 1.2.2
```

## Links

- **NuGet:** https://www.nuget.org/packages/Caveman.PrivacyGuard
- **GitHub:** https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
- **License:** MIT
