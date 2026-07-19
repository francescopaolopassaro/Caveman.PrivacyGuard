# Changelog

## [1.2.2] - 2026-07-19

### Added
- 🌍 5 new countries with real algorithmic validators (not just regex): UK NINO (`NINO_GB`), Swiss AHV/AVS (`AHV_CH`), Chinese Resident ID (`ID_CN`, GB 11643-1999 checksum), Russian INN (`INN_RU`, two-stage weighted checksum), Ukrainian RNOKPP (`RNOKPP_UA`)
- 🛡️ NuGet package icon (`caveman-icon.png`) — now packed and referenced via `PackageIcon`
- ⚖️ EU AI Act compliance-flag mapping (Art.5 vulnerable groups, Annex III employment/credit-scoring/justice) alongside existing GDPR/PCI-DSS/NIST tags
- ⚖️ NIS2 Art.21 compliance flag for detected credentials/secrets (cybersecurity risk management relevance)
- `PrivacySessionManager` — thread-safe registry of `PrivacySession` instances keyed by an arbitrary id (conversation/user/tenant), with `GetOrCreate`, `TryGet`, `Remove`, `Clear`, `GetActiveSessionIds`, and `PruneIdleSessions` for bounding memory in services juggling many concurrent chatbot/AI-provider conversations
- `AiTransparencyNotice` — configurable, localized (EN/IT/DE/FR/ES) disclosure message for informing end users they're interacting with an AI system and that sensitive data is masked (supports, but does not by itself guarantee, EU AI Act Art.50 transparency obligations)
- `ChatIntentRouter` — minimal command router for chatbot backends: register named intents/commands with a predicate and handler, route incoming messages before they reach the analyzer
- Demo: `/dashboard` command — aggregate PII stats (category frequency, average score, risk-level distribution) over a multi-country sample batch

### Fixed
- 🛑 Cross-country false positive: the "German ID Card" rule (`\b[A-Z0-9]{9}\b`) matched *any* 9-character alphanumeric string, including a Spanish NIF (`12345678Z`) or the new UK NINO (`AB123456C`). It's now a structurally distinct 1-letter + 8-digit pattern (matching the real Personalausweis shape) with its own checksum validator (`IDCARD_DE`), eliminating the overlap instead of just down-weighting it
- All nullable-reference-type build warnings (CS8604, CS8602, CS8618) across both target frameworks — `net8.0` and `netstandard2.0` now build with zero warnings

### Testing
- 25 new regression tests covering: the 6 new validators (valid + invalid checksum per country), cross-country conflict checks (Swiss/Chinese formats vs. Luxembourg's bare 13-digit rule, German ID Card vs. Spanish NIF/UK NINO), `PrivacySessionManager` isolation and concurrency, `AiTransparencyNotice`, `ChatIntentRouter`, and the new AI Act/NIS2 compliance flags (230/230 total, up from 181)

## [1.2.1] - 2026-06-01

### Fixed
- 🛑 **Critical: German ID Card false positives** — the regex `\b[A-Z0-9]{9}\b` combined with a
  global `RegexOptions.IgnoreCase` matched any 9-character word (e.g. "francesco", "contratto") as
  a "German ID Card". Added an inline `(?-i)` to restore case-sensitivity. (`rules.yaml:135`)

### Added
- Demo: `/restore` interactive command to restore placeholders from an AI response
- Demo: `/roundtrip` full mask → AI → client-side restore demo

## [1.2.0] - 2026-06-02

### Added
- `ThrowIfDisposed()` — all public methods throw an explicit `ObjectDisposedException`
- `GetWhitelist()` → `IReadOnlySet<string>` — whitelist inspection
- `IsWhitelisted(value)` → `bool` — quick whitelist check
- `AnalyzeAsync` — 4 overloads with `CancellationToken` for UI/web
- `AnalyzeBatch` / `AnalyzeBatchAsync` — batch text analysis
- `PrivacySession.Count` — O(1) count without copying the dictionary
- `NormalizeNewlines(StringBuilder)` — zero extra allocation on `\r\n` / `\r`
- `LoadCustomJson` / `LoadCustomJsonFromString` — JSON configuration
- `WatchConfig` / `StopWatching` / `ConfigReloaded` — hot-reload on JSON files
- `PrivacySession.ToJson` / `FromJson` / `ImportFromJson` — session export/persistence
- `IReadOnlySession` read-only interface for sessions
- `PrivacyAnalyzer.Logger` — `ILogger` integration for diagnostics
- `PrivacyAnalyzer.ValidateRules()` — validates loaded rules
- `GetRule()` O(1) cache via `ConcurrentDictionary`
- `netstandard2.0` target — extended framework compatibility
- Demo: `/export`, `/validate` commands

### Fixed
- `Dispose()` crash if the lock was in use — `catch(SynchronizationLockException)`, lock left to the GC
- Nullable warnings: `ValidatorRegistry.TryGet` out → `Func<string, bool>?`, `ContextKeywords` → `!`
- `System.Index` / `Math.Clamp` / `RegexParseException` netstandard2.0 incompatibilities

### Improved
- Demo: header and `/whitelist`, `/rules`, `/export`, `/validate` commands
- README: documented all new APIs
- NuGet package version updated to 1.2.0
- `RegexOptions` unified in `RegexHelper` for multi-targeting

## [1.1.0] - 2026-21-05

### Added
- `PrivacySession` — session-based placeholder mapping for client-side restore
- Unique `[PG_N]` placeholders per occurrence (vs old `[CATEGORY]` format)
- `session.Restore(text)` — replaces placeholders with original values
- `session.RestoreDetailed(text)` — returns restored text + replacement count
- `session.MergeFrom(other)` — merge sessions by original value
- `session.AddOrGet(category, value)` — public placeholder registration
- `analyzer.Analyze(input, session)` — overload with explicit session
- `analyzer.RestoreText(text)` — instance method using `CurrentSession`
- `PrivacyAnalyzer.RestoreText(text, session)` — static helper
- `EnableAutoMasking ? Session : null` — session is null when masking is off

### Fixed
- `CurrentSession` property was ignored by `Analyze()` overloads
- ReaderWriterLockSlim resource leak — `PrivacyAnalyzer : IDisposable`
- `AddEntry` O(n) value lookup → O(1) via secondary `ConcurrentDictionary`
- `Analyze(input, session)` now updates `CurrentSession`

### Improved
- `CompiledRule` record replaces 7-field tuple for readability
- `GetLoadedCategories()` — list all rule categories
- `GetRule(category)` — inspect a loaded rule's regex, weight, etc.
- `RemoveRule(category)` — remove rules by category at runtime
- `LoadCustomYaml(path, replace: true)` — replace rules instead of append
- `ClearRules()` — remove all rules (start from scratch)
- `AddToWhitelist`/`RemoveFromWhitelist`/`ClearWhitelist` — full whitelist lifecycle
- `ValidatorRegistry.Unregister(name)` / `Reset()` — validator lifecycle
- `LoadCustomYamlFromString(yaml)` + `LoadCustomYaml(path)` — fully implemented
- `compliance_tags` from YAML now included in `ComplianceFlags`
- Regex timeout (3s) — defense-in-depth against ReDoS
- Regex parse errors include rule category and country context
- XML doc comments on all public API surfaces
- Demo: `/status` command, session placeholder count display

## [1.0.0] - 2026-05-01

### Added
- 27 EU countries PII detection
- Privacy scoring (0-100) with 5 risk levels
- Auto-masking with `[CATEGORY]` placeholders
- Compliance flags (GDPR, PCI-DSS, NIST 800-53)
- YAML-driven embedded rules
- Multi-language support (EN, IT, DE, FR, ES)
- Context boost scoring
- Whitelist support
- Thread-safe with ReaderWriterLockSlim
- Algorithmic validators (IBAN MOD97, Luhn, national checksums)
- Entropy analysis for confidence scoring
