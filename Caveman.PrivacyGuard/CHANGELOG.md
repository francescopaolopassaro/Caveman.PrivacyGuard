# Changelog

## [1.4.0] - 2026-10-11

### Added
- **Optional ML confirmation tier.** `IMlEntityDetector`, `MlSpan` and `PrivacyAnalyzer.MlDetector`: a learned detector (the PrivacyGuardML model shipped by the CavemanML package) can confirm a bare value that matches a `requires_context` rule but has no context keyword nearby, when an overlapping span carries the right label (`MlLabelCategories`: a "phone number" span can never confirm an ID rule). **A failed checksum still vetoes the detection** whatever the model says, so the tier can only recover recall the strict gate trades away. Off by default; a detector that throws falls back to regex-only analysis. `PrivacyAnalysisResult.MlAssistedCount` reports how many matches the ML tier confirmed.

## [1.3.1] - 2026-10-11

False-positive hardening ported from Synthelion 1.2.5 (`privacy_analyzer.py`, rules schema 2.1).

### Fixed
- **A bare number in prose was read as national-ID/PII and masked.** Any 7-15 digit run matched Phone E.164, any 8-digit run the Maltese ID, any 9-13 digit run PESEL/OIB/EGN/BSN/etc.; because a modulo-11 checksum passes ~1 in 10 random numbers, even "validated" matches were mostly false positives.
- **Failed checksums were still detected and masked.** A match whose validator returned false still counted toward category, score and `MaskedText`. Only checksum-confirmed matches are detected and masked now.
- **Maltese ID** pattern tightened to the real format (7 digits + trailing letter).
- **Short context keywords match as whole words** (`tel` no longer confirmed by "hotel", `nn` by "annual"); long/multi-word keywords stay substring-based. "nummer" removed from phone keywords.
- Swedish Personal ID validator now accepts the 12-digit form (century dropped) that its own pattern matches.

### Added
- `requires_context` rule field (YAML/JSON, `rules.yaml` version 2.1, `CompiledRule.RequiresContext`): the match counts only when a `context_keywords` term appears within 25 chars of it (and its checksum passes, if any). Applied to every bare numeric rule. A `+`-prefixed phone is E.164 by definition and needs no keyword.
- Phone and credit-card patterns accept one space/dot/dash separator between digits ("+39 333 1234567", "4539 1488 0343 6467").

### Testing
- Existing fixtures used checksum-invalid sample IDs; replaced with valid ones. New tests for bare numbers, failed checksums, `+` phones and whole-word keywords (266/266).

## [1.3.0] - 2026-08-13

Synthelion 1.2.5 streaming & document masking port (Synthelion is the Python port of Caveman.PrivacyGuard's analyzer; this release brings its `privacy_stream.py` / `document_extractor.py` behaviours back into the .NET library, dependency-free).

### Added
- **`PrivacyStreamMasker`** — boundary-safe chunked/streaming PII masking. `Feed(chunk)` appends to an internal tail buffer and returns the masked-safe prefix (everything except the last `overlapChars` characters, default 512, held back so a PII pattern spanning a chunk boundary is still analyzed whole); `Flush()` masks the final remainder once the input is exhausted. Backs both chunked file reads and live stream masking (e.g. an LLM's streamed output). Whitespace-only segments are passed through verbatim instead of being collapsed by the analyzer's empty-text handling.
- **`PrivacyStreamMasker.MaskStream(chunks, ...)`** — convenience helper masking an iterable of chunks, yielding masked pieces as they become safe to emit plus the tail.
- **`PrivacySession.Summary()`** + `SessionSummaryItem` — redacted placeholder+category view that never contains the original value; safe to log, display, or return from an API/CLI response, unlike `GetAll()`/`ToJson()` which carry cleartext PII (their XML docs now warn about exposing them to untrusted parties).
- **`DocumentMasker`** — streaming PII masking for plain text, Markdown and CSV into a `name.masked.ext` copy next to the source (the original file is never overwritten). Files are processed in chunks (<chunk model of `PrivacyStreamMasker`), never loaded whole; CSV rows are read with a minimal RFC-4180-aware reader so quoted multi-line cells survive. Extension-based `DetectFormat`; unrecognized extensions fall back to plain text rather than raising. PDF/DOCX/XLSX (which require optional external libraries in the Python port) are intentionally out of scope to keep the library dependency-free.
- **`DocumentMasker.MaskFile(path, ...)`** returns a `MaskDocumentResult` with the masked copy's path, detected format, and the total PII `MatchCount` (tallied via `PrivacyStreamMasker.OnChunkAnalyzed`).

### Testing
- 12 new regression tests: chunk-boundary masking (PII split across feeds), `MaskStream`, whitespace passthrough, redacted `Summary()` (property shape + no cleartext), `DetectFormat`, txt/md/csv masking (row structure preserved, source untouched), quoted multi-line CSV cells, and missing-source error handling (259/259 total, up from 247).

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
