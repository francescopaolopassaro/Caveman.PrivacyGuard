# Changelog

## [1.2.1] - 2026-06-01

### Fixed
- 🛑 **Critical: German ID Card false positives** — regex `\b[A-Z0-9]{9}\b` con `RegexOptions.IgnoreCase`
  globale matchava qualsiasi parola di 9 caratteri (es. "francesco", "contratto") come "German ID Card".
  Aggiunto `(?-i)` inline per ripristinare case-sensitivity. (`rules.yaml:135`)

### Added
- Demo: `/restore` comando interattivo per ripristinare placeholder da risposta AI
- Demo: `/roundtrip` demo completa mask → AI → restore client-side

## [1.2.0] - 2026-06-02

### Added
- `ThrowIfDisposed()` — tutti i metodi pubblici lanciano `ObjectDisposedException` esplicito
- `GetWhitelist()` → `IReadOnlySet<string>` — ispezione whitelist
- `IsWhitelisted(value)` → `bool` — test rapido whitelist
- `AnalyzeAsync` — 4 overload con `CancellationToken` per UI/web
- `AnalyzeBatch` / `AnalyzeBatchAsync` — analisi batch di testi
- `PrivacySession.Count` — O(1) count senza copiare il dizionario
- `NormalizeNewlines(StringBuilder)` — zero alloc extra su `\r\n` / `\r`
- `LoadCustomJson` / `LoadCustomJsonFromString` — configurazione JSON
- `WatchConfig` / `StopWatching` / `ConfigReloaded` — hot-reload su file JSON
- `PrivacySession.ToJson` / `FromJson` / `ImportFromJson` — export/persistenza sessioni
- `IReadOnlySession` interfaccia read-only per sessioni
- `PrivacyAnalyzer.Logger` — integrazione `ILogger` per diagnostic
- `PrivacyAnalyzer.ValidateRules()` — validazione regole caricate
- `GetRule()` cache O(1) via `ConcurrentDictionary`
- `netstandard2.0` target — compatibilità framework estesa
- Demo: `/export`, `/validate` comandi

### Fixed
- `Dispose()` crash se lock in uso — `catch(SynchronizationLockException)`, lock lasciato al GC
- Warnings nullable: `ValidatorRegistry.TryGet` out → `Func<string, bool>?`, `ContextKeywords` → `!`
- `System.Index` / `Math.Clamp` / `RegexParseException` incompatibilità netstandard2.0

### Improved
- Demo: header e comandi `/whitelist`, `/rules`, `/export`, `/validate`
- README: documentate tutte le nuove API
- NuGet package version updated to 1.2.0
- `RegexOptions` unificato in `RegexHelper` per multi-target

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
