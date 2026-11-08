# Caveman.PrivacyGuard 🛡️🇪🇺

<img width="638" height="408" alt="Gemini_Generated_Image_tnxoi9tnxoi9tnxo" src="https://github.com/user-attachments/assets/5a8e3193-b7d3-4a41-90e6-e672467ce6cb" />

[![NuGet](https://img.shields.io/nuget/v/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![Downloads](https://img.shields.io/nuget/dt/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![License](https://img.shields.io/github/license/francescopaolopassaro/Caveman.PrivacyGuard.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-blueviolet)](https://dotnet.microsoft.com)
[![.NET Standard 2.0](https://img.shields.io/badge/.NET_Standard-2.0-purple)](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)
[![GDPR Ready](https://img.shields.io/badge/GDPR-Compliant-green)](https://gdpr.eu)

> **Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows**
> Detects, scores, and automatically masks sensitive data across **32 countries** (27 EU + UK, Switzerland, China, Russia, Ukraine), with risk scoring, GDPR/AI Act/NIS2/PCI-DSS/NIST compliance mapping, and seamless integration with any AI pipeline — including multi-session scenarios (multiple chatbots/conversations running in parallel).

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🌍 **32 Countries** | Native patterns for all 27 EU countries (IT, DE, FR, ES, PL, NL, SE, FI, DK, AT, BE, PT, IE, GR, CZ, RO, HU, BG, HR, SK, SI, LT, LV, EE, CY, MT, LU) + generic EU rules, plus **UK, Switzerland, China, Russia, Ukraine** |
| 🔍 **Heuristic Detection** | Precompiled regex + algorithmic validators (Luhn, IBAN MOD97, national checksums) + Shannon entropy analysis |
| 📊 **Privacy Score** | 0-100 score with levels: `Safe` → `Low` → `Medium` → `High` → `Critical` |
| 🎭 **Auto-Masking** | Dynamic replacement with contextual placeholders (`[EMAIL]`, `[IBAN]`, `[CF_IT]`, etc.) |
| ⚙️ **YAML-Driven** | Configurable rules in an embedded `rules.yaml`, extensible at runtime |
| 🔐 **Compliance Flags** | Automatic mapping to GDPR, EU AI Act, NIS2, PCI-DSS, NIST 800-53, national authorities (CNIL, BfDI, AEPD, etc.) |
| 🧵 **Thread-Safe** | Ready for high-throughput microservices with `ReaderWriterLockSlim` and a regex cache |
| 🔄 **Session Restore** | Unique `[PG_N]` placeholders per occurrence, client-side restoration of original data in AI responses, zero sensitive data sent to the LLM |
| ✂️ **Dynamic Rules** | Load/unload/inspect rules at runtime: `LoadCustomYaml`, `RemoveRule()`, `GetRule()`, `GetLoadedCategories()` |
| 🧹 **Whitelist Lifecycle** | `AddToWhitelist`, `RemoveFromWhitelist`, `ClearWhitelist`, `GetWhitelist`, `IsWhitelisted` |
| 🔌 **Extensible Validators** | Register, remove, or reset custom validators via `ValidatorRegistry.Register` / `Unregister` / `Reset` |
| ⚡ **Async API** | `AnalyzeAsync` with 4 overloads + `CancellationToken` for UI/web |
| 🔌 **JSON Config** | `LoadCustomJson` / `LoadCustomJsonFromString` with hot-reload (`WatchConfig` / `ConfigReloaded`) |
| 💾 **Session Export** | `ToJson` / `FromJson` / `ImportFromJson` for placeholder persistence |
| 🔍 **IReadOnlySession** | Read-only interface for public APIs that must not mutate the session |
| ✅ **ValidateRules** | Public method to validate all loaded rules |
| 🛡️ **Safe Dispose** | `ThrowIfDisposed()` on all public methods, graceful `catch(SynchronizationLockException)` |
| 🪵 **ILogger** | Integration with `Microsoft.Extensions.Logging.Abstractions` for diagnostics |
| 📋 **CHANGELOG** | Version history shipped inside the NuGet package |
| 🌐 **.NET Standard 2.0** | Compatible with legacy .NET frameworks |
| 🧑‍🤝‍🧑 **Multi-Session** | `PrivacySessionManager` isolates sessions per conversation/user/tenant — built for backends running multiple chatbots or an AI provider handling many concurrent conversations |
| 💬 **AI Transparency Notice** | `AiTransparencyNotice` — a configurable, localized (EN/IT/DE/FR/ES) message informing users they're talking to an AI system and that sensitive data is masked |
| 🧭 **Chat Intent Router** | `ChatIntentRouter` — routes bot commands (e.g. `/reset`, `/help`) before the text reaches the analyzer |
| 🚀 **Performance** | `RegexOptions.NonBacktracking` (.NET 10), precompilation, O(1) cache, zero redundant allocations, 3s anti-ReDoS timeout |

---

## 📦 Installation

```bash
dotnet add package Caveman.PrivacyGuard
```
## 🚀 Quick Start
Warning Mode (Default)

```csharp
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

// 🔹 Default: English
var resEn = analyzer.Analyze("CF: RSSMRA80A01H501U, email: test@x.com");
Console.WriteLine($"[EN] Risk: {resEn.RiskLevel}\n{resEn.WarningMessage}");

// 🔹 Overload: Italian
var resIt = analyzer.Analyze("CF: RSSMRA80A01H501U, email: test@x.com", "it");
Console.WriteLine($"[IT] Risk: {resIt.RiskLevel}\n{resIt.WarningMessage}");

// 🔹 Overload: German
var resDe = analyzer.Analyze("Steuer-ID: 12345678901, IBAN: DE89370400440532013000", "de");
Console.WriteLine($"[DE] Risk: {resDe.RiskLevel}\n{resDe.WarningMessage}");
```
Output:

```bash
🔒 Score: 26/100
⚠️  Warning: ⛔ Data detected: Italian Tax Code (CF), Email. Pseudonymization mandatory.
✅ Safe for AI: False
```

```csharp
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

var text = "Customer: Mario Rossi, email mario@company.it, IBAN: IT60X0542811101000000123456";
var result = analyzer.Analyze(text);

Console.WriteLine($"🛡️  Text safe for LLM:\n{result.MaskedText}");
```

Output:

```bash
🛡️  Text safe for LLM:
Customer: Mario Rossi, email [EMAIL], IBAN: [IBAN]
```

## 🪄 Session Restore — Zero Sensitive Data to the LLM

The core value proposition: sensitive data **never leaves the client**. The flow is:

1. **Mask** — `PrivacyAnalyzer` detects PII and replaces it with unique placeholders `[PG_1]`, `[PG_2]`, etc.
2. **Send** — The masked text (no real data) is sent to the LLM
3. **Restore** — The LLM's response is processed by `PrivacySession.Restore()`, which restores the original values **client-side**

```csharp
var session = new PrivacySession();
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

// 1. Analyze and mask (the real data only lives in the session)
var result = analyzer.Analyze(
    "Mario Rossi, email mario@company.it, IBAN: IT60X0542811101000000123456",
    "en", session);

Console.WriteLine(result.MaskedText);
// Output: Mario Rossi, email [PG_1], IBAN: [PG_2]

// 2. Send result.MaskedText to the LLM...
var aiResponse = "Contact the customer via [PG_1] regarding the charge on [PG_2]";

// 3. Restore client-side (no sensitive data ever left the client)
var safeResponse = session.Restore(aiResponse);
Console.WriteLine(safeResponse);
// Output: Contact the customer via mario@company.it regarding the charge on IT60X0542811101000000123456
```

### API Reference

```csharp
// Create a new session
var session = new PrivacySession();

// Analyze with a session (unique [PG_N] placeholders)
var result = analyzer.Analyze(input, "en", session);

// Or via the CurrentSession property
analyzer.CurrentSession = new PrivacySession();
var result = analyzer.Analyze(input);

// Restore an AI response
string restored = session.Restore(aiResponseText);

// Inspect the generated placeholders
foreach (var entry in session.GetAll())
    Console.WriteLine($"{entry.Key} → {entry.Value.OriginalValue} ({entry.Value.Category})");

// Get a single mapping
var entry = session.GetEntry("[PG_1]");

// Manually add a placeholder (public)
session.AddOrGet("Email", "manual@test.com");

// Merge another session (skips duplicates by value)
session.MergeFrom(anotherSession);

// Reset the session
session.Clear();

// Static method on PrivacyAnalyzer
string restored = PrivacyAnalyzer.RestoreText(aiResponse, session);

// Instance method (uses CurrentSession)
analyzer.CurrentSession = session;
string restored2 = analyzer.RestoreText(aiResponse);
```

> **Note:** Without a session (`Analyze(input)` or `Analyze(input, lang)`), masking uses the textual placeholders `[EMAIL]`, `[IBAN]`, etc. as before.

### Countries Covered

| **Code**  | **Country** | **Main Identifiers** | **Reference Authority**      |
|-------------|-------------|-------------------------------|----------------------------------|
| **🇮🇹 IT** | Italy       | Tax Code (CF), VAT Number     | Garante Privacy, Revenue Agency |
| **🇩🇪 DE** | Germany     | Tax ID, ID Card               | BfDI, GDPR                       |
| **🇫🇷 FR** | France      | NIR/SSN, SIREN/SIRET          | CNIL, GDPR                       |
| **🇪🇸 ES** | Spain       | NIF/NIE                       | AEPD, GDPR                       |
| **🇵🇱 PL** | Poland      | PESEL, NIP                    | UODO, GDPR                       |
| **🇳🇱 NL** | Netherlands | BSN                           | AP, GDPR                         |
| **🇸🇪 SE** | Sweden      | Personnummer                  | IMY                              |
| **🇫🇮 FI** | Finland     | Henkilötunnus (HETU)          | Data Protection Ombudsman        |
| **🇩🇰 DK** | Denmark     | CPR                           | Datatilsynet                     |
| **🇦🇹 AT** | Austria     | Social Insurance No., VAT ID  | DSB                               |
| **🇧🇪 BE** | Belgium     | National Registry Number      | APD                               |
| **🇵🇹 PT** | Portugal    | NIF                           | CNPD                              |
| **🇮🇪 IE** | Ireland     | PPSN                          | DPC                               |
| **🇬🇷 GR** | Greece      | AFM, AMKA                     | HDPA                              |
| **🇨🇿 CZ** | Czechia     | Birth Number                  | ÚOOÚ                              |
| **🇷🇴 RO** | Romania     | CNP                           | ANSPDCP                           |
| **🇭🇺 HU** | Hungary     | Tax ID                        | NAIH                              |
| **🇧🇬 BG** | Bulgaria    | EGN                           | CPDP                              |
| **🇭🇷 HR** | Croatia     | OIB                           | AZOP                              |
| **🇸🇰 SK** | Slovakia    | Birth Number                  | ÚOOÚ                              |
| **🇸🇮 SI** | Slovenia    | EMŠO                          | IP                                |
| **🇱🇹 LT** | Lithuania   | Personal Code                 | VDAI                              |
| **🇱🇻 LV** | Latvia      | Personal Code                 | DVI                               |
| **🇪🇪 EE** | Estonia     | Isikukood                     | AKI                               |
| **🇨🇾 CY** | Cyprus      | ID Number                     | CIPD                              |
| **🇲🇹 MT** | Malta       | ID Number                     | IDPC                              |
| **🇱🇺 LU** | Luxembourg  | National ID Number            | CNPD                              |
| **🇬🇧 GB** | United Kingdom | National Insurance Number (NINO) | ICO                        |
| **🇨🇭 CH** | Switzerland | AHV/AVS Number                | FDPIC                             |
| **🇨🇳 CN** | China       | Resident ID Number            | CAC (PIPL)                        |
| **🇷🇺 RU** | Russia      | Taxpayer ID (INN)             | Roskomnadzor                      |
| **🇺🇦 UA** | Ukraine     | Taxpayer Number (RNOKPP)      | State Data Protection Service     |

## 🧑‍🤝‍🧑 Multi-Session: Multiple Chatbots / AI Providers

If your service juggles many concurrent conversations — several chatbot instances, or an AI-provider-facing gateway serving many users — `PrivacySessionManager` keeps each conversation's placeholder mapping isolated, so one conversation can never leak another's data.

```csharp
var sessions = new PrivacySessionManager();
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

// Each conversation gets (and reuses) its own isolated session
var chat1 = sessions.GetOrCreate("conversation-123");
var chat2 = sessions.GetOrCreate("conversation-456");

var r1 = analyzer.Analyze("email alice@example.com", "en", chat1);
var r2 = analyzer.Analyze("email bob@example.com", "en", chat2);

// chat1 can only restore its own placeholders — chat2's data never crosses over
var restored = chat1.Restore(r1.MaskedText);

// Periodically bound memory usage in long-running services:
int removed = sessions.PruneIdleSessions(TimeSpan.FromMinutes(30));
```

## 💬 AI Transparency Notice & 🧭 Chat Intent Router

For chatbot/assistant use cases, `AiTransparencyNotice` gives you a ready-to-display, configurable disclosure that the user is talking to an AI system and that their data is screened/masked — a technical aid toward the transparency expectations of EU AI Act Art.50 for limited-risk AI systems (whether it fully satisfies your specific obligations depends on your use case and should be confirmed with legal counsel).

```csharp
var notice = new AiTransparencyNotice { Language = "en" }; // or "it", "de", "fr", "es"
Console.WriteLine(notice.GetMessage());
// "You are interacting with an AI system. Your messages are screened locally and any
//  personal or sensitive data is masked before being sent to the AI model (EU AI Act
//  Art.50 transparency notice)."

// Disable it, or supply your own wording:
notice.Enabled = false;
notice.CustomMessage = "Custom disclosure text for your organization.";
```

`ChatIntentRouter` lets you register bot commands (e.g. `/reset`, `/help`) and route them before the text ever reaches the analyzer:

```csharp
var router = new ChatIntentRouter();
router.RegisterCommand("/reset", _ => session.Clear());
router.RegisterCommand("/help", _ => ShowHelp());

var matchedIntent = router.TryRoute(userInput);
if (matchedIntent is null)
{
    // No command matched: treat userInput as regular content to analyze/mask.
    var result = analyzer.Analyze(userInput, "en", session);
}
```

## Streaming & Document Masking (v1.3.0)

### Boundary-Safe Stream Masking

`PrivacyStreamMasker` masks PII in incrementally-arriving text (a chunked file read, or a live LLM stream) without loading the whole input. It keeps a tail buffer of `overlapChars` (default 512) so a match that spans a chunk boundary is still analyzed whole.

```csharp
var masker = new PrivacyStreamMasker(session: session, language: "en", overlapChars: 512);
foreach (var chunk in ReadInChunks(path))
    Console.Write(masker.Feed(chunk));   // masked-safe prefix as it becomes safe
Console.Write(masker.Flush());           // final remainder

// Or, for an in-memory iterable:
var masked = string.Concat(PrivacyStreamMasker.MaskStream(chunks, session));
```

### Redacted Session Summary

`PrivacySession.Summary()` returns placeholder + category only — never the original value — so it is safe to log, display, or return from an API/CLI response. `GetAll()` / `ToJson()` carry the cleartext PII; keep them server-side only.

```csharp
foreach (var item in session.Summary())   // SessionSummaryItem { Placeholder, Category }
    Console.WriteLine($"{item.Placeholder}: {item.Category}");
```

### Document Masking (txt / Markdown / CSV)

`DocumentMasker.MaskFile` streams a file in chunks and writes a masked copy to `name.masked.ext` next to the source — the original file is never overwritten. CSV rows are read with a minimal RFC-4180-aware reader so quoted multi-line cells survive.

```csharp
var result = DocumentMasker.MaskFile("contacts.csv", session: session);
// result.OutputPath → "contacts.masked.csv", result.MaskedMatchCount → total PII matches
```

## Fewer false positives, and an optional ML tier (v1.3.1 / v1.4.0)

**A bare number in prose is not PII.** Since 1.3.1 a match only counts when it is *confirmed*: a value that fails its checksum is never detected or masked, and a rule marked `requires_context` (every bare numeric format: phone, PESEL, BSN, OIB, CNP, ...) additionally needs one of its `context_keywords` within 25 characters - short keywords match as whole words, so `tel` is not confirmed by "hotel". A `+`-prefixed number is E.164 by definition and needs no keyword. Structurally anchored rules (e-mail, IBAN, codice fiscale, NINO, ...) are unaffected.

**Optional learned confirmation (1.4.0).** `PrivacyAnalyzer.MlDetector` accepts any `IMlEntityDetector`; the [`CavemanML`](https://www.nuget.org/packages/CavemanML) package ships *PrivacyGuardML*, a small offline model that recognises PII by shape and context:

```csharp
using var analyzer = new PrivacyAnalyzer { MlDetector = await PrivacyGuardMLDetector.LoadAsync() };
var r = analyzer.Analyze("ssn 123-45-6789 lo trovi nel file");   // r.MlAssistedCount == 1
```

The model is only a *confirmation signal*: it can recover a bare value the context gate rejected (when an overlapping span has the right label), it can **never** override a failed checksum, and without a detector nothing changes.

## Evolutive in 1.5.0: anti-triggers and wider detection

### Negative context - fewer false positives on numbers

A bare number is confirmed by a context keyword ("tel", "cellulare", "iban"...). That is not enough when a *label of
another kind* is closer to the number: in "numero fattura 3389123456" the word "numero" is a phone keyword, but the
digits are an invoice number. 1.5.0 adds **anti-triggers**: words such as *invoice, order, article code, protocol,
serial, SKU, tracking, reference, batch, year* (in 8 languages: Italian, English, French, German, Spanish, Portuguese, Dutch, Polish) mark a nearby number as a non-personal identifier.

How the decision is taken for a bare numeric candidate:

1. The words **before** the number decide first (labels precede values: "codice articolo 123", "telefono 333...").
   A keyword of the rule wins a tie ("codice fiscale 123": "fiscale" is as close as "codice").
2. If nothing precedes it, the words after it are compared the same way.
3. If an anti-trigger is closer than every context keyword, the candidate is rejected.

A trailing remark does not cancel a real label: "numero di telefono 3389123456, anno 2024" is still a phone.
A `+`-prefixed international number is never vetoed.

| Text | Result |
| :--- | :--- |
| `Per problemi chiamami al cellulare 3389123456` | masked (phone) |
| `Il mio numero di telefono è 3389123456, anno 2024` | masked (phone) |
| `Il codice articolo del prodotto è 3389123456` | kept |
| `numero fattura 3389123456` | kept |
| `Ordine n. 3389123456 numero spedizione` | kept |

```csharp
var analyzer = new PrivacyAnalyzer();
analyzer.UseNegativeContext = true;                       // default
analyzer.AddNegativeKeywords("pratica interna", "badge"); // your own labels
```

Rules can carry their own words in YAML or JSON, and a document can extend the global set:

```yaml
global_negative_keywords: ["badge", "ticket"]
countries:
  - code: "IT"
    rules:
      - category: "Internal Phone"
        pattern: '\b\d{4}\b'
        requires_context: true
        context_keywords: ["interno"]
        negative_keywords: ["stanza", "piano"]
```

### New and corrected detections

| Category | What is detected | Notes |
| :--- | :--- | :--- |
| IBAN (printed form) | `IT60 X054 2811 1010 0000 0123 456`, with space, dot or dash groups | Consumes exactly the ISO 13616 length of the country, so it never swallows the next word nor stops halfway; mod-97 decides |
| Credit Card | `4111.1111.1111.1111` and the other separators | Luhn checksum still required |
| Phone E.164 | Landlines starting with 0 (`010-2471234`) are masked whole | More keywords: cellulare, whatsapp, chiamami, handy, móvil, celular... |
| IP Address | IPv4, CIDR (`/24`) and ranges (`a.b.c.d-e.f.g.h`) | Octets 0-255, so `2.3.55.987` is a version; needs a network keyword (ip, server, host, rete...) |
| URL | `https://...`, `www.`, and bare domains with a known TLD | Trailing punctuation is not part of the URL; the domain of an e-mail address is not a second URL |
| Monetary Amount | `EUR 1234,56`, `1.234,56 euro`, `50 €` | A long bare number followed by "euro" is not an amount |
| Date of Birth | `06-11-2014` | Only next to a birth keyword (nato, born, geboren, née...) |
| Document Protocol Number | `Prot. n. 456/2024`, `Rep. 12/2023`, `protocollo 2024/55` | The label is required |
| Italian VAT Number | `P.IVA 00743110157` with or without `IT` | The checksum weights were wrong and rejected valid numbers; the bare-number pattern could not match |

Use `analyzer.RemoveRule("URL")` (or `RemoveRule("Monetary Amount")`) when your use case does not treat a category
as sensitive.

Targets: **.NET 10** and netstandard2.0.

## ⚙️ Advanced Configuration

### Whitelist (Safe Exclusions)

```csharp
analyzer.AddToWhitelist(
    "test@company.eu",      // Test email
    "127.0.0.1",             // Localhost IP
    "IT00000000000"         // Dummy VAT number
);

// Removal and reset
analyzer.RemoveFromWhitelist("test@company.eu");
analyzer.ClearWhitelist();  // removes all exclusions

// Inspection
var all = analyzer.GetWhitelist();     // IReadOnlySet<string>
if (analyzer.IsWhitelisted("127.0.0.1"))
    Console.WriteLine("IP is whitelisted");
```

### Custom Validators

```csharp
// Register a new validator for a custom national format
ValidatorRegistry.Register("MY_CUSTOM_ID", value =>
    value.Length == 10 && value.StartsWith("XYZ") && value.All(char.IsDigit));

// Remove an existing validator
ValidatorRegistry.Unregister("MY_CUSTOM_ID");

// Reset all validators to the built-in defaults (removes custom ones)
ValidatorRegistry.Reset();
```

### Runtime Rule Inspection & Management

```csharp
// List all currently loaded rule categories
var categories = analyzer.GetLoadedCategories();

// Inspect a specific rule (regex, weight, validator, etc.)
var emailRule = analyzer.GetRule("Email");
Console.WriteLine(emailRule.Pattern);   // compiled regex
Console.WriteLine(emailRule.BaseWeight); // weight

// Remove all rules for a category
analyzer.RemoveRule("Email");

// Clear ALL rules (embedded + custom)
analyzer.ClearRules();
```

### Resource Disposal

`PrivacyAnalyzer` implements `IDisposable` to release its `ReaderWriterLockSlim`. All public methods throw `ObjectDisposedException` if called after disposal:

```csharp
using var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };
var result = analyzer.Analyze("test@example.com");
// analyzer.Dispose() is called automatically on exiting the using block
```

### Async Analysis

For UI or web applications, `AnalyzeAsync` runs the analysis on the thread pool and supports `CancellationToken`:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

try
{
    var result = await analyzer.AnalyzeAsync(
        "Email: test@example.com, IBAN: IT60X0542811101000000123456",
        cts.Token);

    Console.WriteLine($"Score: {result.Score}");
}
catch (OperationCanceledException)
{
    Console.WriteLine("Analysis cancelled due to timeout.");
}
```

Available overloads: `AnalyzeAsync(input)`, `AnalyzeAsync(input, session, ct)`, `AnalyzeAsync(input, language, ct)`, `AnalyzeAsync(input, language, session, ct)`.

### External and Dynamic YAML

```csharp
// Load rules from a file (added to the embedded ones)
analyzer.LoadCustomYaml("path/to/custom-rules.yaml");

// Load rules from a YAML string (useful for DB/remote config)
var yaml = @"
version: ""2.0""
countries:
  - code: ""XX""
    rules:
      - category: ""CustomPII""
        pattern: '\bSENSITIVE_\w+\b'
        base_weight: 20
        compliance_tags: [""GDPR Art.4(1)""]";
analyzer.LoadCustomYamlFromString(yaml);
```

### Compliance Tags from YAML

Compliance flags (`compliance_tags` in the YAML) are automatically collected and merged with the hardcoded ones. You can add custom tags per rule:

```yaml
- category: "MyCustomID"
  pattern: '\bMY_\d{6}\b'
  base_weight: 15
  compliance_tags: ["GDPR Art.4(1)", "Internal Policy #42"]
```

### JSON Config and Hot-Reload

Besides YAML, JSON configuration with automatic hot-reload is also supported:

```csharp
// Load rules from a JSON file
analyzer.LoadCustomJson("path/to/custom-rules.json");

// Load from a string
var json = @"{
  ""version"": ""2.0"",
  ""countries"": [
    { ""code"": ""XX"", ""rules"": [
      { ""category"": ""CustomPII"", ""pattern"": ""\\bSENSITIVE_\\w+\\b"", ""base_weight"": 20 }
    ]}
  ]
}";
analyzer.LoadCustomJsonFromString(json);

// Hot-reload: watch the file and reload automatically
analyzer.WatchConfig("path/to/custom-rules.json");

// Event fired after every reload
analyzer.ConfigReloaded += (s, e) => Console.WriteLine("⚡ Config reloaded!");

// Stop the watcher
analyzer.StopWatching();
```

### Rule Validation

Check that all loaded rules are valid (no exceptions during matching):

```csharp
if (analyzer.ValidateRules())
    Console.WriteLine("✅ All rules are valid");
else
    Console.WriteLine("❌ Invalid rules found");
```

### ILogger Integration

Attach a logger for diagnostics during analysis and configuration:

```csharp
analyzer.Logger = myLogger;  // ILogger<PrivacyAnalyzer>
// Logged events: detected categories, high scores, configuration loads
```

### Session Export and Persistence

Export and import sessions as JSON to save/restore state across requests:

```csharp
var session = new PrivacySession();
session.AddEntry("Email", "test@example.com");

// Export
string json = session.ToJson();

// Reconstruct
var restored = PrivacySession.FromJson(json);

// Import into an existing session
existingSession.ImportFromJson(json);
```

### IReadOnlySession

A safe read-only API for public exposure:

```csharp
IReadOnlySession readOnly = session;
int count = readOnly.Count;
var entry = readOnly.GetEntry("[PG_1]");
string text = readOnly.Restore(aiResponse);
```

## 🔐 Compliance & GDPR

`PrivacyAnalysisResult.ComplianceFlags` automatically combines:
- **YAML** — `compliance_tags` defined for each rule in `rules.yaml`
- **Hardcoded** — automatic mapping for known categories (GDPR, EU AI Act, NIS2, PCI-DSS, NIST 800-53)

```csharp
if (result.ComplianceFlags.Contains("GDPR Art.4(1)"))
{
    // Logic for legal basis, DPIA, minimization
}
if (result.ComplianceFlags.Contains("PCI-DSS"))
{
    // Encryption, network segmentation, audit
}
```

### Score Components

| **Component**            | **Description**                                                  | **Notes**       |
|---------------------------|-------------------------------------------------------------------|-----------------|
| **BaseScore**             | Sum of matched-rule weights × validation × confidence             |                 |
| **CorrelationMultiplier** | 1.0 + (distinct categories × 0.12)                                 | capped at 2.2   |
| **ContextBoost**          | +0.12 for each PII near a trigger word (`"password:"`, `"confidential"`, etc.) |     |
| **DensityBonus**          | Penalizes short texts containing many PII (data-leak risk)         |                 |

Risk Thresholds:

| **Score**  | **Level**            | **Recommended Action**                 |
|------------|----------------------|-----------------------------------------|
| **0-15**   | ✅ Safe (AI Ready)    | Direct submission to the LLM            |
| **16-35**  | ⚠️ Low               | Logging + monitoring                    |
| **36-60**  | ⛔ Medium             | Anonymization mandatory                 |
| **61-85**  | 🚨 High              | Isolated sandbox or synthetic data      |
| **86-100** | 🛑 Critical          | Absolute block, on-premise processing   |

# ⚠️ Disclaimer: This library is a technical support tool. It does not replace a Data Protection Impact Assessment (DPIA) or the advice of a DPO. GDPR, AI Act, and NIS2 compliance require contextual assessments, legal bases, and organizational processes that no library can substitute for.

# 🧪 Testing & Performance

```csharp
// Quick benchmark
var analyzer = new PrivacyAnalyzer();
var sw = System.Diagnostics.Stopwatch.StartNew();

for (int i = 0; i < 10_000; i++)
{
    analyzer.Analyze("Text with email test@example.com and IBAN DE89370400440532013000");
}

sw.Stop();
Console.WriteLine($"⚡ 10k analyses in {sw.ElapsedMilliseconds}ms ({10_000.0 / sw.ElapsedMilliseconds:F1} req/sec)");
```

# 🤝 Contributing

Fork the repo
Create a branch for your feature (git checkout -b feature/new-country)
Add rules in rules.yaml + validators in ValidatorRegistry.cs
Add tests in tests/ (xUnit)
Submit a PR with a clear description and examples
🌍 To add a new country: follow the existing YAML schema, implement a validator (if needed), and add an entry to the README table.

# 📄 License

Distributed under the MIT license. See LICENSE for details.

# 🆘 Support & Roadmap

| **Version** | **Feature**                          | **Status**      |
|--------------|--------------------------------------|----------------|
| **1.0**      | 27 EU countries, masking, embedded YAML  | ✅ Released      |
| **1.1**      | Session Restore, unique placeholders, client-side restoration | ✅ Released |
| **1.2**      | JSON config, hot-reload, async API, batch analyze, session export, ILogger, netstandard2.0, whitelist lifecycle, dynamic validators, regex cache, ValidateRules, IReadOnlySession, CHANGELOG | ✅ Released |
| **1.2.2**    | 5 new countries (UK, CH, CN, RU, UA), AI Act/NIS2 compliance flags, PrivacySessionManager, AiTransparencyNotice, ChatIntentRouter, Demo dashboard | ✅ Released |
| **1.3**      | Remote YAML configuration, session streaming | 🔄 Planned |

## Technology Partnership

<img src="https://www.digitalsolutions.it/img/partners/novaroutelogo.png" alt="NovaRouteAI" height="180" style="max-width: 100%; height: auto; min-height: 180px; max-height: 190px;">

**[NovaRouteAI](https://novarouteai.com/?ref=synthelion)** — Build with Chinese AI models through one simple API.

NovaRouteAI helps developers and AI SaaS teams test, compare, and run models like DeepSeek, Qwen, Doubao, Kimi, and GLM without managing multiple provider accounts. Start with test credits and optimize your cost per successful task.

[Click here to know NovaRouteAI](https://novarouteai.com/?ref=synthelion)

---

# 🛡️ Protect data, enable AI. Compliance by design.
