# Caveman.PrivacyGuard

PII and privacy analyzer for AI and LLM workflows. It detects, scores and masks personal data before text reaches a
model, with checksum validators for national identifiers of 32 countries (27 EU members, UK, Switzerland, China,
Russia, Ukraine), compliance flags (GDPR, AI Act, NIS2, PCI-DSS, NIST 800-53) and rules driven by YAML. It is
thread-safe, has no required external service and ships its rules inside the package.

Version 1.5.0 targets .NET 10 and netstandard2.0.

## Install

    dotnet add package Caveman.PrivacyGuard

## Quick start

    using Caveman.PrivacyGuard;

    var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };
    var session = new PrivacySession();

    var result = analyzer.Analyze("Il mio CF e RSSMRA80A01H501U, chiamami al cellulare 3389123456", "it", session);
    Console.WriteLine(result.MaskedText);        // placeholders such as [PG_1]
    Console.WriteLine(result.RiskLevel);
    string restored = PrivacyAnalyzer.RestoreText(modelAnswer, session);   // put the real values back in the reply

## What it detects

| Group | Examples |
| :--- | :--- |
| Identifiers | National IDs and tax codes with checksum (Italian CF and VAT, German Steuer-ID, French NIR, Spanish NIF, Polish PESEL, Dutch BSN...) |
| Finance | IBAN, credit card (Luhn), monetary amounts |
| Contact | E-mail, phone numbers, URLs |
| Network | IP addresses, CIDR and ranges |
| Credentials | JWT, passwords and secrets |
| Other | Dates of birth, document protocol numbers, vehicle plates, GPS coordinates, case numbers |

A value that fails its checksum is never detected or masked. A bare number needs a context keyword nearby
("tel", "cellulare", "iban"...).

## New in 1.5.0

### Anti-triggers: fewer false positives

A keyword such as "numero" confirms a phone number, but a label of another kind can be closer to the digits: in
"numero fattura 3389123456" the number is an invoice. Words such as invoice, order, article code, protocol,
serial, SKU, tracking, reference, batch and year (Italian, English, French, German, Spanish, Portuguese, Dutch,
Polish) now mark a nearby number as a non-personal identifier. The words before the number decide first, and a
keyword of the rule wins a tie. A number prefixed with plus is never vetoed.

| Text | Result |
| :--- | :--- |
| Per problemi chiamami al cellulare 3389123456 | masked as a phone |
| Il mio numero di telefono e 3389123456, anno 2024 | masked as a phone |
| Il codice articolo del prodotto e 3389123456 | kept |
| numero fattura 3389123456 | kept |

    analyzer.UseNegativeContext = true;                        // default
    analyzer.AddNegativeKeywords("pratica interna", "badge");  // your own labels

Rules can carry their own words: negative_keywords on a rule, global_negative_keywords on a rules document.

### New and corrected detections

| Category | What is detected |
| :--- | :--- |
| IBAN, printed form | Groups separated by space, dot or dash; the match has exactly the length of the country, mod-97 decides |
| Credit card | Also with dots as separators |
| Phone | Landlines starting with 0 are masked whole; more keywords (cellulare, whatsapp, chiamami, handy, movil, celular...) |
| IP Address | IPv4, CIDR and ranges; a network keyword is required, so a version number is not an address |
| URL | Scheme, www and bare domains with a known TLD; trailing punctuation excluded |
| Monetary Amount | Prefix or suffix currency, grouped or decimal amounts |
| Date of Birth | Numeric date next to a birth keyword |
| Document Protocol Number | Prot., Rep., protocollo with or without the number sign |
| Italian VAT Number | Checksum weights corrected: valid numbers were rejected before |

Use RemoveRule with a category name (for example URL) when your use case does not treat it as sensitive.

## Main API

| Member | Purpose |
| :--- | :--- |
| Analyze, AnalyzeAsync, AnalyzeBatch | Score and detect |
| EnableAutoMasking, MaskedText | Placeholder masking |
| PrivacySession, PrivacySessionManager | Reversible masking, one session per conversation |
| RestoreText | Put real values back in a model answer |
| PrivacyStreamMasker, DocumentMasker | Streaming and file masking (txt, Markdown, CSV) |
| PromptInjectionGuard | Screens untrusted text for injection attempts |
| AddToWhitelist, LoadCustomYaml, LoadCustomJson | Customize rules at runtime |
| UseNegativeContext, AddNegativeKeywords | Anti-trigger control |
| MlDetector | Optional learned confirmation tier |

## Disclaimer

This library is a technical aid. It does not replace a Data Protection Impact Assessment or the advice of a Data
Protection Officer.

## License

MIT. See the LICENSE file in the package.
