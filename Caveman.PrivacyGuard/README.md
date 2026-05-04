# Caveman.PrivacyGuard# <img width="1276" height="816" alt="Gemini_Generated_Image_tnxoi9tnxoi9tnxo" src="https://github.com/user-attachments/assets/5a8e3193-b7d3-4a41-90e6-e672467ce6cb" />

# Caveman.PrivacyGuard 🛡️🇪🇺

[![NuGet](https://img.shields.io/nuget/v/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![Downloads](https://img.shields.io/nuget/dt/Caveman.PrivacyGuard.svg)](https://www.nuget.org/packages/Caveman.PrivacyGuard)
[![License](https://img.shields.io/github/license/caveman/privacyguard.svg)](LICENSE)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-blueviolet)](https://dotnet.microsoft.com)
[![GDPR Ready](https://img.shields.io/badge/GDPR-Compliant-green)](https://gdpr.eu)

> **Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows**  
> Rileva, valuta e maschera automaticamente dati sensibili in **27 paesi UE**, con scoring del rischio, conformità GDPR/PCI-DSS/NIST e integrazione seamless con qualsiasi pipeline AI.

---

## ✨ Features

| Feature | Descrizione |
|---------|-------------|
| 🌍 **27 Paesi UE** | Pattern nativi per IT, DE, FR, ES, PL, NL, SE, FI, DK, AT, BE, PT, IE, GR, CZ, RO, HU, BG, HR, SK, SI, LT, LV, EE, CY, MT, LU + regole EU generiche |
| 🔍 **Detection Euristica** | Regex precompilate + validatori algoritmici (Luhn, IBAN MOD97, checksum nazionali) + analisi entropia Shannon |
| 📊 **Privacy Score** | Punteggio 0-100 con livelli: `Sicuro` → `Basso` → `Medio` → `Alto` → `Critico` |
| 🎭 **Auto-Masking** | Sostituzione dinamica con placeholder contestuali (`[EMAIL]`, `[IBAN]`, `[CF_IT]`, ecc.) |
| ⚙️ **YAML-Driven** | Regole configurabili in `rules.yaml` embedded, estendibili a runtime |
| 🔐 **Compliance Flags** | Mappatura automatica a GDPR, PCI-DSS, NIST 800-53, autorità nazionali (CNIL, BfDI, AEPD, ecc.) |
| 🧵 **Thread-Safe** | Pronto per microservizi ad alto throughput con `ReaderWriterLockSlim` e regex cache |
| 🚀 **Performance** | `RegexOptions.NonBacktracking` (.NET 8), pre-compilazione, zero allocazioni ridondanti |

---

## 📦 Installazione

```bash
dotnet add package Caveman.PrivacyGuard
```
## 🚀 Quick Start
Modalità Avviso (Default)

```csharp
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

// 🔹 Default: Inglese
var resEn = analyzer.Analyze("CF: RSSMRA80A01H501U, email: test@x.com");
Console.WriteLine($"[EN] Risk: {resEn.RiskLevel}\n{resEn.WarningMessage}");

// 🔹 Overload: Italiano
var resIt = analyzer.Analyze("CF: RSSMRA80A01H501U, email: test@x.com", "it");
Console.WriteLine($"[IT] Rischio: {resIt.RiskLevel}\n{resIt.WarningMessage}");

// 🔹 Overload: Tedesco
var resDe = analyzer.Analyze("Steuer-ID: 12345678901, IBAN: DE89370400440532013000", "de");
Console.WriteLine($"[DE] Risiko: {resDe.RiskLevel}\n{resDe.WarningMessage}");
```
Output:

```bash
🔒 Score: 26/100
⚠️  Avviso: ⛔ Dati rilevati: Codice Fiscale (IT), Email. Pseudonimizzazione obbligatoria.
✅ Safe for AI: False
```

```csharp
var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

var text = "Cliente: Mario Rossi, email mario@azienda.it, IBAN: IT60X0542811101000000123456";
var result = analyzer.Analyze(text);

Console.WriteLine($"🛡️  Testo sicuro per LLM:\n{result.MaskedText}");
```

Output:

```bash
🛡️  Testo sicuro per LLM:
Cliente: Mario Rossi, email [EMAIL], IBAN: [IBAN]
```

| **Codice**  | **Paese**   | **Identificatori Principali** | **Autorità di Riferimento**      |
|-------------|-------------|-------------------------------|----------------------------------|
| **🇮🇹 IT** | Italia      | Codice Fiscale, Partita IVA   | Garante Privacy, Agenzia Entrate |
| **🇩🇪 DE** | Germania    | Steuer-ID, Personalausweis    | BfDI, DSGVO                      |
| **🇫🇷 FR** | Francia     | NIR/SSN, SIREN/SIRET          | CNIL, RGPD                       |
| **🇪🇸 ES** | Spagna      | NIF/NIE                       | AEPD, RGPD                       |
| **🇵🇱 PL** | Polonia     | PESEL, NIP                    | UODO, RODO                       |
| **🇳🇱 NL** | Paesi Bassi | BSN                           | AP, AVG                          |
| **🇸🇪 SE** | Svezia      | Personnummer                  | IMY                              |
| **🇫🇮 FI** | Finlandia   | Henkilötunnus (HETU)          | Tietosuojavaltuutettu            |
| **🇩🇰 DK** | Danimarca   | CPR                           | Datatilsynet                     |
| **🇦🇹 AT** | Austria     | SV-Nummer, UID                | DSB                              |
| **🇧🇪 BE** | Belgio      | Numéro National               | APD                              |
| **🇵🇹 PT** | Portogallo  | NIF                           | CNPD                             |
| **🇮🇪 IE** | Irlanda     | PPSN                          | DPC                              |
| **🇬🇷 GR** | Grecia      | AFM, AMKA                     | HDPA                             |
| **🇨🇿 CZ** | Cechia      | Rodné číslo                   | ÚOOÚ                             |
| **🇷🇴 RO** | Romania     | CNP                           | ANSPDCP                          |
| **🇭🇺 HU** | Ungheria    | Adóazonosító                  | NAIH                             |
| **🇧🇬 BG** | Bulgaria    | EGN                           | CPDP                             |
| **🇭🇷 HR** | Croazia     | OIB                           | AZOP                             |
| **🇸🇰 SK** | Slovacchia  | Rodné číslo                   | ÚOOÚ                             |
| **🇸🇮 SI** | Slovenia    | EMŠO                          | IP                               |
| **🇱🇹 LT** | Lituania    | Asmens kodas                  | VDAI                             |
| **🇱🇻 LV** | Lettonia    | Personas kods                 | DVI                              |
| **🇪🇪 EE** | Estonia     | Isikukood                     | AKI                              |
| **🇨🇾 CY** | Cipro       | ID Number                     | CIPD                             |
| **🇲🇹 MT** | Malta       | ID Number                     | IDPC                             |
| **🇱🇺 LU** | Lussemburgo | Numéro d'identification       | CNPD                             |


## ⚙️ Configurazione Avanzata

Whitelist (Esclusioni Sicure)

```csharp
analyzer.AddToWhitelist(
    "test@company.eu",      // Email di test
    "127.0.0.1",            // IP localhost
    "IT00000000000"         // PIVA dummy
);
```

# Validatori Personalizzati a Runtime

```csharp
// Registra un nuovo validatore per un formato nazionale custom
ValidatorRegistry.Register("MY_CUSTOM_ID", value => 
    value.Length == 10 && value.StartsWith("XYZ") && value.All(char.IsDigit));

// Poi usalo nel tuo YAML custom:
// validator_name: "MY_CUSTOM_ID"
```
# 📐 Caricamento YAML Esterno (Opzionale)

```csharp
// Per caricare regole aggiornate senza ricompilare la libreria
// (implementazione da aggiungere su richiesta)
// analyzer.LoadCustomYaml("path/to/custom-rules.yaml");
```

# 📐 Architettura del Punteggio

```csharp
Score Finale = 
  (BaseScore × CorrelationMultiplier) + 
  (ContextBoost × 12) + 
  (DensityBonus × 18)
```

| **Componente**            | **Descrizione**                                                 | ****        | ****   |
|---------------------------|-----------------------------------------------------------------|-------------|--------|
| **BaseScore**             | Somma dei pesi delle regole matchate × validazione × confidence |             |        |
| **CorrelationMultiplier** | 1.0 + (categorie_distinte × 0.12)"                              | max 2.2"    |        |
| **ContextBoost**          | +0.12 per ogni PII vicino a parole trigger (""password:"        | "riservato" | ecc.)" |
| **DensityBonus**          | Penalizza testi brevi con molti PII (rischio fuga dati)         |             |        |


Soglie di Rischio:

| **Score**  | **Livello**         | **Azione Consigliata**                 |
|------------|---------------------|----------------------------------------|
| **0-15**   | ✅ Sicuro (AI Ready) | Invio diretto a LLM                   |
| **16-35**  | ⚠️ Basso            | Logging + monitoraggio                 |
| **36-60**  | ⛔ Medio             | Anonimizzazione obbligatoria          |
| **61-85**  | 🚨 Alto             | Sandbox isolata o dati sintetici       |
| **86-100** | 🛑 Critico          | Blocco assoluto, processing on-premise |


# 🔐 Compliance & GDPR

PrivacyAnalysisResult.ComplianceFlags mappa automaticamente i dati rilevati a framework normativi:

```csharp
if (result.ComplianceFlags.Contains("GDPR Art.4(1)"))
{
    // Logica per base giuridica, DPIA, minimizzazione
}
if (result.ComplianceFlags.Contains("PCI-DSS"))
{
    // Crittografia, segmentazione rete, audit
}
```

# ⚠️ Disclaimer: Questa libreria è uno strumento tecnico di supporto. Non sostituisce una Valutazione d'Impatto sulla Protezione dei Dati (DPIA) né il parere di un DPO. La conformità GDPR richiede valutazioni contestuali, basi giuridiche e processi organizzativi.

# 🧪 Testing & Performance

```csharp
// Benchmark rapido
var analyzer = new PrivacyAnalyzer();
var sw = System.Diagnostics.Stopwatch.StartNew();

for (int i = 0; i < 10_000; i++)
{
    analyzer.Analyze("Testo con email test@example.com e IBAN DE89370400440532013000");
}

sw.Stop();
Console.WriteLine($"⚡ 10k analisi in {sw.ElapsedMilliseconds}ms ({10_000.0 / sw.ElapsedMilliseconds:F1} req/sec)");
```

# 🤝 Contributing

Fork il repo
Crea un branch per la tua feature (git checkout -b feature/nuovo-paese)
Aggiungi regole in rules.yaml + validatori in ValidatorRegistry.cs
Aggiungi test in tests/ (xUnit)
PR con descrizione chiara e esempi
🌍 Per aggiungere un nuovo paese: segui lo schema YAML esistente, implementa il validatore (se necessario) e aggiungi la voce nella tabella del README.

# 📄 License

Distribuito sotto licenza MIT. Vedi LICENSE per dettagli.

# 🆘 Support & Roadmap

| **Versione** | **Feature**                          | **Stato**      |
|--------------|--------------------------------------|----------------|
| **1.0**      | 27 paesi UE, masking, YAML embedded  | ✅ Release      |
| **1.1**      | Configurazione JSON + hot-reloadog   | 🔄 In sviluppo |


# 🛡️ Proteggi i dati, abilita l'AI. Compliance by design.
