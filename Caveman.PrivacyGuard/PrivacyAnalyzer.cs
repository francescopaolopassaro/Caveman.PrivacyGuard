// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows.
// Detects, scores, and auto-masks sensitive data across 27 EU countries with 
// GDPR/PCI-DSS/NIST compliance flags, multi-language support, and YAML-driven 
// extensible rules. Thread-safe, embedded resources, zero external dependencies.
// ------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Caveman.PrivacyGuard.Models;

namespace Caveman.PrivacyGuard;

public record PrivacyAnalysisResult
{
    public int Score { get; init; }
    public string RiskLevel { get; init; } = string.Empty;
    public List<string> DetectedCategories { get; init; } = new();
    public List<string> ComplianceFlags { get; init; } = new();
    public string WarningMessage { get; init; } = string.Empty;
    public bool IsSafeForAI => Score <= 15;
    public int MatchCount { get; init; }
    public double DensityScore { get; init; }
    public Dictionary<string, int> MatchesPerCategory { get; init; } = new();
    public string MaskedText { get; init; } = string.Empty;
}

public class PrivacyAnalyzer
{
    private readonly List<(string Category, Regex Pattern, int BaseWeight, Func<string, bool>? Validator, string[]? ContextKeywords, bool IsHighConfidence)> _rules = new();
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ReaderWriterLockSlim _lock = new();

    public bool EnableAutoMasking { get; set; } = false;

    // 🔹 Dictionary inizializzato separatamente per evitare TypeInitializationException
    private static readonly Dictionary<string, LocData> _locales = new(StringComparer.OrdinalIgnoreCase);

    static PrivacyAnalyzer()
    {
        _locales["en"] = new LocData("Safe (AI Ready)", "Low (Monitoring)", "Medium (Anonymization Required)", "High (Block Recommended)", "Critical (Absolute Prohibition)",
            "✅ No sensitive data detected. AI processing is safe.", "\n🛡️ Sensitive data automatically masked before AI submission.",
            "⚠️ Minor indicators: {0}. Verify format.", "⚠️ Data detected: {0}. Logging and monitoring recommended.",
            "⛔ Data detected: {0}. Pseudonymization mandatory before AI.", "🚨 Data detected: {0}. Do not send to public models. Use isolated sandbox.",
            "🛑 CRITICAL SENSITIVE DATA: {0}. Submission prohibited. Require on-premise processing.");

        _locales["it"] = new LocData("Sicuro (AI Ready)", "Basso (Monitoraggio)", "Medio (Anonimizzazione Obbligatoria)", "Alto (Blocco Consigliato)", "Critico (Divieto Assoluto)",
            "✅ Nessun dato sensibile rilevato. Elaborazione AI sicura.", "\n🛡️ Dati sensibili automaticamente mascherati.",
            "⚠️ Minimi indicatori: {0}. Verifica formato.", "⚠️ Dati rilevati: {0}. Consigliato logging.",
            "⛔ Dati rilevati: {0}. Pseudonimizzazione obbligatoria.", "🚨 Dati rilevati: {0}. Non inviare a modelli pubblici.",
            "🛑 DATI SENSIBILI CRITICI: {0}. VIETATO l'invio.");

        _locales["de"] = new LocData("Sicher (AI Ready)", "Niedrig (Überwachung)", "Mittel (Anonymisierung erforderlich)", "Hoch (Blockade empfohlen)", "Kritisch (Absolutes Verbot)",
            "✅ Keine sensiblen Daten erkannt. KI-Verarbeitung sicher.", "\n🛡️ Sensible Daten wurden automatisch maskiert.",
            "⚠️ Geringe Hinweise: {0}. Format prüfen.", "⚠️ Daten erkannt: {0}. Protokollierung empfohlen.",
            "⛔ Daten erkannt: {0}. Pseudonymisierung vor KI erforderlich.", "🚨 Daten erkannt: {0}. Nicht an öffentliche Modelle senden.",
            "🛑 KRITISCHE SENSIBLE DATEN: {0}. Übermittlung verboten. On-Premise erforderlich.");

        _locales["fr"] = new LocData("Sûr (AI Ready)", "Faible (Surveillance)", "Moyen (Anonymisation requise)", "Élevé (Blocage recommandé)", "Critique (Interdiction absolue)",
            "✅ Aucune donnée sensible détectée. Traitement IA sûr.", "\n🛡️ Données sensibles automatiquement masquées.",
            "⚠️ Indicateurs mineurs : {0}. Vérifiez le format.", "⚠️ Données détectées : {0}. Journalisation recommandée.",
            "⛔ Données détectées : {0}. Pseudonymisation obligatoire avant l'IA.", "🚨 Données détectées : {0}. Ne pas envoyer aux modèles publics.",
            "🛑 DONNÉES SENSIBLES CRITIQUES : {0}. Envoi interdit. Traitement local requis.");

        _locales["es"] = new LocData("Seguro (AI Ready)", "Bajo (Monitoreo)", "Medio (Anonimización requerida)", "Alto (Bloqueo recomendado)", "Crítico (Prohibición absoluta)",
            "✅ No se detectaron datos sensibles. Procesamiento con IA seguro.", "\n🛡️ Datos sensibles enmascarados automáticamente.",
            "⚠️ Indicadores menores: {0}. Verifique el formato.", "⚠️ Datos detectados: {0}. Se recomienda registro.",
            "⛔ Datos detectados: {0}. Pseudonimización obligatoria antes de IA.", "🚨 Datos detectados: {0}. No enviar a modelos públicos.",
            "🛑 DATOS SENSIBLES CRÍTICOS: {0}. Envío prohibido. Requiere procesamiento local.");

        // ✅ Safe reference after dictionary creation
        _locales["default"] = _locales["en"];
    }

    public PrivacyAnalyzer() => LoadFromEmbeddedYaml();

    public PrivacyAnalysisResult Analyze(string input) => Analyze(input, "en");

    public PrivacyAnalysisResult Analyze(string input, string language)
    {
        var loc = GetLocalization(language);
        if (string.IsNullOrWhiteSpace(input))
            return new PrivacyAnalysisResult { Score = 0, RiskLevel = "None", WarningMessage = loc.Empty };

        var normalized = input.Replace("\r\n", "\n").Replace("\r", "\n");
        var detected = new Dictionary<string, (int count, bool validated)>();
        int baseScore = 0, totalMatches = 0;

        _lock.EnterReadLock();
        try
        {
            foreach (var rule in _rules)
            {
                var matches = rule.Pattern.Matches(normalized);
                if (matches.Count == 0) continue;

                int ruleMatches = 0; bool anyValid = false;
                foreach (Match m in matches)
                {
                    if (_whitelist.Contains(m.Value)) continue;
                    bool isValid = rule.Validator?.Invoke(m.Value) ?? true;
                    if (isValid) anyValid = true;
                    ruleMatches++; totalMatches++;
                }

                if (ruleMatches > 0)
                {
                    detected[rule.Category] = (ruleMatches, anyValid);
                    double w = rule.BaseWeight * (anyValid ? 1.3 : 0.5) * (rule.IsHighConfidence ? 1.2 : 0.8);
                    baseScore += (int)(ruleMatches * w);
                }
            }
        }
        finally { _lock.ExitReadLock(); }

        double contextBoost = CalculateContextBoost(normalized, detected);
        double densityBonus = Math.Min(((double)totalMatches / Math.Max(1, normalized.Length / 100.0)) * 0.7, 1.0);
        double correlationMult = Math.Min(1.0 + (detected.Count * 0.12), 2.2);
        int finalScore = (int)Math.Clamp((baseScore * correlationMult) + (contextBoost * 12) + (densityBonus * 18), 0, 100);

        var result = new PrivacyAnalysisResult
        {
            Score = finalScore,
            RiskLevel = GetRiskLevel(finalScore, loc),
            DetectedCategories = detected.Keys.OrderBy(k => k).ToList(),
            MatchesPerCategory = detected.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.count),
            ComplianceFlags = MapComplianceFlags(detected.Keys),
            WarningMessage = GenerateWarning(finalScore, detected, loc),
            MatchCount = totalMatches,
            DensityScore = densityBonus,
            MaskedText = string.Empty
        };

        if (EnableAutoMasking)
        {
            var masked = MaskText(normalized, detected);
            result = result with
            {
                MaskedText = masked,
                WarningMessage = result.WarningMessage + loc.MaskedSuffix
            };
        }

        return result;
    }

    public void AddToWhitelist(params string[] patterns)
    {
        _lock.EnterWriteLock();
        try { foreach (var p in patterns) _whitelist.Add(p); }
        finally { _lock.ExitWriteLock(); }
    }

    #region  Localization & Scoring
    private record LocData(
        string Safe, string Low, string Medium, string High, string Critical,
        string Empty, string MaskedSuffix,
        string WarnSafe, string WarnLow, string WarnMedium, string WarnHigh, string WarnCritical);

    private static LocData GetLocalization(string lang) =>
        _locales.TryGetValue(lang, out var loc) ? loc : _locales["default"];

    private static string GetRiskLevel(int score, LocData loc) => score switch
    {
        <= 15 => loc.Safe,
        <= 35 => loc.Low,
        <= 60 => loc.Medium,
        <= 85 => loc.High,
        _ => loc.Critical
    };

    private static string GenerateWarning(int score, Dictionary<string, (int, bool)> detected, LocData loc)
    {
        if (detected.Count == 0) return loc.Empty;
        var cats = string.Join(", ", detected.Keys);
        string level = GetRiskLevel(score, loc);

        return level switch
        {
            var s when s == loc.Safe => string.Format(loc.WarnSafe, cats),
            var s when s == loc.Low => string.Format(loc.WarnLow, cats),
            var s when s == loc.Medium => string.Format(loc.WarnMedium, cats),
            var s when s == loc.High => string.Format(loc.WarnHigh, cats),
            var s when s == loc.Critical => string.Format(loc.WarnCritical, cats),
            _ => "Check input format."
        };
    }

    private static List<string> MapComplianceFlags(IEnumerable<string> categories)
    {
        var flags = new List<string>();
        var c = new HashSet<string>(categories, StringComparer.OrdinalIgnoreCase);

        var personalIds = new[] {
            "Email", "Phone E.164", "Italian Tax Code (CF)", "Spanish Tax/ID Number (NIF/NIE)", "Polish PESEL",
            "Dutch BSN", "French Social Security (NIR)", "Swedish Personal ID", "Danish CPR Number", "Finnish Personal ID (Hetu)",
            "Irish PPSN", "Belgian National Registry", "Czech Birth Number", "Romanian Personal Code (CNP)", "Bulgarian EGN",
            "Croatian OIB", "Slovenian EMSO", "Lithuanian Personal Code", "Latvian Personal Code", "Estonian Personal ID",
            "German Tax ID (Steuer-Id)", "Hungarian Tax ID", "Portuguese Tax Number (NIF)", "Greek Tax Number (AFM)",
            "Cypriot ID Number", "Maltese ID Number", "Luxembourg National ID", "Slovak Birth Number"
        };
        var financialIds = new[] {
            "Credit Card", "IBAN", "Italian VAT Number", "French Business ID (SIREN/SIRET)", "Polish VAT (NIP)",
            "Austrian VAT (UID)"
        };

        if (c.ContainsAny(personalIds))
            flags.Add("GDPR/DSGVO/RGPD/RODO - Personal Identifiers");
        if (c.ContainsAny(financialIds))
            flags.Add("PCI-DSS & SEPA - Financial/Payment Data");
        if (c.Contains("Password/Secret") || c.Contains("JWT/Token"))
            flags.Add("NIST 800-53 - Credentials & Secrets");
        if (c.Contains("GPS Coordinates"))
            flags.Add("GDPR Art.4(1) - Location Tracking");
        if (c.Contains("EU Vehicle License Plate"))
            flags.Add("GDPR Art.4(1) - Indirect Identifiers");
        if (c.Contains("PNR / Booking Code"))
            flags.Add("GDPR Art.4(1) - Mobility Data");
        if (c.Contains("Social / Messenger Handle"))
            flags.Add("GDPR Art.4(1) - Digital Identity");
        if (c.Contains("Minor Data (<16)"))
            flags.Add("GDPR Art.8 - Enhanced Minor Protection");
        if (c.Contains("Legal Case / File Number"))
            flags.Add("GDPR Art.10 - Judicial Data");
        if (c.Contains("Employee / Badge ID"))
            flags.Add("GDPR Art.4(1) - Employment Data");

        return flags.Distinct().ToList();
    }
    #endregion

    #region Masking & Utils
    private string MaskText(string input, Dictionary<string, (int, bool)> detected)
    {
        var intervals = new List<(int Start, int End, string Category)>();
        _lock.EnterReadLock();
        try
        {
            foreach (var rule in _rules)
            {
                if (!detected.ContainsKey(rule.Category)) continue;
                foreach (Match m in rule.Pattern.Matches(input))
                {
                    if (_whitelist.Contains(m.Value)) continue;
                    intervals.Add((m.Index, m.Index + m.Length, rule.Category));
                }
            }
        }
        finally { _lock.ExitReadLock(); }

        intervals.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<(int Start, int End, string Category)>();
        foreach (var curr in intervals)
        {
            if (merged.Count == 0 || curr.Start >= merged[^1].End) merged.Add(curr);
            else merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, curr.End), merged[^1].Category);
        }

        var sb = new StringBuilder(input);
        for (int i = merged.Count - 1; i >= 0; i--)
        {
            var (start, end, cat) = merged[i];
            sb.Remove(start, end - start);
            sb.Insert(start, $"[{cat.ToUpperInvariant()}]");
        }
        return sb.ToString();
    }

    private double CalculateContextBoost(string input, Dictionary<string, (int, bool)> detected)
    {
        double boost = 0;
        foreach (var rule in _rules.Where(r => r.ContextKeywords?.Length > 0))
        {
            if (!detected.ContainsKey(rule.Category)) continue;
            foreach (Match m in rule.Pattern.Matches(input))
            {
                int start = Math.Max(0, m.Index - 25);
                int end = Math.Min(input.Length, m.Index + m.Length + 25);
                string window = input.Substring(start, end - start).ToLowerInvariant();
                if (rule.ContextKeywords.Any(k => window.Contains(k))) boost += 0.12;
            }
        }
        return Math.Min(boost, 1.0);
    }

    private void LoadFromEmbeddedYaml()
    {
        var doc = RuleLoader.Rules;
        foreach (var country in doc.Countries)
        {
            foreach (var rule in country.Rules)
            {
                Func<string, bool>? validator = null;
                if (!string.IsNullOrEmpty(rule.ValidatorName) && ValidatorRegistry.TryGet(rule.ValidatorName, out var v))
                    validator = v;

                var regex = new Regex(rule.Pattern, RegexOptions.Compiled | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                _rules.Add((rule.Category, regex, rule.BaseWeight, validator, rule.ContextKeywords, rule.IsHighConfidence));
            }
        }
    }
    #endregion
}