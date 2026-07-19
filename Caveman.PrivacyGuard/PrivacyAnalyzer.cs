// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows.
// Detects, scores, and auto-masks sensitive data across 32 countries (27 EU + UK, Switzerland, China, Russia, Ukraine) with 
// GDPR/PCI-DSS/NIST compliance flags, multi-language support, and YAML-driven 
// extensible rules. Thread-safe, embedded resources, zero external dependencies.
// ------------------------------------------------------------------------------
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Caveman.PrivacyGuard.Models;
using Microsoft.Extensions.Logging;

namespace Caveman.PrivacyGuard;

/// <summary>Result of a privacy analysis containing score, risk level, detected categories and masked text.</summary>
public record PrivacyAnalysisResult
{
    /// <summary>Privacy score from 0 (safe) to 100 (critical).</summary>
    public int Score { get; init; }

    /// <summary>Localized risk level label.</summary>
    public string RiskLevel { get; init; } = string.Empty;

    /// <summary>List of detected PII category names.</summary>
    public List<string> DetectedCategories { get; init; } = new();

    /// <summary>Compliance framework flags (GDPR, PCI-DSS, NIST, etc.).</summary>
    public List<string> ComplianceFlags { get; init; } = new();

    /// <summary>Localized warning/status message.</summary>
    public string WarningMessage { get; init; } = string.Empty;

    /// <summary>True if score &le; 15 (safe to send to AI).</summary>
    public bool IsSafeForAI => Score <= 15;

    /// <summary>Total number of PII matches found.</summary>
    public int MatchCount { get; init; }

    /// <summary>Density score component (0.0 - 1.0).</summary>
    public double DensityScore { get; init; }

    /// <summary>Match counts grouped by category.</summary>
    public Dictionary<string, int> MatchesPerCategory { get; init; } = new();

    /// <summary>Input text with PII replaced by placeholders (when masking enabled).</summary>
    public string MaskedText { get; init; } = string.Empty;

    /// <summary>Session used during analysis, null when masking is disabled.</summary>
    public PrivacySession? Session { get; init; }
}

/// <summary>A compiled detection rule with its regex, weight, validator and metadata.</summary>
public record CompiledRule(
    /// <summary>PII category name (e.g. "Email", "IBAN").</summary>
    string Category,
    /// <summary>Compiled regex pattern used for detection.</summary>
    Regex Pattern,
    /// <summary>Base weight for score calculation.</summary>
    int BaseWeight,
    /// <summary>Optional algorithmic validator function.</summary>
    Func<string, bool>? Validator,
    /// <summary>Context keywords that boost score when found near a match.</summary>
    string[]? ContextKeywords,
    /// <summary>Whether this rule produces high-confidence matches.</summary>
    bool IsHighConfidence,
    /// <summary>Compliance framework tags (GDPR, PCI-DSS, etc.).</summary>
    string[] ComplianceTags
);

/// <summary>
/// Enterprise-grade PII &amp; Privacy Analyzer for AI/LLM workflows.
/// Detects, scores, and auto-masks sensitive data across 32 countries (27 EU + UK, Switzerland, China, Russia, Ukraine) with
/// GDPR/PCI-DSS/NIST compliance flags, multi-language support, and YAML-driven
/// extensible rules. Thread-safe.
/// </summary>
public class PrivacyAnalyzer : IDisposable
{
    private readonly List<CompiledRule> _rules = new();
    private readonly ConcurrentDictionary<string, CompiledRule> _ruleCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ReaderWriterLockSlim _lock = new();
    private volatile bool _disposed;
    private FileSystemWatcher? _watcher;

    /// <summary>When true, detected PII is replaced with placeholders in the result's MaskedText.</summary>
    public bool EnableAutoMasking { get; set; } = false;

    /// <summary>Optional session for tracking placeholder-to-original mappings. Used by Analyze() overloads without explicit session.</summary>
    public PrivacySession? CurrentSession { get; set; }

    /// <summary>Optional logger for diagnostic events during analysis and configuration loading.</summary>
    public ILogger? Logger { get; set; }

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

        _locales["default"] = _locales["en"];
    }

    /// <summary>Initializes a new analyzer with embedded YAML rules.</summary>
    public PrivacyAnalyzer() => LoadFromEmbeddedYaml();

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PrivacyAnalyzer),
                "This PrivacyAnalyzer instance has been disposed and can no longer be used.");
    }

    /// <summary>Releases the ReaderWriterLockSlim used for thread safety and stops config file watcher.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopWatching();
        try { _lock?.Dispose(); }
        catch (SynchronizationLockException) { /* Lock in use; GC will handle it */ }
        GC.SuppressFinalize(this);
    }

    private static string NormalizeNewlines(string input)
    {
        var sb = new StringBuilder(input.Length);
        int last = 0;
        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == '\r')
            {
                sb.Append(input, last, i - last);
                sb.Append('\n');
                last = i + (i + 1 < input.Length && input[i + 1] == '\n' ? 2 : 1);
                if (i + 1 < input.Length && input[i + 1] == '\n') i++;
            }
        }
        if (last < input.Length) sb.Append(input, last, input.Length - last);
        return sb.ToString();
    }

    /// <summary>Analyzes text for PII using English locale.</summary>
    public PrivacyAnalysisResult Analyze(string input) =>
        Analyze(input, "en", CurrentSession);

    /// <summary>Analyzes text for PII with an explicit session (also sets CurrentSession).</summary>
    public PrivacyAnalysisResult Analyze(string input, PrivacySession session)
    {
        ThrowIfDisposed();
        CurrentSession = session;
        return Analyze(input, "en", session);
    }

    /// <summary>Analyzes text for PII in the specified language.</summary>
    public PrivacyAnalysisResult Analyze(string input, string language) =>
        Analyze(input, language, CurrentSession);

    /// <summary>Analyzes text for PII with full control over language and session.</summary>
    public PrivacyAnalysisResult Analyze(string input, string language, PrivacySession? session)
    {
        ThrowIfDisposed();

        var loc = GetLocalization(language);
        if (string.IsNullOrWhiteSpace(input))
            return new PrivacyAnalysisResult { Score = 0, RiskLevel = "None", WarningMessage = loc.Empty };

        var normalized = NormalizeNewlines(input);
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
                    Logger?.LogDebug("Detected {Category} ({Matches} matches, validated: {Validated})", rule.Category, ruleMatches, anyValid);
                }
            }
        }
        finally { _lock.ExitReadLock(); }

        double contextBoost = CalculateContextBoost(normalized, detected);
        double densityBonus = Math.Min(((double)totalMatches / Math.Max(1, normalized.Length / 100.0)) * 0.7, 1.0);
        double correlationMult = Math.Min(1.0 + (detected.Count * 0.12), 2.2);
        int finalScore = (int)Polyfill.Clamp((baseScore * correlationMult) + (contextBoost * 12) + (densityBonus * 18), 0, 100);

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
            MaskedText = string.Empty,
            Session = EnableAutoMasking ? session : null
        };

        if (EnableAutoMasking)
        {
            var masked = MaskText(normalized, detected, session);
            result = result with
            {
                MaskedText = masked,
                WarningMessage = result.WarningMessage + loc.MaskedSuffix
            };
        }

        return result;
    }

    /// <summary>Analyzes text for PII asynchronously with cancellation support.</summary>
    public Task<PrivacyAnalysisResult> AnalyzeAsync(string input, CancellationToken ct = default) =>
        AnalyzeAsync(input, "en", CurrentSession, ct);

    /// <summary>Analyzes text for PII asynchronously with cancellation support.</summary>
    public Task<PrivacyAnalysisResult> AnalyzeAsync(string input, PrivacySession session, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();
        CurrentSession = session;
        return Task.Run(() => Analyze(input, "en", session), ct);
    }

    /// <summary>Analyzes text for PII asynchronously with cancellation support.</summary>
    public Task<PrivacyAnalysisResult> AnalyzeAsync(string input, string language, CancellationToken ct = default) =>
        Task.Run(() => Analyze(input, language, CurrentSession), ct);

    /// <summary>Analyzes text for PII asynchronously with full control over language and session.</summary>
    public Task<PrivacyAnalysisResult> AnalyzeAsync(string input, string language, PrivacySession? session, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();
        return Task.Run(() => Analyze(input, language, session), ct);
    }

    /// <summary>Analyzes a batch of texts and returns results in order. Uses CurrentSession.</summary>
    public List<PrivacyAnalysisResult> AnalyzeBatch(IEnumerable<string> inputs) =>
        AnalyzeBatch(inputs, "en", CurrentSession);

    /// <summary>Analyzes a batch of texts with the given language. Uses CurrentSession.</summary>
    public List<PrivacyAnalysisResult> AnalyzeBatch(IEnumerable<string> inputs, string language) =>
        AnalyzeBatch(inputs, language, CurrentSession);

    /// <summary>Analyzes a batch of texts with full control over language and session.</summary>
    public List<PrivacyAnalysisResult> AnalyzeBatch(IEnumerable<string> inputs, string language, PrivacySession? session)
    {
        ThrowIfDisposed();
        return inputs.Select(i => Analyze(i, language, session)).ToList();
    }

    /// <summary>Analyzes a batch of texts asynchronously. Uses CurrentSession.</summary>
    public Task<List<PrivacyAnalysisResult>> AnalyzeBatchAsync(IEnumerable<string> inputs, CancellationToken ct = default) =>
        AnalyzeBatchAsync(inputs, "en", CurrentSession, ct);

    /// <summary>Analyzes a batch of texts asynchronously with cancellation support.</summary>
    public Task<List<PrivacyAnalysisResult>> AnalyzeBatchAsync(IEnumerable<string> inputs, string language, CancellationToken ct = default) =>
        AnalyzeBatchAsync(inputs, language, CurrentSession, ct);

    /// <summary>Streams analysis results one at a time as they're produced, instead of waiting for the whole batch. Uses CurrentSession.</summary>
    public IAsyncEnumerable<PrivacyAnalysisResult> AnalyzeStreamAsync(IEnumerable<string> inputs, CancellationToken ct = default) =>
        AnalyzeStreamAsync(inputs, "en", CurrentSession, ct);

    /// <summary>Streams analysis results one at a time as they're produced, with full control over language and session. Useful for progressively showing results in a UI, or for very large batches where materializing the whole list upfront is undesirable.</summary>
    public async IAsyncEnumerable<PrivacyAnalysisResult> AnalyzeStreamAsync(IEnumerable<string> inputs, string language, PrivacySession? session, [EnumeratorCancellation] CancellationToken ct = default)
    {
        ThrowIfDisposed();
        foreach (var input in inputs)
        {
            ct.ThrowIfCancellationRequested();
            yield return await Task.Run(() => Analyze(input, language, session), ct).ConfigureAwait(false);
        }
    }

    /// <summary>Analyzes a batch of texts asynchronously with full control over language and session.</summary>
    public Task<List<PrivacyAnalysisResult>> AnalyzeBatchAsync(IEnumerable<string> inputs, string language, PrivacySession? session, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();
        return Task.Run(() => inputs.Select(i => Analyze(i, language, session)).ToList(), ct);
    }

    /// <summary>Adds values to the whitelist. Whitelisted values are ignored during detection.</summary>
    public void AddToWhitelist(params string[] values)
    {
        ThrowIfDisposed();
        _lock.EnterWriteLock();
        try { foreach (var v in values) _whitelist.Add(v); }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Removes values from the whitelist.</summary>
    public void RemoveFromWhitelist(params string[] values)
    {
        ThrowIfDisposed();
        _lock.EnterWriteLock();
        try { foreach (var v in values) _whitelist.Remove(v); }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Clears all whitelist entries.</summary>
    public void ClearWhitelist()
    {
        ThrowIfDisposed();
        _lock.EnterWriteLock();
        try { _whitelist.Clear(); }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Returns a read-only snapshot of all whitelisted values (unique, case-insensitive).</summary>
    public IReadOnlyCollection<string> GetWhitelist()
    {
        ThrowIfDisposed();
        _lock.EnterReadLock();
        try { return new HashSet<string>(_whitelist, StringComparer.OrdinalIgnoreCase); }
        finally { _lock.ExitReadLock(); }
    }

    /// <summary>Returns true if the given value is in the whitelist.</summary>
    public bool IsWhitelisted(string value)
    {
        ThrowIfDisposed();
        _lock.EnterReadLock();
        try { return _whitelist.Contains(value); }
        finally { _lock.ExitReadLock(); }
    }

    /// <summary>Returns all distinct PII categories currently loaded in the rule set.</summary>
    public IReadOnlyCollection<string> GetLoadedCategories()
    {
        ThrowIfDisposed();
        _lock.EnterReadLock();
        try { return _rules.Select(r => r.Category).Distinct().OrderBy(c => c).ToList().AsReadOnly(); }
        finally { _lock.ExitReadLock(); }
    }

    /// <summary>Returns the first compiled rule matching the given category, or null if not found. Uses internal cache for O(1) lookup.</summary>
    public CompiledRule? GetRule(string category)
    {
        ThrowIfDisposed();
        if (_ruleCache.TryGetValue(category, out var cached))
            return cached;
        _lock.EnterReadLock();
        try
        {
            var rule = _rules.FirstOrDefault(r =>
                string.Equals(r.Category, category, StringComparison.OrdinalIgnoreCase));
            if (rule != null)
                _ruleCache[category] = rule;
            return rule;
        }
        finally { _lock.ExitReadLock(); }
    }

    private void InvalidateRuleCache() => _ruleCache.Clear();

    /// <summary>Removes all rules matching the given category (case-insensitive). Returns true if any were removed.</summary>
    public bool RemoveRule(string category)
    {
        ThrowIfDisposed();
        _lock.EnterWriteLock();
        try { return _rules.RemoveAll(r => string.Equals(r.Category, category, StringComparison.OrdinalIgnoreCase)) > 0; }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Loads custom YAML rules from a file path. When <paramref name="replace"/> is true, existing rules are cleared first.</summary>
    public void LoadCustomYaml(string filePath, bool replace = false)
    {
        ThrowIfDisposed();
        var doc = RuleLoader.LoadFromFile(filePath);
        LoadRules(doc, replace);
    }

    /// <summary>Loads custom YAML rules from a string. When <paramref name="replace"/> is true, existing rules are cleared first.</summary>
    public void LoadCustomYamlFromString(string yamlContent, bool replace = false)
    {
        ThrowIfDisposed();
        var doc = RuleLoader.LoadFromString(yamlContent);
        LoadRules(doc, replace);
    }

    /// <summary>
    /// Downloads YAML rules from a remote URL (e.g. a centrally managed rules feed) and loads them.
    /// When <paramref name="replace"/> is true, existing rules are cleared first. The caller is responsible
    /// for the trustworthiness of <paramref name="url"/> — rules loaded this way execute as regular
    /// detection rules, so only point it at a source you control.
    /// </summary>
    public async Task LoadCustomYamlFromUrlAsync(string url, HttpClient? httpClient = null, bool replace = false, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        var client = httpClient ?? _sharedHttpClient.Value;
        using var response = await client.GetAsync(url, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var yaml = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        LoadCustomYamlFromString(yaml, replace);
    }

    private static readonly Lazy<HttpClient> _sharedHttpClient = new(() => new HttpClient());

    /// <summary>Loads custom JSON rules from a file path. When <paramref name="replace"/> is true, existing rules are cleared first.</summary>
    public void LoadCustomJson(string filePath, bool replace = false)
    {
        ThrowIfDisposed();
        var json = File.ReadAllText(filePath);
        LoadCustomJsonFromString(json, replace);
    }

    /// <summary>Loads custom JSON rules from a string. When <paramref name="replace"/> is true, existing rules are cleared first.</summary>
    public void LoadCustomJsonFromString(string json, bool replace = false)
    {
        ThrowIfDisposed();
        var doc = JsonSerializer.Deserialize<RulesDocumentJson>(json);
        if (doc?.Countries == null)
            throw new InvalidOperationException("Invalid JSON rules document: missing 'countries' array.");

        _lock.EnterWriteLock();
        try
        {
            if (replace) _rules.Clear();
            foreach (var country in doc.Countries)
            {
                foreach (var rule in country.Rules)
                {
                    try
                    {
                        Func<string, bool>? validator = null;
                        if (!string.IsNullOrEmpty(rule.ValidatorName) && ValidatorRegistry.TryGet(rule.ValidatorName!, out var v))
                            validator = v;

                        var regex = new Regex(rule.Pattern, RegexHelper.CompiledAndSafe, RegexHelper.RegexTimeout);
                        _rules.Add(new CompiledRule(rule.Category, regex, rule.BaseWeight, validator, rule.ContextKeywords, rule.IsHighConfidence, rule.ComplianceTags ?? Array.Empty<string>()));
                    }
#if NET8_0_OR_GREATER
                    catch (RegexParseException ex)
#else
                    catch (ArgumentException ex)
#endif
                    {
                        throw new InvalidOperationException(
                            $"Invalid regex pattern in JSON rule '{rule.Category}' (country '{country.Code}'): \"{rule.Pattern}\"", ex);
                    }
                }
            }
            InvalidateRuleCache();
            Logger?.LogInformation("Loaded {Count} JSON rules from {Source}", doc.Countries.Sum(c => c.Rules.Count), replace ? "replace" : "append");
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Removes all loaded rules (including embedded ones). Useful before loading a completely custom set.</summary>
    public void ClearRules()
    {
        ThrowIfDisposed();
        _lock.EnterWriteLock();
        try { _rules.Clear(); InvalidateRuleCache(); }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Validates all currently loaded rules by checking they do not throw exceptions during matching. Returns true if all rules are valid.</summary>
    public bool ValidateRules()
    {
        ThrowIfDisposed();
        _lock.EnterReadLock();
        try
        {
            foreach (var r in _rules)
            {
                try { r.Pattern.Match(""); }
                catch { return false; }
            }
            return true;
        }
        finally { _lock.ExitReadLock(); }
    }

    private void LoadRules(RulesDocument doc, bool replace = false)
    {
        _lock.EnterWriteLock();
        try
        {
            if (replace) _rules.Clear();

            foreach (var country in doc.Countries)
            {
                foreach (var rule in country.Rules)
                {
                    try
                    {
                        Func<string, bool>? validator = null;
                        if (!string.IsNullOrEmpty(rule.ValidatorName) && ValidatorRegistry.TryGet(rule.ValidatorName!, out var v))
                            validator = v;

                        var regex = new Regex(rule.Pattern,
                            RegexHelper.CompiledAndSafe,
                            RegexHelper.RegexTimeout);

                        _rules.Add(new CompiledRule(rule.Category, regex, rule.BaseWeight, validator, rule.ContextKeywords, rule.IsHighConfidence, rule.ComplianceTags));
                    }
#if NET8_0_OR_GREATER
                    catch (RegexParseException ex)
#else
                    catch (ArgumentException ex)
#endif
                    {
                        throw new InvalidOperationException(
                            $"Invalid regex pattern for rule '{rule.Category}' (country '{country.Code}'): \"{rule.Pattern}\"", ex);
                    }
                }
            }
        }
        finally { _lock.ExitWriteLock(); }
        InvalidateRuleCache();
        Logger?.LogInformation("Loaded YAML rules: {Count} countries, {Rules} rules", doc.Countries.Count, doc.Countries.Sum(c => c.Rules.Count));
    }

    /// <summary>Restores original values in text using the given session (static helper).</summary>
    public static string RestoreText(string text, PrivacySession session) =>
        session.Restore(text);

    /// <summary>Restores original values in text using CurrentSession. Throws if no session is set.</summary>
    public string RestoreText(string text)
    {
        ThrowIfDisposed();
        if (CurrentSession == null)
            throw new InvalidOperationException(
                "No session set. Set CurrentSession or use PrivacyAnalyzer.RestoreText(text, session).");
        return CurrentSession.Restore(text);
    }

    /// <summary>Starts watching a JSON config file for changes. Triggers <see cref="ConfigReloaded"/> on every valid change.</summary>
    public void WatchConfig(string filePath)
    {
        ThrowIfDisposed();
        StopWatching();
        var dir = Path.GetDirectoryName(Path.GetFullPath(filePath));
        var file = Path.GetFileName(filePath);
        _watcher = new FileSystemWatcher(dir ?? ".", file)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };
        _watcher.Changed += OnConfigFileChanged;
        Logger?.LogInformation("Watching config file: {Path}", filePath);
    }

    /// <summary>Stops watching the config file if a watcher is active.</summary>
    public void StopWatching()
    {
        if (_watcher != null)
        {
            _watcher.Changed -= OnConfigFileChanged;
            _watcher.Dispose();
            _watcher = null;
        }
    }

    /// <summary>Raised after a config file is successfully reloaded.</summary>
    public event EventHandler<EventArgs>? ConfigReloaded;

    private void OnConfigFileChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            LoadCustomJson(e.FullPath, replace: true);
            Logger?.LogInformation("Config reloaded: {Path}", e.FullPath);
            ConfigReloaded?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "Config reload failed: {Path}", e.FullPath);
        }
    }

    #region Localization & Scoring
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

    private List<string> MapComplianceFlags(IEnumerable<string> categories)
    {
        var flags = new List<string>();
        var c = new HashSet<string>(categories, StringComparer.OrdinalIgnoreCase);

        _lock.EnterReadLock();
        try
        {
            foreach (var rule in _rules)
            {
                if (c.Contains(rule.Category) && rule.ComplianceTags.Length > 0)
                    flags.AddRange(rule.ComplianceTags);
            }
        }
        finally { _lock.ExitReadLock(); }

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
        {
            flags.Add("NIST 800-53 - Credentials & Secrets");
            flags.Add("NIS2 Art.21 - Cybersecurity Risk Management (Credential Exposure)");
        }
        if (c.Contains("GPS Coordinates"))
            flags.Add("GDPR Art.4(1) - Location Tracking");
        if (c.Contains("EU Vehicle License Plate"))
            flags.Add("GDPR Art.4(1) - Indirect Identifiers");
        if (c.Contains("PNR / Booking Code"))
            flags.Add("GDPR Art.4(1) - Mobility Data");
        if (c.Contains("Social / Messenger Handle"))
            flags.Add("GDPR Art.4(1) - Digital Identity");
        if (c.Contains("Minor Data (<16)"))
        {
            flags.Add("GDPR Art.8 - Enhanced Minor Protection");
            flags.Add("EU AI Act Art.5 - Vulnerable Groups Protection");
        }
        if (c.Contains("Legal Case / File Number"))
        {
            flags.Add("GDPR Art.10 - Judicial Data");
            flags.Add("EU AI Act Annex III(8) - Law Enforcement & Justice");
        }
        if (c.Contains("Employee / Badge ID"))
        {
            flags.Add("GDPR Art.4(1) - Employment Data");
            flags.Add("EU AI Act Annex III(4) - Employment/Worker Management");
        }
        if (c.ContainsAny(financialIds))
            flags.Add("EU AI Act Annex III(5) - Credit Scoring & Essential Services");

        return flags.Distinct().ToList();
    }
    #endregion

    #region Masking & Utils
    private string MaskText(string input, Dictionary<string, (int, bool)> detected, PrivacySession? session = null)
    {
        var intervals = new List<(int Start, int End, string Category, string Value)>();
        _lock.EnterReadLock();
        try
        {
            foreach (var rule in _rules)
            {
                if (!detected.ContainsKey(rule.Category)) continue;
                foreach (Match m in rule.Pattern.Matches(input))
                {
                    if (_whitelist.Contains(m.Value)) continue;
                    intervals.Add((m.Index, m.Index + m.Length, rule.Category, m.Value));
                }
            }
        }
        finally { _lock.ExitReadLock(); }

        intervals.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<(int Start, int End, string Category, string Value)>();
        foreach (var curr in intervals)
        {
            if (merged.Count == 0 || curr.Start >= merged[merged.Count - 1].End) merged.Add(curr);
            else merged[merged.Count - 1] = (merged[merged.Count - 1].Start, Math.Max(merged[merged.Count - 1].End, curr.End), merged[merged.Count - 1].Category, merged[merged.Count - 1].Value);
        }

        var sb = new StringBuilder(input);
        for (int i = merged.Count - 1; i >= 0; i--)
        {
            var (start, end, cat, val) = merged[i];
            string placeholder;
            if (session != null)
            {
                placeholder = session.AddEntry(cat, val);
            }
            else
            {
                placeholder = $"[{cat.ToUpperInvariant()}]";
            }
            sb.Remove(start, end - start);
            sb.Insert(start, placeholder);
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
                if (rule.ContextKeywords!.Any(k => window.Contains(k))) boost += 0.12;
            }
        }
        return Math.Min(boost, 1.0);
    }

    private void LoadFromEmbeddedYaml()
    {
        var doc = RuleLoader.Rules;
        LoadRules(doc);
    }
    #endregion
}
