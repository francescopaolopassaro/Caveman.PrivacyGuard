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
using NUnit.Framework;
using Caveman.PrivacyGuard;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Threading;

namespace Caveman.PrivacyGuard.Tests;

[TestFixture]
public class PrivacyAnalyzerTests
{
    private PrivacyAnalyzer _analyzer = null!;

    [SetUp]
    public void Setup() => _analyzer = new PrivacyAnalyzer();


    [Test]
    public void Analyze_ComplianceFlags_AreCorrect()
    {
        var text = "CF: RSSMRA85T10H501Z IBAN: IT60X0542811101000000123456 password: MyS3cret!";
        var result = _analyzer.Analyze(text);


        Assert.That(result.ComplianceFlags, Does.Contain("GDPR/DSGVO/RGPD/RODO - Personal Identifiers"));
        Assert.That(result.ComplianceFlags, Does.Contain("PCI-DSS & SEPA - Financial/Payment Data"));
        Assert.That(result.ComplianceFlags, Does.Contain("NIST 800-53 - Credentials & Secrets"));
    }

    [Test]
    public void Analyze_GermanSteuerId_DetectedCorrectly()
    {
        var text = "Steuer-Identifikationsnummer: 12345678901";
        var result = _analyzer.Analyze(text);
        Assert.That(result.DetectedCategories, Does.Contain("German Tax ID (Steuer-Id)"));
    }

    [Test]
    public void Analyze_FrenchNIR_DetectedCorrectly()
    {
        var text = "Numéro Sécurité Sociale: 1 85 12 75 001 234 56";
        var result = _analyzer.Analyze(text);
        Assert.That(result.DetectedCategories, Does.Contain("French Social Security (NIR)"));
    }

    [Test]
    public void Analyze_SpanishNIF_DetectedCorrectly()
    {
        var text = "DNI español: 12345678Z";
        var result = _analyzer.Analyze(text);
        Assert.That(result.DetectedCategories, Does.Contain("Spanish Tax/ID Number (NIF/NIE)"));
    }

    [Test]
    public void Analyze_WithMaskingEnabled_ReturnsMaskedText()
    {
        _analyzer.EnableAutoMasking = true;
        var result = _analyzer.Analyze("Email: test@example.com, CF: RSSMRA85T10H501Z");
        Assert.That(result.MaskedText, Does.Contain("[EMAIL]"));
        Assert.That(result.MaskedText, Does.Contain("[ITALIAN TAX CODE (CF)]"));
        Assert.That(result.MaskedText, Does.Not.Contain("test@example.com"));
        Assert.That(result.MaskedText, Does.Not.Contain("RSSMRA85T10H501Z"));
    }

    [Test]
    public void Analyze_WithWhitelist_IgnoresMatchedValues()
    {
        _analyzer.AddToWhitelist("safe@company.com");
        var result = _analyzer.Analyze("Email: safe@company.com, CF: RSSMRA85T10H501Z");

        Assert.That(result.DetectedCategories, Does.Not.Contain("Email"));
        Assert.That(result.DetectedCategories, Does.Contain("Italian Tax Code (CF)"));
    }





    [Test]
    public void Analyze_EmptyString_ReturnsZeroScore()
    {
        var result = _analyzer.Analyze("");
        Assert.That(result.Score, Is.EqualTo(0));
        Assert.That(result.IsSafeForAI, Is.True);
        Assert.That(result.RiskLevel, Is.EqualTo("None"));
    }

    [Test]
    public void Analyze_EmailOnly_ReturnsDetectedCategory()
    {
        var result = _analyzer.Analyze("Scrivimi a mario.rossi@live.it per favore.");
        Assert.That(result.Score, Is.GreaterThan(0));
        Assert.That(result.DetectedCategories, Does.Contain("Email"));
    }

    [Test]
    public void Analyze_MultiplePII_ReturnsHighScore()
    {
        var text = "CF: RSSMRA85T10H501Z, IBAN: IT60X0542811101000000123456, email: test@x.com, tel: +393331234567";
        var result = _analyzer.Analyze(text);
        Assert.That(result.Score, Is.GreaterThan(60));
        Assert.That(result.DetectedCategories.Count, Is.GreaterThanOrEqualTo(3));
    }

    [Test]
    public void Analyze_IsSafeForAI_ThresholdWorks()
    {
        // Punteggio basso -> sicuro
        var safeResult = _analyzer.Analyze("Oggi fa bel tempo.");
        Assert.That(safeResult.IsSafeForAI, Is.True);

        // Punteggio alto -> non sicuro
        var unsafeResult = _analyzer.Analyze("CF: RSSMRA85T10H501Z email: a@b.com IBAN: IT60X0542811101000000123456");
        Assert.That(unsafeResult.IsSafeForAI, Is.False);
    }

    [Test]
    public void Analyze_WithSession_ReturnsUniquePlaceholders()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@example.com, Email: other@test.com", "en", session);

        Assert.That(result.Session, Is.Not.Null);
        Assert.That(result.MaskedText, Does.Contain("[PG_"));
        Assert.That(result.MaskedText, Does.Not.Contain("test@example.com"));
        Assert.That(result.MaskedText, Does.Not.Contain("other@test.com"));

        var entries = session.GetAll();
        Assert.That(entries.Count, Is.EqualTo(2));
        Assert.That(entries.Values.Any(e => e.OriginalValue == "test@example.com"), Is.True);
        Assert.That(entries.Values.Any(e => e.OriginalValue == "other@test.com"), Is.True);
    }

    [Test]
    public void Session_Restore_ReplacesPlaceholdersWithOriginalValues()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@example.com, CF: RSSMRA85T10H501Z", "en", session);

        Assert.That(result.Session, Is.Not.Null);

        var entries = session.GetAll();
        var placeholder = entries.Keys.First();
        var original = entries.Values.First().OriginalValue;

        var aiResponse = $"Please send an email to {placeholder}";
        var restored = session.Restore(aiResponse);

        Assert.That(restored, Does.Contain(original));
        Assert.That(restored, Does.Not.Contain(placeholder));
    }

    [Test]
    public void Session_Restore_MultiplePlaceholders_AllRestored()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@example.com, CF: RSSMRA85T10H501Z, IBAN: IT60X0542811101000000123456", "en", session);

        var entries = session.GetAll();
        var aiResponse = string.Join(" ", entries.Keys.Select(k => $"Data: {k}"));
        var restored = session.Restore(aiResponse);

        Assert.That(restored, Does.Contain("test@example.com"));
        Assert.That(restored, Does.Contain("RSSMRA85T10H501Z"));
        Assert.That(restored, Does.Contain("IT60X0542811101000000123456"));
    }

    [Test]
    public void Session_Restore_NotInSession_LeavesUnchanged()
    {
        var session = new PrivacySession();
        session.AddEntry("Email", "real@test.com");

        var result = session.Restore("Unknown placeholder [PG_999]");
        Assert.That(result, Does.Contain("[PG_999]"));
    }

    [Test]
    public void Session_Clear_RemovesAllMappings()
    {
        var session = new PrivacySession();
        session.AddEntry("Email", "test@test.com");
        Assert.That(session.GetAll().Count, Is.EqualTo(1));

        session.Clear();
        Assert.That(session.GetAll().Count, Is.EqualTo(0));
    }

    [Test]
    public void Session_Restore_WithPrivacyAnalyzerStaticMethod()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@example.com", "en", session);

        var placeholder = session.GetAll().Keys.First();
        var aiResponse = $"Contact: {placeholder}";
        var restored = PrivacyAnalyzer.RestoreText(aiResponse, session);

        Assert.That(restored, Is.EqualTo("Contact: test@example.com"));
    }

    [Test]
    public void Session_Restore_EmptyText_ReturnsEmpty()
    {
        var session = new PrivacySession();
        var result = session.Restore("");
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Session_Restore_NullText_ReturnsNull()
    {
        var session = new PrivacySession();
        var result = session.Restore(null!);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Analyze_WithoutSession_UsesLegacyPlaceholders()
    {
        _analyzer.EnableAutoMasking = true;
        var result = _analyzer.Analyze("Email: test@example.com", "en");

        Assert.That(result.Session, Is.Null);
        Assert.That(result.MaskedText, Does.Contain("[EMAIL]"));
        Assert.That(result.MaskedText, Does.Not.Contain("[PG_"));
    }

    [Test]
    public void Session_Deduplicate_SameValueReusesPlaceholder()
    {
        var session = new PrivacySession();
        var p1 = session.AddEntry("Email", "same@test.com");
        var p2 = session.AddEntry("Email", "same@test.com");

        Assert.That(p1, Is.EqualTo(p2));
        Assert.That(session.GetAll().Count, Is.EqualTo(1));
    }

    [Test]
    public void Session_Deduplicate_DifferentValuesDifferentPlaceholders()
    {
        var session = new PrivacySession();
        var p1 = session.AddEntry("Email", "a@test.com");
        var p2 = session.AddEntry("Email", "b@test.com");

        Assert.That(p1, Is.Not.EqualTo(p2));
        Assert.That(session.GetAll().Count, Is.EqualTo(2));
    }

    [Test]
    public void Session_MergeFrom_CombinesMappings()
    {
        var s1 = new PrivacySession();
        s1.AddEntry("Email", "a@test.com");

        var s2 = new PrivacySession();
        s2.AddEntry("IBAN", "IT60X0542811101000000123456");

        s1.MergeFrom(s2);
        Assert.That(s1.GetAll().Count, Is.EqualTo(2));
    }

    [Test]
    public void Session_MergeFrom_SkipsExistingValues()
    {
        var s1 = new PrivacySession();
        var p1 = s1.AddEntry("Email", "a@test.com");

        var s2 = new PrivacySession();
        s2.AddEntry("Email", "a@test.com");

        s1.MergeFrom(s2);
        Assert.That(s1.GetAll().Count, Is.EqualTo(1));
        Assert.That(s1.GetAll().Values.First().OriginalValue, Is.EqualTo("a@test.com"));
    }

    [Test]
    public void Session_AddOrGet_PublicMethod()
    {
        var session = new PrivacySession();
        var p1 = session.AddOrGet("Email", "test@test.com");
        var p2 = session.AddOrGet("Email", "test@test.com");

        Assert.That(p1, Is.EqualTo(p2));
    }

    [Test]
    public void CurrentSession_UsedByParameterlessAnalyze()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        _analyzer.CurrentSession = session;

        var result = _analyzer.Analyze("Email: test@example.com");
        Assert.That(result.Session, Is.Not.Null);
        Assert.That(result.MaskedText, Does.Contain("[PG_"));
    }

    [Test]
    public void CurrentSession_UsedByLanguageOverload()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        _analyzer.CurrentSession = session;

        var result = _analyzer.Analyze("Email: test@example.com", "it");
        Assert.That(result.Session, Is.Not.Null);
        Assert.That(result.Session, Is.EqualTo(session));
    }

    [Test]
    public void InstanceRestoreText_UsesCurrentSession()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        _analyzer.CurrentSession = session;

        _analyzer.Analyze("Email: test@example.com");
        var restored = _analyzer.RestoreText("Contact [PG_1]");

        Assert.That(restored, Is.EqualTo("Contact test@example.com"));
    }

    [Test]
    public void InstanceRestoreText_WithoutSession_Throws()
    {
        _analyzer.CurrentSession = null;
        Assert.Throws<InvalidOperationException>(() => _analyzer.RestoreText("test"));
    }

    [Test]
    public void Masking_DeduplicatesSameValueInText()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: a@a.com, also Email: a@a.com", "en", session);

        Assert.That(session.GetAll().Count, Is.EqualTo(1));
        Assert.That(result.MaskedText, Does.Contain("[PG_1]"));
    }

    [Test]
    public void Analyze_ExplicitSession_UpdatesCurrentSession()
    {
        var session = new PrivacySession();
        var result = _analyzer.Analyze("test", session);
        Assert.That(_analyzer.CurrentSession, Is.EqualTo(session));
    }

    [Test]
    public void ComplianceFlags_FromYaml_AreIncluded()
    {
        var result = _analyzer.Analyze("email: test@x.com");
        Assert.That(result.ComplianceFlags, Does.Contain("GDPR Art.4(1)"));
    }

    [Test]
    public void RemoveFromWhitelist_Works()
    {
        _analyzer.AddToWhitelist("test@x.com");
        _analyzer.RemoveFromWhitelist("test@x.com");
        var result = _analyzer.Analyze("Email: test@x.com");
        Assert.That(result.DetectedCategories, Does.Contain("Email"));
    }

    [Test]
    public void ClearWhitelist_RemovesAll()
    {
        _analyzer.AddToWhitelist("a@a.com", "b@b.com");
        _analyzer.ClearWhitelist();
        var result = _analyzer.Analyze("Email: a@a.com");
        Assert.That(result.DetectedCategories, Does.Contain("Email"));
    }

    [Test]
    public void ValidatorRegistry_Unregister_RemovesValidator()
    {
        ValidatorRegistry.Register("TEST", v => v == "valid");
        Assert.That(ValidatorRegistry.TryGet("TEST", out var v1), Is.True);
        ValidatorRegistry.Unregister("TEST");
        Assert.That(ValidatorRegistry.TryGet("TEST", out var v2), Is.False);
    }

    [Test]
    public void LoadCustomYamlFromString_AddsRules()
    {
        var yaml = @"
version: ""2.0""
countries:
  - code: ""XX""
    rules:
      - category: ""TestCategory""
        pattern: '\bCUSTOM_PATTERN\b'
        base_weight: 10";
        _analyzer.LoadCustomYamlFromString(yaml);
        var result = _analyzer.Analyze("Found CUSTOM_PATTERN here");
        Assert.That(result.DetectedCategories, Does.Contain("TestCategory"));
    }

    [Test]
    public void PrivacySession_O1_Lookup_AfterManyEntries()
    {
        var session = new PrivacySession();
        for (int i = 0; i < 1000; i++)
            session.AddEntry("Email", $"user{i}@test.com");

        var p = session.AddEntry("Email", "new@test.com");
        Assert.That(p, Is.EqualTo("[PG_1001]"));
        Assert.That(session.GetAll().Count, Is.EqualTo(1001));
    }

    [Test]
    public void GetLoadedCategories_ReturnsDistinctCategories()
    {
        var cats = _analyzer.GetLoadedCategories();
        Assert.That(cats, Does.Contain("Email"));
        Assert.That(cats, Does.Contain("IBAN"));
        Assert.That(cats.Count, Is.GreaterThan(20));
    }

    [Test]
    public void RemoveRule_RemovesCategory()
    {
        Assert.That(_analyzer.GetLoadedCategories(), Does.Contain("Email"));
        var removed = _analyzer.RemoveRule("Email");
        Assert.That(removed, Is.True);
        Assert.That(_analyzer.GetLoadedCategories(), Does.Not.Contain("Email"));
    }

    [Test]
    public void RemoveRule_NotFound_ReturnsFalse()
    {
        var removed = _analyzer.RemoveRule("NonExistentCategory_XYZ");
        Assert.That(removed, Is.False);
    }

    [Test]
    public void LoadCustomYamlFromString_Replace_ClearsEmbeddedRules()
    {
        var yaml = @"
version: ""2.0""
countries:
  - code: ""XX""
    rules:
      - category: ""SoloRule""
        pattern: '\bSOLO\b'
        base_weight: 10";
        _analyzer.LoadCustomYamlFromString(yaml, replace: true);
        var cats = _analyzer.GetLoadedCategories();
        Assert.That(cats.Count, Is.EqualTo(1));
        Assert.That(cats, Does.Contain("SoloRule"));
        Assert.That(cats, Does.Not.Contain("Email"));
    }

    [Test]
    public void ClearRules_RemovesAll()
    {
        _analyzer.ClearRules();
        Assert.That(_analyzer.GetLoadedCategories().Count, Is.EqualTo(0));
    }

    [Test]
    public void RestoreDetailed_ReturnsCount()
    {
        var session = new PrivacySession();
        session.AddEntry("Email", "a@a.com");
        session.AddEntry("IBAN", "IT60X0542811101000000123456");

        var result = session.RestoreDetailed("Contact [PG_1] via [PG_2]");
        Assert.That(result.Text, Is.EqualTo("Contact a@a.com via IT60X0542811101000000123456"));
        Assert.That(result.RestoredCount, Is.EqualTo(2));
    }

    [Test]
    public void RestoreDetailed_PartialMatch_CountsOnlyKnown()
    {
        var session = new PrivacySession();
        session.AddEntry("Email", "a@a.com");

        var result = session.RestoreDetailed("[PG_1] and [PG_999]");
        Assert.That(result.RestoredCount, Is.EqualTo(1));
        Assert.That(result.Text, Does.Contain("a@a.com"));
        Assert.That(result.Text, Does.Contain("[PG_999]"));
    }

    [Test]
    public void RestoreDetailed_EmptyText_ReturnsZero()
    {
        var session = new PrivacySession();
        var result = session.RestoreDetailed("");
        Assert.That(result.RestoredCount, Is.EqualTo(0));
    }

    [Test]
    public void Dispose_DoesNotThrow()
    {
        using var a = new PrivacyAnalyzer();
        Assert.DoesNotThrow(() => a.Dispose());
    }

    [Test]
    public void Dispose_Twice_DoesNotThrow()
    {
        var a = new PrivacyAnalyzer();
        a.Dispose();
        Assert.DoesNotThrow(() => a.Dispose());
    }

    [Test]
    public void GetRule_ReturnsRuleForCategory()
    {
        var rule = _analyzer.GetRule("Email");
        Assert.That(rule, Is.Not.Null);
        Assert.That(rule!.Category, Is.EqualTo("Email"));
        Assert.That(rule.BaseWeight, Is.GreaterThan(0));
        Assert.That(rule.Pattern.ToString(), Does.Contain("@"));
    }

    [Test]
    public void GetRule_UnknownCategory_ReturnsNull()
    {
        var rule = _analyzer.GetRule("NonExistent_XYZ");
        Assert.That(rule, Is.Null);
    }

    [Test]
    public void Session_NullWhenMaskingDisabled()
    {
        _analyzer.EnableAutoMasking = false;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@x.com", session);
        Assert.That(result.Session, Is.Null);
    }

    [Test]
    public void Session_NotNullWhenMaskingEnabled()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = _analyzer.Analyze("Email: test@x.com", session);
        Assert.That(result.Session, Is.Not.Null);
    }

    [Test]
    public void LoadCustomYaml_InvalidRegex_ThrowsWithContext()
    {
        var yaml = @"
version: ""2.0""
countries:
  - code: ""XX""
    rules:
      - category: ""BadRule""
        pattern: '\b(unclosed_group'
        base_weight: 10";
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _analyzer.LoadCustomYamlFromString(yaml));
        Assert.That(ex!.Message, Does.Contain("BadRule"));
        Assert.That(ex.Message, Does.Contain("unclosed_group"));
    }

    [Test]
    public void Dispose_ThenAnalyze_ThrowsObjectDisposed()
    {
        var a = new PrivacyAnalyzer();
        a.Dispose();
        Assert.Throws<ObjectDisposedException>(() => a.Analyze("test"));
    }

    [Test]
    public void Dispose_ThenWhitelist_ThrowsObjectDisposed()
    {
        var a = new PrivacyAnalyzer();
        a.Dispose();
        Assert.Throws<ObjectDisposedException>(() => a.AddToWhitelist("x"));
        Assert.Throws<ObjectDisposedException>(() => a.RemoveFromWhitelist("x"));
        Assert.Throws<ObjectDisposedException>(() => a.ClearWhitelist());
        Assert.Throws<ObjectDisposedException>(() => a.GetWhitelist());
        Assert.Throws<ObjectDisposedException>(() => a.IsWhitelisted("x"));
    }

    [Test]
    public void Dispose_ThenRules_ThrowsObjectDisposed()
    {
        var a = new PrivacyAnalyzer();
        a.Dispose();
        Assert.Throws<ObjectDisposedException>(() => a.GetLoadedCategories());
        Assert.Throws<ObjectDisposedException>(() => a.GetRule("Email"));
        Assert.Throws<ObjectDisposedException>(() => a.RemoveRule("Email"));
        Assert.Throws<ObjectDisposedException>(() => a.ClearRules());
    }

    [Test]
    public void Dispose_ThenRestoreText_ThrowsObjectDisposed()
    {
        var a = new PrivacyAnalyzer();
        a.CurrentSession = new PrivacySession();
        a.Dispose();
        Assert.Throws<ObjectDisposedException>(() => a.RestoreText("test"));
    }

    [Test]
    public async Task AnalyzeAsync_ReturnsSameResultAsSync()
    {
        var syncResult = _analyzer.Analyze("Email: test@example.com");
        var asyncResult = await _analyzer.AnalyzeAsync("Email: test@example.com");
        Assert.That(asyncResult.Score, Is.EqualTo(syncResult.Score));
        Assert.That(asyncResult.DetectedCategories, Is.EquivalentTo(syncResult.DetectedCategories));
    }

    [Test]
    public void AnalyzeAsync_WithCancellationToken_CanCancel()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await _analyzer.AnalyzeAsync("test", cts.Token));
    }

    [Test]
    public async Task AnalyzeAsync_WithSession_ReturnsSame()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();
        var result = await _analyzer.AnalyzeAsync("Email: test@example.com", session);
        Assert.That(result.Session, Is.Not.Null);
        Assert.That(result.MaskedText, Does.Contain("[PG_"));
    }

    [Test]
    public void GetWhitelist_InitiallyEmpty()
    {
        Assert.That(_analyzer.GetWhitelist().Count, Is.EqualTo(0));
    }

    [Test]
    public void GetWhitelist_ReturnsAddedItems()
    {
        _analyzer.AddToWhitelist("a@a.com", "b@b.com");
        var list = _analyzer.GetWhitelist();
        Assert.That(list.Count, Is.EqualTo(2));
        Assert.That(list.Contains("a@a.com"), Is.True);
    }

    [Test]
    public void IsWhitelisted_AfterAdd_ReturnsTrue()
    {
        _analyzer.AddToWhitelist("safe@x.com");
        Assert.That(_analyzer.IsWhitelisted("safe@x.com"), Is.True);
        Assert.That(_analyzer.IsWhitelisted("other@x.com"), Is.False);
    }

    [Test]
    public void NormalizeNewlines_HandlesAllVariants()
    {
        _analyzer.EnableAutoMasking = true;
        var session = new PrivacySession();

        var resultCrLf = _analyzer.Analyze("Email:\r\ntest@example.com", "en", session);
        Assert.That(resultCrLf.DetectedCategories, Does.Contain("Email"));

        session.Clear();
        var resultCr = _analyzer.Analyze("Email:\rtest@example.com", "en", session);
        Assert.That(resultCr.DetectedCategories, Does.Contain("Email"));
    }

    [Test]
    public void PrivacySession_Count_ReturnsCorrectNumber()
    {
        var session = new PrivacySession();
        Assert.That(session.Count, Is.EqualTo(0));

        session.AddEntry("Email", "a@a.com");
        Assert.That(session.Count, Is.EqualTo(1));

        session.AddEntry("Email", "b@b.com");
        Assert.That(session.Count, Is.EqualTo(2));

        session.AddEntry("Email", "a@a.com"); // duplicate
        Assert.That(session.Count, Is.EqualTo(2));
    }

    [Test]
    public void AnalyzeBatch_ReturnsResultsInOrder()
    {
        var inputs = new[] { "Email: a@a.com", "IBAN: IT60X0542811101000000123456", "no pii here" };
        var results = _analyzer.AnalyzeBatch(inputs);

        Assert.That(results.Count, Is.EqualTo(3));
        Assert.That(results[0].DetectedCategories, Does.Contain("Email"));
        Assert.That(results[1].DetectedCategories, Does.Contain("IBAN"));
        Assert.That(results[2].DetectedCategories.Count, Is.EqualTo(0));
    }

    [Test]
    public async Task AnalyzeBatchAsync_ReturnsResultsInOrder()
    {
        var inputs = new[] { "Email: a@a.com", "IBAN: IT60X0542811101000000123456" };
        var results = await _analyzer.AnalyzeBatchAsync(inputs);

        Assert.That(results.Count, Is.EqualTo(2));
        Assert.That(results[0].DetectedCategories, Does.Contain("Email"));
        Assert.That(results[1].DetectedCategories, Does.Contain("IBAN"));
    }

    [Test]
    public void LoadCustomJson_AddsRules()
    {
        var json = @"{
  ""version"": ""2.0"",
  ""countries"": [
    { ""code"": ""XX"", ""rules"": [
      { ""category"": ""JsonTest"", ""pattern"": ""\\bJSON_TEST\\b"", ""base_weight"": 10 }
    ]}
  ]
}";
        _analyzer.LoadCustomJsonFromString(json);
        var result = _analyzer.Analyze("Found JSON_TEST here");
        Assert.That(result.DetectedCategories, Does.Contain("JsonTest"));
    }

    [Test]
    public void LoadCustomJson_Replace_ClearsEmbedded()
    {
        var json = @"{
  ""version"": ""2.0"",
  ""countries"": [
    { ""code"": ""XX"", ""rules"": [
      { ""category"": ""OnlyRule"", ""pattern"": ""\\bONLY\\b"", ""base_weight"": 10 }
    ]}
  ]
}";
        _analyzer.LoadCustomJsonFromString(json, replace: true);
        var cats = _analyzer.GetLoadedCategories();
        Assert.That(cats.Count, Is.EqualTo(1));
        Assert.That(cats, Does.Contain("OnlyRule"));
    }

    [Test]
    public void LoadCustomJson_InvalidJson_Throws()
    {
        Assert.Throws<JsonException>(() => _analyzer.LoadCustomJsonFromString("not json"));
    }

    [Test]
    public void ValidateRules_ReturnsTrue()
    {
        Assert.That(_analyzer.ValidateRules(), Is.True);
    }

    [Test]
    public void Session_ToJson_Roundtrip()
    {
        var session = new PrivacySession();
        session.AddEntry("Email", "test@example.com");
        session.AddEntry("IBAN", "IT60X0542811101000000123456");

        var json = session.ToJson();
        var restored = PrivacySession.FromJson(json);

        Assert.That(restored.Count, Is.EqualTo(2));
        Assert.That(restored.GetAll().Values.Any(e => e.OriginalValue == "test@example.com"), Is.True);
    }

    [Test]
    public void Session_ImportFromJson_Merges()
    {
        var s1 = new PrivacySession();
        s1.AddEntry("Email", "a@a.com");

        var s2 = new PrivacySession();
        s2.AddEntry("IBAN", "IT60X0542811101000000123456");
        var json = s2.ToJson();
        s1.ImportFromJson(json);

        Assert.That(s1.Count, Is.EqualTo(2));
    }

    [Test]
    public void IReadOnlySession_Interface_Works()
    {
        IReadOnlySession session = new PrivacySession();
        session.Restore("test");
        Assert.That(session.Count, Is.EqualTo(0));
    }
}