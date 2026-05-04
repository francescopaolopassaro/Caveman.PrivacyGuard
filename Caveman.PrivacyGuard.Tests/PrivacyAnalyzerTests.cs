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
}