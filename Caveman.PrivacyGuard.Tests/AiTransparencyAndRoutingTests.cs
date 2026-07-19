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
using NUnit.Framework;
using Caveman.PrivacyGuard;

namespace Caveman.PrivacyGuard.Tests;

[TestFixture]
public class AiTransparencyNoticeTests
{
    [Test]
    public void GetMessage_ReturnsEnglishByDefault()
    {
        var notice = new AiTransparencyNotice();
        Assert.That(notice.GetMessage(), Does.Contain("AI system"));
    }

    [Test]
    public void GetMessage_ReturnsEmpty_WhenDisabled()
    {
        var notice = new AiTransparencyNotice { Enabled = false };
        Assert.That(notice.GetMessage(), Is.Empty);
    }

    [Test]
    public void GetMessage_RespectsLanguage()
    {
        var notice = new AiTransparencyNotice { Language = "it" };
        Assert.That(notice.GetMessage(), Does.Contain("intelligenza artificiale"));
    }

    [Test]
    public void GetMessage_FallsBackToEnglish_ForUnknownLanguage()
    {
        var notice = new AiTransparencyNotice { Language = "xx" };
        Assert.That(notice.GetMessage(), Does.Contain("AI system"));
    }

    [Test]
    public void GetMessage_PrefersCustomMessage_OverBuiltIn()
    {
        var notice = new AiTransparencyNotice { CustomMessage = "Custom disclosure text." };
        Assert.That(notice.GetMessage(), Is.EqualTo("Custom disclosure text."));
    }

    [Test]
    public void RegisterMessage_AddsOrOverridesLanguage()
    {
        AiTransparencyNotice.RegisterMessage("xx-test", "Test language message.");
        var notice = new AiTransparencyNotice { Language = "xx-test" };
        Assert.That(notice.GetMessage(), Is.EqualTo("Test language message."));
    }
}

[TestFixture]
public class ChatIntentRouterTests
{
    private ChatIntentRouter _router = null!;

    [SetUp]
    public void Setup() => _router = new ChatIntentRouter();

    [Test]
    public void RegisterCommand_MatchesExactCommand_CaseInsensitive()
    {
        string? received = null;
        _router.RegisterCommand("/reset", input => received = input);

        var matched = _router.TryRoute("/RESET");

        Assert.That(matched, Is.EqualTo("/reset"));
        Assert.That(received, Is.EqualTo("/RESET"));
    }

    [Test]
    public void TryRoute_ReturnsNull_WhenNothingMatches()
    {
        _router.RegisterCommand("/reset", _ => { });
        Assert.That(_router.TryRoute("hello, my email is test@example.com"), Is.Null);
    }

    [Test]
    public void TryRoute_UsesFirstMatchingIntent_InRegistrationOrder()
    {
        var order = new List<string>();
        _router.Register("generic", input => input.StartsWith("/"), _ => order.Add("generic"));
        _router.Register("specific", input => input == "/help", _ => order.Add("specific"));

        _router.TryRoute("/help");

        Assert.That(order, Is.EqualTo(new[] { "generic" }));
    }

    [Test]
    public void Unregister_RemovesIntent()
    {
        _router.RegisterCommand("/reset", _ => { });
        Assert.That(_router.Unregister("/reset"), Is.True);
        Assert.That(_router.TryRoute("/reset"), Is.Null);
        Assert.That(_router.Unregister("/reset"), Is.False);
    }

    [Test]
    public void Clear_RemovesAllIntents()
    {
        _router.RegisterCommand("/reset", _ => { });
        _router.RegisterCommand("/help", _ => { });
        _router.Clear();
        Assert.That(_router.RegisteredIntents, Is.Empty);
    }

    [Test]
    public void RegisteredIntents_ReflectsRegistrationOrder()
    {
        _router.RegisterCommand("/a", _ => { });
        _router.RegisterCommand("/b", _ => { });
        Assert.That(_router.RegisteredIntents, Is.EqualTo(new[] { "/a", "/b" }));
    }
}

[TestFixture]
public class ComplianceFlagExtensionTests
{
    private PrivacyAnalyzer _analyzer = null!;

    [SetUp]
    public void Setup() => _analyzer = new PrivacyAnalyzer();

    [Test]
    public void CredentialLeak_IsFlagged_UnderNis2()
    {
        var result = _analyzer.Analyze("token: bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.NOT_A_REAL_SIGNATURE_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        Assert.That(result.ComplianceFlags.Any(f => f.Contains("NIS2")), Is.True,
            "Detected credentials/secrets should surface a NIS2 cybersecurity-risk-management flag");
    }

    [Test]
    public void MinorData_IsFlagged_UnderAiAct()
    {
        var result = _analyzer.Analyze("minore di 15 anni");
        Assert.That(result.ComplianceFlags.Any(f => f.Contains("AI Act")), Is.True,
            "Detected minor data should surface an EU AI Act vulnerable-groups flag");
    }
}
