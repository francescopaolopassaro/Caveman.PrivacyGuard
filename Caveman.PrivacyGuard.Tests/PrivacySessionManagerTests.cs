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
public class PrivacySessionManagerTests
{
    private PrivacySessionManager _manager = null!;

    [SetUp]
    public void Setup() => _manager = new PrivacySessionManager();

    [Test]
    public void GetOrCreate_ReturnsSameSession_ForSameId()
    {
        var s1 = _manager.GetOrCreate("chat-1");
        var s2 = _manager.GetOrCreate("chat-1");
        Assert.That(s1, Is.SameAs(s2));
    }

    [Test]
    public void GetOrCreate_ReturnsDistinctSessions_ForDifferentIds()
    {
        var s1 = _manager.GetOrCreate("chat-1");
        var s2 = _manager.GetOrCreate("chat-2");
        Assert.That(s1, Is.Not.SameAs(s2));
        Assert.That(_manager.Count, Is.EqualTo(2));
    }

    [Test]
    public void Sessions_AreIsolated_BetweenConversations()
    {
        var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };

        var chat1 = _manager.GetOrCreate("chat-1");
        var chat2 = _manager.GetOrCreate("chat-2");

        var r1 = analyzer.Analyze("email chat1@example.com", "en", chat1);
        var r2 = analyzer.Analyze("email chat2@example.com", "en", chat2);

        // Both sessions independently start numbering from [PG_1]; the mapped values must not cross over.
        Assert.That(chat1.Restore(r1.MaskedText), Does.Contain("chat1@example.com"));
        Assert.That(chat2.Restore(r2.MaskedText), Does.Contain("chat2@example.com"));
        Assert.That(chat1.Restore(r2.MaskedText), Does.Not.Contain("chat2@example.com"),
            "Restoring one conversation's masked text with another conversation's session must not leak data");
    }

    [Test]
    public void TryGet_ReturnsFalse_ForUnknownId()
    {
        Assert.That(_manager.TryGet("unknown", out var session), Is.False);
        Assert.That(session, Is.Null);
    }

    [Test]
    public void TryGet_ReturnsTrue_ForKnownId()
    {
        _manager.GetOrCreate("chat-1");
        Assert.That(_manager.TryGet("chat-1", out var session), Is.True);
        Assert.That(session, Is.Not.Null);
    }

    [Test]
    public void Remove_DropsSession()
    {
        _manager.GetOrCreate("chat-1");
        Assert.That(_manager.Remove("chat-1"), Is.True);
        Assert.That(_manager.Count, Is.EqualTo(0));
        Assert.That(_manager.Remove("chat-1"), Is.False, "Removing twice should report false the second time");
    }

    [Test]
    public void Clear_RemovesAllSessions()
    {
        _manager.GetOrCreate("chat-1");
        _manager.GetOrCreate("chat-2");
        _manager.Clear();
        Assert.That(_manager.Count, Is.EqualTo(0));
    }

    [Test]
    public void GetActiveSessionIds_ReflectsCurrentState()
    {
        _manager.GetOrCreate("chat-1");
        _manager.GetOrCreate("chat-2");
        Assert.That(_manager.GetActiveSessionIds(), Is.EquivalentTo(new[] { "chat-1", "chat-2" }));
    }

    [Test]
    public void PruneIdleSessions_RemovesOnlyStaleSessions()
    {
        _manager.GetOrCreate("stale");
        System.Threading.Thread.Sleep(50);
        _manager.GetOrCreate("fresh"); // touched after the idle window below

        var removed = _manager.PruneIdleSessions(TimeSpan.FromMilliseconds(25));

        Assert.That(removed, Is.EqualTo(1));
        Assert.That(_manager.TryGet("stale", out _), Is.False);
        Assert.That(_manager.TryGet("fresh", out _), Is.True);
    }

    [Test]
    public void ManySessions_CanBeCreatedConcurrently_WithoutCorruption()
    {
        // Simulates a gateway juggling many simultaneous chatbot/AI-provider conversations.
        System.Threading.Tasks.Parallel.For(0, 200, i => _manager.GetOrCreate($"chat-{i}"));
        Assert.That(_manager.Count, Is.EqualTo(200));
    }
}
