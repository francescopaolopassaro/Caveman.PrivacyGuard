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

namespace Caveman.PrivacyGuard;

/// <summary>
/// Minimal, configurable router for chatbot-style commands (e.g. "/reset", "/help") that sits in front of
/// <see cref="PrivacyAnalyzer"/>: register named intents with a match predicate and a handler, then call
/// <see cref="TryRoute"/> on each incoming message. If no intent matches, the caller falls back to treating
/// the message as regular text to analyze/mask. Intended for chatbot backends or an AI-provider-facing
/// gateway that need to distinguish control commands from user content before it reaches the model.
/// </summary>
public class ChatIntentRouter
{
    private readonly List<(string Name, Func<string, bool> Match, Action<string> Handler)> _intents = new();

    /// <summary>Names of all currently registered intents, in registration order.</summary>
    public IReadOnlyList<string> RegisteredIntents => _intents.Select(i => i.Name).ToList();

    /// <summary>Registers an intent with a custom match predicate.</summary>
    public void Register(string name, Func<string, bool> match, Action<string> handler) =>
        _intents.Add((name, match, handler));

    /// <summary>Registers an intent that matches a single exact command (e.g. "/reset"), case-insensitively.</summary>
    public void RegisterCommand(string command, Action<string> handler) =>
        Register(command, input => input.Trim().Equals(command, StringComparison.OrdinalIgnoreCase), handler);

    /// <summary>Removes a previously registered intent by name. Returns true if it existed.</summary>
    public bool Unregister(string name)
    {
        var idx = _intents.FindIndex(i => i.Name == name);
        if (idx < 0) return false;
        _intents.RemoveAt(idx);
        return true;
    }

    /// <summary>Removes all registered intents.</summary>
    public void Clear() => _intents.Clear();

    /// <summary>
    /// Attempts to route <paramref name="input"/> to the first matching registered intent (in registration
    /// order) and invokes its handler. Returns the matched intent's name, or null if nothing matched —
    /// in which case the caller should treat <paramref name="input"/> as plain content for analysis.
    /// </summary>
    public string? TryRoute(string input)
    {
        foreach (var intent in _intents)
        {
            if (intent.Match(input))
            {
                intent.Handler(input);
                return intent.Name;
            }
        }
        return null;
    }
}
