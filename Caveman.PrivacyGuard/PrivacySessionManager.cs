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

using System.Collections.Concurrent;

namespace Caveman.PrivacyGuard;

/// <summary>
/// Thread-safe registry of <see cref="PrivacySession"/> instances keyed by an arbitrary session id
/// (e.g. a conversation id, chat/user id, or tenant id). Intended for services that talk to many
/// independent conversations at once (multi-chatbot backends, an AI-provider-facing gateway, etc.),
/// where each conversation needs its own isolated placeholder mapping.
/// </summary>
public class PrivacySessionManager
{
    private readonly ConcurrentDictionary<string, (PrivacySession Session, DateTime LastAccessedUtc)> _sessions = new();

    /// <summary>Number of active sessions currently tracked.</summary>
    public int Count => _sessions.Count;

    /// <summary>Gets the existing session for <paramref name="sessionId"/>, or creates and registers a new one.</summary>
    public PrivacySession GetOrCreate(string sessionId)
    {
        var entry = _sessions.AddOrUpdate(
            sessionId,
            _ => (new PrivacySession(), DateTime.UtcNow),
            (_, existing) => (existing.Session, DateTime.UtcNow));
        return entry.Session;
    }

    /// <summary>Attempts to retrieve an existing session without creating one. Updates its last-accessed time on hit.</summary>
    public bool TryGet(string sessionId, out PrivacySession? session)
    {
        if (_sessions.TryGetValue(sessionId, out var entry))
        {
            _sessions[sessionId] = (entry.Session, DateTime.UtcNow);
            session = entry.Session;
            return true;
        }
        session = null;
        return false;
    }

    /// <summary>Removes a session, discarding its placeholder mappings. Returns true if it existed.</summary>
    public bool Remove(string sessionId) => _sessions.TryRemove(sessionId, out _);

    /// <summary>Removes all tracked sessions.</summary>
    public void Clear() => _sessions.Clear();

    /// <summary>Ids of all currently tracked sessions.</summary>
    public IReadOnlyCollection<string> GetActiveSessionIds() => _sessions.Keys.ToList();

    /// <summary>
    /// Removes sessions that have not been accessed (via <see cref="GetOrCreate"/> or <see cref="TryGet"/>)
    /// for at least <paramref name="maxIdle"/>. Call periodically in long-running services (e.g. a chatbot
    /// gateway serving many concurrent users) to bound memory usage. Returns the number of sessions removed.
    /// </summary>
    public int PruneIdleSessions(TimeSpan maxIdle)
    {
        var cutoff = DateTime.UtcNow - maxIdle;
        var removed = 0;
        foreach (var kvp in _sessions)
        {
            if (kvp.Value.LastAccessedUtc < cutoff && _sessions.TryRemove(kvp.Key, out _))
                removed++;
        }
        return removed;
    }
}
