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

using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Caveman.PrivacyGuard;

/// <summary>Represents a single placeholder-to-original mapping in a session.</summary>
public record PlaceholderEntry
{
    /// <summary>The original sensitive value that was masked.</summary>
    public required string OriginalValue { get; init; }

    /// <summary>The detection category (e.g. "Email", "IBAN").</summary>
    public required string Category { get; init; }

    /// <summary>The placeholder token (e.g. "[PG_1]").</summary>
    public required string Placeholder { get; init; }
}

/// <summary>Result of a restore operation with the restored text and a count of replaced placeholders.</summary>
public record RestoreResult(string Text, int RestoredCount);

/// <summary>Read-only interface for a privacy session. Useful for APIs that should not mutate the session.</summary>
public interface IReadOnlySession
{
    /// <summary>Number of unique placeholder entries.</summary>
    int Count { get; }
    /// <summary>Gets the entry for a placeholder token, or null if not found.</summary>
    PlaceholderEntry? GetEntry(string placeholder);
    /// <summary>Returns a snapshot of all placeholder entries.</summary>
    IReadOnlyDictionary<string, PlaceholderEntry> GetAll();
    /// <summary>Replaces all placeholders in the given text with their original values.</summary>
    string Restore(string text);
    /// <summary>Replaces all placeholders and returns both the restored text and count of replacements.</summary>
    RestoreResult RestoreDetailed(string text);
}

/// <summary>
/// Thread-safe session that maps unique placeholders to original sensitive values.
/// Use with <see cref="PrivacyAnalyzer"/> to mask PII before sending to AI,
/// then restore original values in the AI response client-side.
/// </summary>
public class PrivacySession : IReadOnlySession
{
    private readonly ConcurrentDictionary<string, PlaceholderEntry> _map = new();
    private readonly ConcurrentDictionary<string, string> _valueIndex = new(StringComparer.Ordinal);
    private int _counter;

    private static readonly Regex PlaceholderPattern = new(@"\[PG_\d+\]", RegexOptions.Compiled);

    /// <summary>Number of unique placeholder entries in this session.</summary>
    public int Count => _map.Count;

    /// <summary>Adds or retrieves a placeholder for the given value. Reuses the same placeholder for duplicate values.</summary>
    internal string AddEntry(string category, string originalValue)
    {
        if (_valueIndex.TryGetValue(originalValue, out var existingPlaceholder))
            return existingPlaceholder;

        var id = Interlocked.Increment(ref _counter);
        var placeholder = $"[PG_{id}]";
        var entry = new PlaceholderEntry
        {
            OriginalValue = originalValue,
            Category = category,
            Placeholder = placeholder
        };
        _map[placeholder] = entry;
        _valueIndex[originalValue] = placeholder;
        return placeholder;
    }

    /// <summary>Adds or retrieves a placeholder for the given value. Reuses the same placeholder for duplicate values.</summary>
    public string AddOrGet(string category, string originalValue) =>
        AddEntry(category, originalValue);

    /// <summary>
    /// Replaces all placeholders (e.g. <c>[PG_1]</c>) in the given text with their original values.
    /// Unknown placeholders are left unchanged.
    /// </summary>
    public string Restore(string text)
    {
        if (string.IsNullOrEmpty(text) || _map.IsEmpty)
            return text;

        return PlaceholderPattern.Replace(text, m =>
            _map.TryGetValue(m.Value, out var entry) ? entry.OriginalValue : m.Value);
    }

    /// <summary>
    /// Replaces all placeholders and returns both the restored text and a count of how many were replaced.
    /// </summary>
    public RestoreResult RestoreDetailed(string text)
    {
        if (string.IsNullOrEmpty(text) || _map.IsEmpty)
            return new RestoreResult(text ?? string.Empty, 0);

        int count = 0;
        var result = PlaceholderPattern.Replace(text, m =>
        {
            if (_map.TryGetValue(m.Value, out var entry))
            {
                count++;
                return entry.OriginalValue;
            }
            return m.Value;
        });

        return new RestoreResult(result, count);
    }

    /// <summary>Gets the entry for a placeholder token, or null if not found.</summary>
    public PlaceholderEntry? GetEntry(string placeholder)
    {
        _map.TryGetValue(placeholder, out var entry);
        return entry;
    }

    /// <summary>Returns a snapshot of all placeholder entries.</summary>
    public IReadOnlyDictionary<string, PlaceholderEntry> GetAll() =>
        new Dictionary<string, PlaceholderEntry>(_map);

    /// <summary>Merges entries from another session into this one. Duplicate values are skipped.</summary>
    public void MergeFrom(PrivacySession other)
    {
        foreach (var kvp in other.GetAll())
        {
            if (!_valueIndex.ContainsKey(kvp.Value.OriginalValue))
            {
                AddEntry(kvp.Value.Category, kvp.Value.OriginalValue);
            }
        }
    }

    /// <summary>Removes all placeholder entries and resets the counter.</summary>
    public void Clear()
    {
        _map.Clear();
        _valueIndex.Clear();
        _counter = 0;
    }

    /// <summary>Exports all entries as a JSON string for persistence.</summary>
    public string ToJson()
    {
        var entries = _map.Select(kvp => new
        {
            placeholder = kvp.Key,
            original_value = kvp.Value.OriginalValue,
            category = kvp.Value.Category
        }).ToList();

        return System.Text.Json.JsonSerializer.Serialize(new
        {
            counter = _counter,
            entries
        });
    }

    /// <summary>Creates a new session from a JSON string produced by <see cref="ToJson"/>.</summary>
    public static PrivacySession FromJson(string json)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        var session = new PrivacySession();
        session._counter = root.GetProperty("counter").GetInt32();
        foreach (var e in root.GetProperty("entries").EnumerateArray())
        {
            var p = e.GetProperty("placeholder").GetString()!;
            var o = e.GetProperty("original_value").GetString()!;
            var c = e.GetProperty("category").GetString()!;
            session._map[p] = new PlaceholderEntry { OriginalValue = o, Category = c, Placeholder = p };
            session._valueIndex[o] = p;
        }
        return session;
    }

    /// <summary>Merges entries from a JSON string into this session. Duplicate values are skipped.</summary>
    public void ImportFromJson(string json)
    {
        var other = FromJson(json);
        MergeFrom(other);
    }
}
