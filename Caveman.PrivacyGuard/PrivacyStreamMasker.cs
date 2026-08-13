// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Boundary-safe chunked/streaming PII masking, built on top of the existing
// PrivacyAnalyzer/PrivacySession primitives (no scoring logic is reimplemented
// here). Ported from Synthelion 1.2.5 `privacy_stream.py`.
// ------------------------------------------------------------------------------

using System.Collections.Generic;

namespace Caveman.PrivacyGuard;

/// <summary>
/// Boundary-safe chunked/streaming PII masking. Backs two use cases: (a) reading a
/// large file in pieces without loading it whole into memory, and (b) masking live,
/// incrementally-arriving text (e.g. an LLM's streamed output) as it comes in.
/// </summary>
/// <remarks>
/// Overlap sizing: the bounded categories (IBAN, credit cards, tax IDs, etc.) all match
/// well under 100 characters; the default <c>overlapChars = 512</c> covers them
/// generously. Two categories use unbounded patterns (JWT, generic secret/password
/// <c>\S{8,}</c>) — a match of one of those that is split across a chunk boundary by
/// more than <c>overlapChars</c> characters is a known residual risk, not something a
/// finite overlap window can fully eliminate. Choose a larger <c>overlapChars</c> for
/// deployments where this matters.
/// </remarks>
public sealed class PrivacyStreamMasker
{
    private readonly object _lock = new();
    private readonly PrivacyAnalyzer _analyzer;
    private readonly PrivacySession? _session;
    private readonly string _language;
    private readonly int _overlapChars;
    private string _buffer = string.Empty;

    /// <summary>
    /// Initializes a new masker. If <paramref name="analyzer"/> is null a dedicated
    /// <see cref="PrivacyAnalyzer"/> is created with <see cref="PrivacyAnalyzer.EnableAutoMasking"/>
    /// forced on; when one is supplied it is used as-is but auto-masking is enabled on it
    /// too, since this masker only ever produces masked text.
    /// </summary>
    public PrivacyStreamMasker(
        PrivacyAnalyzer? analyzer = null,
        PrivacySession? session = null,
        string language = "en",
        int overlapChars = 512)
    {
        _analyzer = analyzer ?? new PrivacyAnalyzer();
        _analyzer.EnableAutoMasking = true;
        _session = session;
        _language = language;
        _overlapChars = System.Math.Max(0, overlapChars);
    }

    /// <summary>
    /// Appends <paramref name="chunk"/> to the internal tail buffer and returns the
    /// masked-safe prefix (everything except the last <c>overlapChars</c> characters,
    /// held back in case a PII pattern spans the boundary with the next chunk).
    /// Returns an empty string when there isn't yet enough buffered text to safely
    /// emit anything.
    /// </summary>
    public string Feed(string chunk)
    {
        if (string.IsNullOrEmpty(chunk))
            return string.Empty;

        string safePart;
        lock (_lock)
        {
            _buffer += chunk;
            if (_buffer.Length <= _overlapChars)
                return string.Empty;

            int split = _buffer.Length - _overlapChars;
            safePart = _buffer.Substring(0, split);
            _buffer = _buffer.Substring(split);
        }

        return Mask(safePart);
    }

    /// <summary>
    /// Masks and returns whatever remains in the tail buffer. Call once, after the last
    /// <see cref="Feed"/>, when the input stream is exhausted.
    /// </summary>
    public string Flush()
    {
        string remainder;
        lock (_lock)
        {
            remainder = _buffer;
            _buffer = string.Empty;
        }

        return Mask(remainder);
    }

    /// <summary>
    /// Optional hook invoked with each analyzed chunk's <see cref="PrivacyAnalysisResult"/>
    /// (including the final <see cref="Flush"/> remainder). Useful for callers that want
    /// to tally e.g. <see cref="PrivacyAnalysisResult.MatchCount"/> without re-analyzing.
    /// </summary>
    public System.Action<PrivacyAnalysisResult>? OnChunkAnalyzed { get; set; }

    private string Mask(string text)
    {
        // Whitespace-only segment: nothing to analyze, pass through as-is (analyze()
        // would otherwise collapse it to an empty result via its empty-text early
        // return, silently dropping real whitespace/newlines).
        if (string.IsNullOrWhiteSpace(text))
            return text;

        var result = _analyzer.Analyze(text, _language, _session);
        OnChunkAnalyzed?.Invoke(result);
        return string.IsNullOrEmpty(result.MaskedText) ? text : result.MaskedText;
    }

    /// <summary>
    /// Convenience wrapper around <see cref="PrivacyStreamMasker"/>: masks an iterable of
    /// text chunks (from a chunked file read or a live text stream), yielding masked
    /// pieces as they become safe to emit, plus the final remainder once
    /// <paramref name="chunks"/> is exhausted.
    /// </summary>
    public static IEnumerable<string> MaskStream(
        IEnumerable<string> chunks,
        PrivacySession? session = null,
        string language = "en",
        int overlapChars = 512,
        PrivacyAnalyzer? analyzer = null)
    {
        var masker = new PrivacyStreamMasker(analyzer, session, language, overlapChars);
        foreach (var chunk in chunks)
        {
            var output = masker.Feed(chunk);
            if (!string.IsNullOrEmpty(output))
                yield return output;
        }

        var tail = masker.Flush();
        if (!string.IsNullOrEmpty(tail))
            yield return tail;
    }
}
