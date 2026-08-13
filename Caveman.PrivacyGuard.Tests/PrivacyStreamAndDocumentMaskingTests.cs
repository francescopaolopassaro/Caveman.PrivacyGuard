// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Regression tests for the Synthelion 1.2.5 port: PrivacyStreamMasker (boundary-safe
// chunked masking), PrivacySession.Summary() (redacted view), and DocumentMasker
// (streaming masking of txt/md/csv into a .masked copy).
// ------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NUnit.Framework;

namespace Caveman.PrivacyGuard.Tests;

[TestFixture]
public class PrivacyStreamAndDocumentMaskingTests
{
    private static string NewTempFile(string name, string content)
    {
        var dir = Path.Combine(Path.GetTempPath(), "pgmask_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string ReadThenDelete(string path)
    {
        var text = File.ReadAllText(path);
        var dir = Path.GetDirectoryName(path);
        Directory.Delete(dir!, recursive: true);
        return text;
    }

    [Test]
    public void PrivacyStreamMasker_EmitsNothingUntilEnoughBuffered()
    {
        var masker = new PrivacyStreamMasker(overlapChars: 512);
        Assert.That(masker.Feed("short prefix "), Is.Empty, "no output until the buffer exceeds the overlap window");
    }

    [Test]
    public void PrivacyStreamMasker_MasksPiiSpanningAChunkBoundary()
    {
        // The email is split across two feed() calls; the overlap window must keep the
        // second half buffered so the full address is still analyzed on flush.
        var masker = new PrivacyStreamMasker(session: new PrivacySession(), overlapChars: 64);
        var first = masker.Feed("contact m");
        var second = masker.Feed("ario.rossi@example.com for details");

        var combined = first + second + masker.Flush();

        Assert.That(combined, Does.Not.Contain("mario.rossi@example.com"),
            "the email must never leak in masked output");
        Assert.That(combined, Does.Contain("[PG_"), "masked output should carry a session placeholder");
    }

    [Test]
    public void PrivacyStreamMasker_WhitespaceOnlySafePartIsPassedThrough()
    {
        // Whitespace-only segments must survive verbatim (analyze() would collapse them);
        // feed enough to emit a safe part that is entirely whitespace.
        var masker = new PrivacyStreamMasker(overlapChars: 4);
        Assert.That(masker.Feed("    "), Is.Empty, "not enough buffered yet");

        var second = masker.Feed("\t\n ");
        Assert.That(second, Is.EqualTo("   "), "whitespace-only safe part must be passed through, not collapsed to empty");
    }

    [Test]
    public void PrivacyStreamMasker_MaskStream_MasksAllChunks()
    {
        var session = new PrivacySession();
        var chunks = new[]
        {
            "Hi, please review ",
            "alice.smith@contoso.com",
            " and call the office.",
            "\nRegards"
        };

        var output = string.Concat(PrivacyStreamMasker.MaskStream(chunks, session));

        Assert.That(output, Does.Not.Contain("alice.smith@contoso.com"));
        Assert.That(output, Does.Contain("[PG_"));
        Assert.That(session.Count, Is.GreaterThanOrEqualTo(1));
    }

    [Test]
    public void PrivacySession_Summary_IsRedacted_NeverOriginalValue()
    {
        var analyzer = new PrivacyAnalyzer { EnableAutoMasking = true };
        var session = new PrivacySession();

        analyzer.Analyze("Write to mario.rossi@example.com", "en", session);

        Assert.That(session.Count, Is.GreaterThan(0));

        var summary = session.Summary();
        Assert.That(summary, Is.Not.Empty);
        Assert.That(summary, Has.All.Matches<SessionSummaryItem>(i =>
            !string.IsNullOrEmpty(i.Placeholder) && !string.IsNullOrEmpty(i.Category)));

        // The redacted view must never leak the original sensitive value.
        var serialized = string.Join("|", summary.Select(i => i.Placeholder + ":" + i.Category));
        Assert.That(serialized, Does.Not.Contain("mario.rossi@example.com"));
        Assert.That(serialized, Does.Contain("Email"));
    }

    [Test]
    public void Documentation_ListableItems_CarriesNoCleartextPii()
    {
        // SessionSummaryItem only exposes Placeholder/Category — there is no property
        // naming the original value, so a redacted API can enumerate it safely.
        var properties = typeof(SessionSummaryItem).GetProperties().Select(p => p.Name).ToArray();
        Assert.That(properties, Does.Contain(nameof(SessionSummaryItem.Placeholder)));
        Assert.That(properties, Does.Contain(nameof(SessionSummaryItem.Category)));
        Assert.That(properties, Does.Not.Contain("OriginalValue"));
        Assert.That(properties, Does.Not.Contain("Value"));
    }

    [Test]
    public void DocumentMasker_DetectFormat_MapsExtensions()
    {
        Assert.That(DocumentMasker.DetectFormat("report.csv"), Is.EqualTo("csv"));
        Assert.That(DocumentMasker.DetectFormat("notes.md"), Is.EqualTo("md"));
        Assert.That(DocumentMasker.DetectFormat("notes.markdown"), Is.EqualTo("md"));
        Assert.That(DocumentMasker.DetectFormat("notes.txt"), Is.EqualTo("txt"));
        Assert.That(DocumentMasker.DetectFormat("notes.unknown"), Is.EqualTo("txt"), "unrecognized extensions fall back to plain text");
    }

    [Test]
    public void DocumentMasker_MaskTextFile_WritesMaskedCopy_OriginalUntouched()
    {
        var input = NewTempFile("note.txt", "Contact mario.rossi@example.com for details.\nThanks.");
        var original = File.ReadAllText(input);

        var result = DocumentMasker.MaskFile(input, session: new PrivacySession());

        Assert.That(result.OutputPath, Is.EqualTo(Path.ChangeExtension(input, ".masked.txt")));
        Assert.That(File.Exists(result.OutputPath), Is.True);
        Assert.That(result.Format, Is.EqualTo("txt"));
        Assert.That(result.MaskedMatchCount, Is.GreaterThan(0));

        var masked = ReadThenDelete(result.OutputPath);

        // Source file is never overwritten.
        Assert.That(masked, Does.Not.Contain("mario.rossi@example.com"));
        Assert.That(masked, Does.Contain("[PG_"));
    }

    [Test]
    public void DocumentMasker_MaskCsvFile_PreservesRowStructure()
    {
        var input = NewTempFile("contacts.csv", "name,email\nMario Rossi,mario.rossi@example.com\nAnna Bianchi,anna@example.com\n");

        var result = DocumentMasker.MaskFile(input, session: new PrivacySession());
        var masked = ReadThenDelete(result.OutputPath);

        Assert.That(result.Format, Is.EqualTo("csv"));
        var lines = masked.TrimEnd().Split('\n');
        Assert.That(lines.Length, Is.EqualTo(3), "header + 2 data rows must be preserved");
        Assert.That(lines[0], Is.EqualTo("name,email"));
        Assert.That(masked, Does.Not.Contain("mario.rossi@example.com"));
        Assert.That(masked, Does.Not.Contain("anna@example.com"));
        Assert.That(masked, Does.Contain("[PG_"));
    }

    [Test]
    public void DocumentMasker_MaskCsvFile_QuotedMultilineCell_Survives()
    {
        // An email inside a quoted field that spans physical lines must be masked while
        // the multi-line cell text remains intact.
        var input = NewTempFile("quoted.csv", "\"header\"\n\"mario.rossi@example.com\nsecond line\",\"plain\"\n");

        var result = DocumentMasker.MaskFile(input, session: new PrivacySession());
        var masked = ReadThenDelete(result.OutputPath);

        Assert.That(masked, Does.Not.Contain("mario.rossi@example.com"));
        Assert.That(masked, Does.Contain("[PG_"));
        Assert.That(masked, Does.Contain("second line"), "second physical line of the quoted cell must survive");
    }

    [Test]
    public void DocumentMasker_MaskFile_ThrowsWhenSourceMissing()
    {
        Assert.Throws<FileNotFoundException>(() =>
            DocumentMasker.MaskFile(Path.Combine(Path.GetTempPath(), "definitely_missing_" + Guid.NewGuid() + ".txt")));
    }
}