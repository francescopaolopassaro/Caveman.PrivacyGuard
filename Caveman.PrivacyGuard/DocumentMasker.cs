// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Per-format document extraction and in-place PII masking.
// CSV/Markdown/plain-text are read in chunks (never the whole file in RAM).
// Ported from Synthelion 1.2.5 `document_extractor.py` (PDF/DOCX/XLSX require
// optional external libraries in the Python port and are intentionally out of
// scope here — this library stays dependency-free).
// ------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Caveman.PrivacyGuard;

/// <summary>Result of a masked-document write: the masked copy's path, detected format, and the total PII match count.</summary>
public record MaskDocumentResult(string InputPath, string OutputPath, string Format, int MaskedMatchCount);

/// <summary>
/// Streaming PII masking over text documents (plain text, Markdown, CSV). A file is
/// read in chunks and masked through a <see cref="PrivacyStreamMasker"/> so a large
/// document is never held whole in memory; the result is written to a new
/// "<c>name.masked.ext</c>" copy next to the source — the original file is never
/// overwritten. Extension-based format dispatch; unrecognized extensions fall back to
/// plain text rather than raising.
/// </summary>
public static class DocumentMasker
{
    private const int DefaultOverlapChars = 512;
    private const int DefaultChunkChars = 8192;
    private const int DefaultChunkRows = 500;

    /// <summary>Extension-based format dispatch. Unrecognized extensions fall back to plain text (".txt" behavior).</summary>
    public static string DetectFormat(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        switch (ext)
        {
            case ".csv":
                return "csv";
            case ".md":
            case ".markdown":
                return "md";
            default:
                return "txt";
        }
    }

    /// <summary>
    /// Masks PII in the file at <paramref name="inputPath"/> and writes a masked copy
    /// to <paramref name="outputPath"/> (default <c>name.masked.ext</c> next to the
    /// source). Returns the masked copy's path, detected format, and total match count.
    /// </summary>
    public static MaskDocumentResult MaskFile(
        string inputPath,
        string? outputPath = null,
        string language = "en",
        PrivacyAnalyzer? analyzer = null,
        PrivacySession? session = null,
        int overlapChars = DefaultOverlapChars,
        int chunkChars = DefaultChunkChars,
        int chunkRows = DefaultChunkRows,
        Encoding? encoding = null)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new ArgumentException("A file path is required.", nameof(inputPath));
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("The source document was not found.", inputPath);

        var format = DetectFormat(inputPath);

        // netstandard2.0 does not annotate string.IsNullOrEmpty with NotNullWhen(false),
        // so guarantee a non-null path in a local regardless of target framework.
        string resolvedOutputPath = string.IsNullOrEmpty(outputPath)
            ? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(inputPath)) ?? string.Empty,
                Path.GetFileNameWithoutExtension(inputPath) + ".masked" + Path.GetExtension(inputPath))
            : outputPath!;

        var enc = encoding ?? new UTF8Encoding(false);
        var masker = new PrivacyStreamMasker(analyzer, session, language, overlapChars);
        int totalMatches = 0;
        masker.OnChunkAnalyzed = r => totalMatches += r.MatchCount;

        using (var output = new StreamWriter(resolvedOutputPath, false, enc))
        {
            if (format == "csv")
                foreach (var piece in CsvChunks(inputPath, chunkRows, enc))
                    output.Write(masker.Feed(piece));
            else
                using (var input = new StreamReader(inputPath, enc))
                {
                    var buffer = new char[chunkChars];
                    int read;
                    while ((read = input.Read(buffer, 0, chunkChars)) > 0)
                        output.Write(masker.Feed(new string(buffer, 0, read)));
                }

            output.Write(masker.Flush());
        }

        return new MaskDocumentResult(inputPath, resolvedOutputPath, format, totalMatches);
    }

    private static IEnumerable<string> CsvChunks(string path, int chunkRows, Encoding encoding)
    {
        using var reader = new StreamReader(path, encoding);
        var rows = new List<string>();
        int count = 0;

        while (TryReadCsvRow(reader, out var row))
        {
            rows.Add(row);
            count++;
            if (count >= chunkRows)
            {
                yield return string.Join("\n", rows) + "\n";
                rows.Clear();
                count = 0;
            }
        }

        if (rows.Count > 0)
            yield return string.Join("\n", rows) + "\n";
    }

    // Minimal RFC-4180-aware row reader: splits on newlines only when not inside a
    // quoted field, supporting escaped quotes (""), so multi-line quoted cells are
    // preserved as a single logical row for masking.
    private static bool TryReadCsvRow(StreamReader reader, out string row)
    {
        var sb = new StringBuilder();
        bool inQuotes = false;
        bool readAny = false;
        int c;

        while ((c = reader.Read()) >= 0)
        {
            readAny = true;
            var ch = (char)c;

            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (reader.Peek() == '"')
                    {
                        reader.Read();
                        sb.Append('"');
                        continue;
                    }

                    inQuotes = false;
                    sb.Append('"');
                    continue;
                }

                sb.Append(ch);
                continue;
            }

            if (ch == '"')
            {
                inQuotes = true;
                sb.Append('"');
                continue;
            }

            if (ch == '\n')
                break;

            if (ch != '\r')
                sb.Append(ch);
        }

        row = sb.ToString();
        return readAny;
    }
}