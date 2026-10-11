// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Optional ML confirmation tier. PrivacyAnalyzer's core tier is regex + algorithmic checksum (or a context
// keyword for rules with no checksum) and stays zero-ML and the default. A learned detector - e.g. the
// PrivacyGuardML model shipped by the CavemanML package - can be plugged in through IMlEntityDetector as an
// opt-in *confirmation signal*: a value that matches a requires_context rule but has no context keyword nearby
// is confirmed by an overlapping prediction. A failed checksum still vetoes the detection regardless of what the
// model says, so the tier can only recover recall the strict context gate trades away - it can never introduce a
// false positive the validator would reject.
// ------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Linq;

namespace Caveman.PrivacyGuard;

/// <summary>One entity found by an ML detector, with character offsets into the analysed text.</summary>
public sealed record MlSpan(int Start, int End, string Value, string Label, double Confidence);

/// <summary>A learned PII detector that can confirm bare values the context gate would otherwise reject.</summary>
public interface IMlEntityDetector
{
    /// <summary>Returns the entities found in <paramref name="text"/>. Must not throw; return an empty list when unavailable.</summary>
    IReadOnlyList<MlSpan> Detect(string text);
}

/// <summary>Which analyzer categories each ML entity label is allowed to confirm.</summary>
/// <remarks>
/// Strict on purpose: a "phone number" span must not turn a bare ID run into a phone detection and an "ID number"
/// span must not confirm the Phone rule - the model's semantic judgement is coupled to the right rule family.
/// Labels outside this table confirm nothing.
/// </remarks>
public static class MlLabelCategories
{
    private static readonly string[] PersonalIds =
    {
        "Email", "Phone E.164", "Italian Tax Code (CF)", "Spanish Tax/ID Number (NIF/NIE)", "Polish PESEL",
        "Dutch BSN", "French Social Security (NIR)", "Swedish Personal ID", "Danish CPR Number", "Finnish Personal ID (Hetu)",
        "Irish PPSN", "Belgian National Registry", "Czech Birth Number", "Romanian Personal Code (CNP)", "Bulgarian EGN",
        "Croatian OIB", "Slovenian EMSO", "Lithuanian Personal Code", "Latvian Personal Code", "Estonian Personal ID",
        "German Tax ID (Steuer-Id)", "Hungarian Tax ID", "Portuguese Tax Number (NIF)", "Greek Tax Number (AFM)",
        "Cypriot ID Number", "Maltese ID Number", "Luxembourg National ID", "Slovak Birth Number",
    };

    private static readonly Dictionary<string, HashSet<string>> Table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["phone number"] = new() { "Phone E.164" },
        ["email address"] = new() { "Email" },
        ["credit card number"] = new() { "Credit Card" },
        ["iban number"] = new() { "IBAN" },
        ["bank account number"] = new() { "IBAN" },
        ["bank account number (iban)"] = new() { "IBAN" },
        ["national identification number"] = new(PersonalIds.Where(c => c != "Email" && c != "Phone E.164").Concat(new[]
        {
            "Maltese ID Number", "German ID Card", "UK National Insurance Number (NINO)", "Swiss AHV/AVS Number", "Chinese Resident ID Number",
        })),
        ["tax identification number"] = new()
        {
            "Italian Tax Code (CF)", "German Tax ID (Steuer-Id)", "Hungarian Tax ID", "Portuguese Tax Number (NIF)",
            "Greek Tax Number (AFM)", "Polish VAT (NIP)", "Italian VAT Number", "Spanish Tax/ID Number (NIF/NIE)",
            "Czech Business ID", "Russian Taxpayer ID (INN)", "Ukrainian Taxpayer Number (RNOKPP)",
        },
        ["social security number"] = new() { "French Social Security (NIR)", "Austrian Social Insurance", "Greek Social Security (AMKA)" },
        ["gps coordinates"] = new() { "GPS Coordinates" },
        ["passport number"] = new(),
        ["driver license number"] = new(),
        ["vehicle license plate"] = new() { "EU Vehicle License Plate" },
        ["employee badge id"] = new() { "Employee / Badge ID" },
        ["business identification number"] = new() { "French Business ID (SIREN/SIRET)", "Austrian VAT (UID)" },
        ["credential or secret"] = new() { "Password/Secret", "JWT/Token" },
        ["social media handle"] = new() { "Social / Messenger Handle" },
        ["legal case number"] = new() { "Legal Case / File Number" },
        ["booking reference"] = new() { "PNR / Booking Code" },
        ["minor age indicator"] = new() { "Minor Data (<16)" },
    };

    /// <summary>True when an ML entity <paramref name="label"/> (e.g. "national identification number") may confirm <paramref name="category"/>.</summary>
    public static bool Allows(string? label, string category)
    {
        var key = (label ?? "").Trim().ToLowerInvariant().TrimEnd('.');
        return Table.TryGetValue(key, out var set) && set.Contains(category);
    }
}
