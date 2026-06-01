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

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Caveman.PrivacyGuard.Models;

internal class RulesDocumentJson
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "2.0";

    [JsonPropertyName("countries")]
    public List<CountryConfigJson> Countries { get; set; } = new();
}

internal class CountryConfigJson
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = "EU";

    [JsonPropertyName("language")]
    public string Language { get; set; } = "en";

    [JsonPropertyName("rules")]
    public List<RuleEntryJson> Rules { get; set; } = new();
}

internal class RuleEntryJson
{
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("pattern")]
    public string Pattern { get; set; } = string.Empty;

    [JsonPropertyName("base_weight")]
    public int BaseWeight { get; set; }

    [JsonPropertyName("validator_name")]
    public string? ValidatorName { get; set; }

    [JsonPropertyName("context_keywords")]
    public string[]? ContextKeywords { get; set; }

    [JsonPropertyName("is_high_confidence")]
    public bool IsHighConfidence { get; set; }

    [JsonPropertyName("compliance_tags")]
    public string[]? ComplianceTags { get; set; }
}
