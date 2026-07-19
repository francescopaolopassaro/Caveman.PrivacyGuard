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
using System.Collections.Generic;
using YamlDotNet.Serialization;

namespace Caveman.PrivacyGuard.Models;

public class RulesDocument
{
    [YamlMember(Alias = "version")]
    public string Version { get; set; } = "2.0";

    [YamlMember(Alias = "global_context_keywords")]
    public List<string> GlobalContextKeywords { get; set; } = new();

    [YamlMember(Alias = "countries")]
    public List<CountryConfig> Countries { get; set; } = new();
}

public class CountryConfig
{
    [YamlMember(Alias = "code")]
    public string Code { get; set; } = "EU";

    [YamlMember(Alias = "language")]
    public string Language { get; set; } = "en";

    [YamlMember(Alias = "rules")]
    public List<RuleEntry> Rules { get; set; } = new();
}

public class RuleEntry
{
    [YamlMember(Alias = "category")]
    public string Category { get; set; } = string.Empty;

    [YamlMember(Alias = "pattern")]
    public string Pattern { get; set; } = string.Empty;

    [YamlMember(Alias = "base_weight")]
    public int BaseWeight { get; set; }

    [YamlMember(Alias = "validator_name")]
    public string? ValidatorName { get; set; }

    [YamlMember(Alias = "context_keywords")]
    public string[]? ContextKeywords { get; set; }

    [YamlMember(Alias = "is_high_confidence")]
    public bool IsHighConfidence { get; set; }

    [YamlMember(Alias = "compliance_tags")]
    public string[] ComplianceTags { get; set; } = Array.Empty<string>();
}