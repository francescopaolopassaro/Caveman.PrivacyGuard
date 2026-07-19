// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
//
// Enterprise-grade PII & Privacy Analyzer for AI/LLM workflows.
// Detects, scores, and auto-masks sensitive data across 32 countries (27 EU + UK, Switzerland, China, Russia, Ukraine) with
// GDPR/AI Act/NIS2/PCI-DSS/NIST compliance flags, multi-language support, and YAML-driven
// extensible rules. Thread-safe, embedded resources, zero external dependencies.
// ------------------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace Caveman.PrivacyGuard;

/// <summary>Risk level for a prompt injection scan.</summary>
public enum PromptInjectionRisk { Safe, Low, Medium, High, Critical }

/// <summary>Result of scanning a piece of text for prompt-injection patterns.</summary>
public record PromptInjectionResult
{
    /// <summary>Risk score from 0 (clean) to 100 (near-certain injection attempt).</summary>
    public int Score { get; init; }

    /// <summary>Overall risk level derived from <see cref="Score"/>.</summary>
    public PromptInjectionRisk RiskLevel { get; init; }

    /// <summary>Names of the pattern categories that matched (e.g. "Instruction Override", "Role Hijack").</summary>
    public List<string> DetectedCategories { get; init; } = new();

    /// <summary>True when no injection pattern matched at all (Score == 0).</summary>
    public bool IsClean => DetectedCategories.Count == 0;
}

/// <summary>
/// Heuristic, regex-based scanner for prompt-injection attempts in untrusted text before it reaches an
/// LLM (user messages, tool outputs, retrieved documents, etc.). Complements <see cref="PrivacyAnalyzer"/>:
/// where that class protects data flowing OUT to the model, this class screens instructions trying to
/// sneak IN and hijack the model's behavior. Detection is heuristic and cannot catch every technique —
/// treat it as one layer of defense, not a guarantee, and combine it with model-level safeguards
/// (system-prompt hardening, output filtering, least-privilege tool access).
/// </summary>
public class PromptInjectionGuard
{
    private readonly List<(string Category, Regex Pattern, int Weight)> _patterns = new();

    /// <summary>Creates a guard pre-loaded with the built-in heuristic pattern set.</summary>
    public PromptInjectionGuard() => LoadBuiltInPatterns();

    /// <summary>Registers an additional custom detection pattern.</summary>
    public void AddPattern(string category, string regexPattern, int weight) =>
        _patterns.Add((category, new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(2)), weight));

    /// <summary>Removes all patterns registered for a given category. Returns the number removed.</summary>
    public int RemoveCategory(string category) => _patterns.RemoveAll(p => p.Category.Equals(category, StringComparison.OrdinalIgnoreCase));

    /// <summary>Removes all patterns (built-in and custom). Use <see cref="LoadBuiltInPatterns"/> to restore the defaults.</summary>
    public void ClearPatterns() => _patterns.Clear();

    /// <summary>(Re-)loads the built-in heuristic pattern set, without removing any custom patterns already added.</summary>
    public void LoadBuiltInPatterns()
    {
        // Instruction override: attempts to discard the system prompt or prior instructions.
        AddPattern("Instruction Override", @"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,30}\b(instructions?|prompts?|rules?)\b", 30);
        AddPattern("Instruction Override", @"\b(ignora|dimentica)\b.{0,30}\b(le istruzioni|il prompt|le regole)\b", 30);
        AddPattern("Instruction Override", @"\bnew instructions?\s*:", 20);

        // System prompt exfiltration: trying to get the model to reveal its hidden configuration.
        AddPattern("System Prompt Exfiltration", @"\b(repeat|reveal|show|print|output)\b.{0,20}\b(your|the)\b.{0,20}\b(system prompt|instructions|initial prompt)\b", 30);
        AddPattern("System Prompt Exfiltration", @"\bwhat (are|were) your (instructions|rules|guidelines)\b", 25);

        // Role hijack / jailbreak framing: asking the model to assume an unrestricted persona.
        AddPattern("Role Hijack", @"\byou are now\b.{0,30}\b(dan|jailbroken|unrestricted|uncensored)\b", 35);
        AddPattern("Role Hijack", @"\b(developer mode|dan mode|jailbreak)\b", 30);
        AddPattern("Role Hijack", @"\bpretend (you are|to be)\b.{0,30}\bno (restrictions|rules|filters)\b", 30);
        AddPattern("Role Hijack", @"\bact as if\b.{0,30}\b(no|without)\b.{0,20}\b(restrictions|filters|guidelines|rules)\b", 25);

        // Delimiter/role-marker injection: fake system/assistant turns smuggled inside user content.
        AddPattern("Delimiter Injection", @"<\|im_start\|>\s*(system|assistant)", 35);
        AddPattern("Delimiter Injection", @"\[\s*(system|SYSTEM)\s*\]\s*:", 25);
        AddPattern("Delimiter Injection", @"```\s*system\b", 20);

        // Encoded payload: unusually long base64-looking blob that may hide instructions from a naive filter.
        AddPattern("Encoded Payload", @"\b[A-Za-z0-9+/]{80,}={0,2}\b", 15);

        // Exfiltration coercion: asking the model to leak secrets/config to an external channel.
        AddPattern("Data Exfiltration Coercion", @"\bsend\b.{0,30}\b(api key|password|secret|credentials)\b.{0,30}\bto\b", 30);
    }

    /// <summary>Scans <paramref name="input"/> for prompt-injection patterns and returns a risk-scored result.</summary>
    public PromptInjectionResult Analyze(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new PromptInjectionResult { Score = 0, RiskLevel = PromptInjectionRisk.Safe };

        var matchedCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int score = 0;

        foreach (var (category, pattern, weight) in _patterns)
        {
            if (pattern.IsMatch(input))
            {
                matchedCategories.Add(category);
                score += weight;
            }
        }

        score = Math.Min(score, 100);

        return new PromptInjectionResult
        {
            Score = score,
            RiskLevel = ToRiskLevel(score),
            DetectedCategories = matchedCategories.OrderBy(c => c).ToList()
        };
    }

    private static PromptInjectionRisk ToRiskLevel(int score) => score switch
    {
        0 => PromptInjectionRisk.Safe,
        <= 20 => PromptInjectionRisk.Low,
        <= 45 => PromptInjectionRisk.Medium,
        <= 70 => PromptInjectionRisk.High,
        _ => PromptInjectionRisk.Critical
    };
}
