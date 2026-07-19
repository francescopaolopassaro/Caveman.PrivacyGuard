// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard.Mcp — MCP tools for Caveman.PrivacyGuard.
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
// ------------------------------------------------------------------------------
using System.ComponentModel;
using System.Text.Json;
using Caveman.PrivacyGuard;
using ModelContextProtocol.Server;

namespace Caveman.PrivacyGuard.Mcp;

[McpServerToolType]
internal sealed class PrivacyGuardMcpTools(
    PrivacyAnalyzer analyzer,
    PrivacySessionManager sessions,
    PromptInjectionGuard injectionGuard,
    AiTransparencyNotice transparencyNotice)
{
    [McpServerTool(Name = "analyze_text")]
    [Description("Detects and scores PII/sensitive data in a text across 32 countries (27 EU + UK, Switzerland, China, Russia, Ukraine). Returns risk score (0-100), risk level, detected categories, and GDPR/AI Act/NIS2/PCI-DSS/NIST compliance flags. Does not mask the text — use mask_text for that.")]
    public string AnalyzeText(
        [Description("Text to analyze")] string text,
        [Description("Language code for the warning message, e.g. en, it, de, fr, es (default: en)")] string language = "en")
    {
        var r = analyzer.Analyze(text, language);
        return JsonSerializer.Serialize(new
        {
            score = r.Score,
            risk_level = r.RiskLevel,
            is_safe_for_ai = r.IsSafeForAI,
            detected_categories = r.DetectedCategories,
            compliance_flags = r.ComplianceFlags,
            match_count = r.MatchCount,
            warning_message = r.WarningMessage
        });
    }

    [McpServerTool(Name = "mask_text")]
    [Description("Masks PII/sensitive data in a text before it is sent to an LLM. Without a session_id, uses fixed textual placeholders like [EMAIL]/[IBAN]. With a session_id, uses unique [PG_N] placeholders scoped to that conversation, so the original values can later be restored client-side via restore_text — the real data never has to reach the model twice.")]
    public string MaskText(
        [Description("Text to mask")] string text,
        [Description("Language code for the warning message (default: en)")] string language = "en",
        [Description("Conversation/session id to scope placeholders to, for later restore_text calls (optional)")] string? sessionId = null)
    {
        var session = sessionId is null ? null : sessions.GetOrCreate(sessionId);
        var r = analyzer.Analyze(text, language, session);
        return JsonSerializer.Serialize(new
        {
            masked_text = r.MaskedText,
            score = r.Score,
            risk_level = r.RiskLevel,
            detected_categories = r.DetectedCategories
        });
    }

    [McpServerTool(Name = "restore_text")]
    [Description("Restores the original sensitive values in text containing [PG_N] placeholders previously produced by mask_text for the given session_id. Call this on the model's response before showing it to the end user.")]
    public string RestoreText(
        [Description("Text containing [PG_N] placeholders to restore")] string text,
        [Description("The session id used in the corresponding mask_text call")] string sessionId)
    {
        if (!sessions.TryGet(sessionId, out var session) || session is null)
            return JsonSerializer.Serialize(new { error = $"Unknown session_id '{sessionId}'. Call mask_text with this session_id first.", restored_text = text, restored_count = 0 });

        var detailed = session.RestoreDetailed(text);
        return JsonSerializer.Serialize(new { restored_text = detailed.Text, restored_count = detailed.RestoredCount });
    }

    [McpServerTool(Name = "check_prompt_injection")]
    [Description("Heuristically scans untrusted text (user messages, tool output, retrieved documents) for prompt-injection attempts — instruction overrides, system-prompt exfiltration, role-hijack/jailbreak framing, fake delimiter/role markers, and credential-exfiltration coercion — before it reaches an LLM's context. Returns a risk score and the matched categories. This is one layer of defense, not a guarantee: combine with system-prompt hardening and least-privilege tool access.")]
    public string CheckPromptInjection(
        [Description("Untrusted text to scan")] string text)
    {
        var r = injectionGuard.Analyze(text);
        return JsonSerializer.Serialize(new
        {
            score = r.Score,
            risk_level = r.RiskLevel.ToString(),
            is_clean = r.IsClean,
            detected_categories = r.DetectedCategories
        });
    }

    [McpServerTool(Name = "get_ai_transparency_notice")]
    [Description("Returns a ready-to-display disclosure message informing the end user they are interacting with an AI system and that sensitive data is screened/masked — a technical aid toward EU AI Act Art.50 transparency expectations for limited-risk AI systems.")]
    public string GetAiTransparencyNotice(
        [Description("Language code: en, it, de, fr, es (default: en)")] string language = "en")
    {
        transparencyNotice.Language = language;
        return JsonSerializer.Serialize(new { message = transparencyNotice.GetMessage() });
    }
}
