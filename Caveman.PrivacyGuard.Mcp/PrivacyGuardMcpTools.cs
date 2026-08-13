// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard.Mcp — MCP tools for Caveman.PrivacyGuard.
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
// ------------------------------------------------------------------------------
using System.ComponentModel;
using System.Linq;
using System.Text;
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

    [McpServerTool(Name = "mask_stream")]
    [Description("Masks PII in a stream of text chunks (e.g. a chunked file read or a live LLM output) as they arrive. Uses a boundary-safe overlap window (default 512 chars) so a sensitive value that happens to be split across two chunks is still caught and masked whole. Returns the concatenated masked text and the total match count. With a session_id, placeholders are [PG_N] scoped to that conversation and restorable via restore_text.")]
    public string MaskStream(
        [Description("Text chunks of the stream, in arrival order")] string[] chunks,
        [Description("Language code for the warning message (default: en)")] string language = "en",
        [Description("Conversation/session id to scope placeholders to, for later restore_text calls (optional)")] string? sessionId = null,
        [Description("Overlap window in characters held back across chunk boundaries (default: 512)")] int overlapChars = 512)
    {
        var session = sessionId is null ? null : sessions.GetOrCreate(sessionId);
        int totalMatches = 0;
        var masker = new PrivacyStreamMasker(analyzer, session, language, overlapChars);
        masker.OnChunkAnalyzed = r => totalMatches += r.MatchCount;

        var sb = new StringBuilder();
        foreach (var chunk in chunks)
            sb.Append(masker.Feed(chunk));
        sb.Append(masker.Flush());

        return JsonSerializer.Serialize(new
        {
            masked_text = sb.ToString(),
            match_count = totalMatches,
            session_id = sessionId
        });
    }

    [McpServerTool(Name = "mask_document")]
    [Description("Masks PII in a plain-text, Markdown or CSV file and writes a masked copy (default: name.masked.ext next to the source; the original file is never overwritten). The file is processed in chunks, never loaded whole into memory. Returns the masked copy's path, detected format, and total match count.")]
    public string MaskDocument(
        [Description("Path of the file to mask")] string path,
        [Description("Path for the masked copy; defaults to name.masked.ext next to the source")] string? outputPath = null,
        [Description("Language code for the warning message (default: en)")] string language = "en",
        [Description("Conversation/session id to scope placeholders to, for later restore_text calls (optional)")] string? sessionId = null)
    {
        var session = sessionId is null ? null : sessions.GetOrCreate(sessionId);
        var result = DocumentMasker.MaskFile(path, outputPath, language, analyzer, session);
        return JsonSerializer.Serialize(new
        {
            input_path = result.InputPath,
            output_path = result.OutputPath,
            format = result.Format,
            masked_match_count = result.MaskedMatchCount,
            session_id = sessionId
        });
    }

    [McpServerTool(Name = "session_summary")]
    [Description("Returns a redacted view of a session's placeholders (placeholder token + category only, never the original sensitive value). Safe to log, display, or return in an API/CLI response — unlike restore_text/GetAll/ToJson, which carry the real PII.")]
    public string SessionSummary(
        [Description("The session id used in the corresponding mask_text / mask_stream / mask_document call")] string sessionId)
    {
        if (!sessions.TryGet(sessionId, out var session) || session is null)
            return JsonSerializer.Serialize(new { error = $"Unknown session_id '{sessionId}'. Call mask_text/mask_stream/mask_document with this session_id first." });

        return JsonSerializer.Serialize(new
        {
            session_id = sessionId,
            entry_count = session.Summary().Count,
            entries = session.Summary().Select(i => new { placeholder = i.Placeholder, category = i.Category })
        });
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
