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

namespace Caveman.PrivacyGuard;

/// <summary>
/// Produces a user-facing disclosure message informing the end user that they are interacting with an AI
/// system and that their input is screened/masked for sensitive data before being sent to the model.
/// This supports (but does not by itself guarantee) the transparency obligations of EU AI Act Art.50 for
/// limited-risk AI systems, which requires that natural persons be informed they are interacting with an AI
/// system. Whether it applies, and what exact wording is required, depends on your use case and should be
/// confirmed with legal counsel — this class only provides a configurable, ready-to-display message.
/// </summary>
public class AiTransparencyNotice
{
    private static readonly Dictionary<string, string> _defaultMessages = new(StringComparer.OrdinalIgnoreCase)
    {
        ["en"] = "You are interacting with an AI system. Your messages are screened locally and any personal or sensitive data is masked before being sent to the AI model (EU AI Act Art.50 transparency notice).",
        ["it"] = "Stai interagendo con un sistema di intelligenza artificiale. I tuoi messaggi vengono analizzati localmente e i dati personali o sensibili vengono mascherati prima dell'invio al modello AI (informativa ai sensi dell'Art.50 dell'AI Act).",
        ["de"] = "Sie interagieren mit einem KI-System. Ihre Nachrichten werden lokal geprüft und personenbezogene oder sensible Daten werden vor der Übermittlung an das KI-Modell maskiert (Transparenzhinweis gemäß Art. 50 KI-Verordnung).",
        ["fr"] = "Vous interagissez avec un système d'IA. Vos messages sont analysés localement et toute donnée personnelle ou sensible est masquée avant l'envoi au modèle d'IA (mention de transparence conformément à l'art. 50 du règlement IA).",
        ["es"] = "Está interactuando con un sistema de IA. Sus mensajes se analizan localmente y los datos personales o sensibles se enmascaran antes de enviarlos al modelo de IA (aviso de transparencia conforme al art. 50 del Reglamento de IA)."
    };

    /// <summary>Whether the notice should be shown. Defaults to true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Language code used to pick the built-in message (en, it, de, fr, es). Ignored if <see cref="CustomMessage"/> is set.</summary>
    public string Language { get; set; } = "en";

    /// <summary>Overrides the built-in message entirely, for organizations that need specific wording.</summary>
    public string? CustomMessage { get; set; }

    /// <summary>Returns the disclosure message to show the user, or an empty string if <see cref="Enabled"/> is false.</summary>
    public string GetMessage()
    {
        if (!Enabled) return string.Empty;
        if (!string.IsNullOrEmpty(CustomMessage)) return CustomMessage!;
        return _defaultMessages.TryGetValue(Language, out var msg) ? msg! : _defaultMessages["en"];
    }

    /// <summary>Registers or overrides the built-in message for a given language code.</summary>
    public static void RegisterMessage(string language, string message) => _defaultMessages[language] = message;
}
