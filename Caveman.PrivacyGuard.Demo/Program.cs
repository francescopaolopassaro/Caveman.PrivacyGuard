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
//💬 What can I do for you? (type your message, press ESC to exit): 
//using System.Text.RegularExpressions;

//using static System.Runtime.InteropServices.JavaScript.JSType;

//> My email is john.doe @company.com and my CF is RSSMRA85T10H501Z

// ⚠️ Low (Monitoring)  | Score: 18 / 100
//🔍 Detected(2 matches):
//   • Email
//   • Italian Tax Code (CF)

//📜 Compliance Flags:
//   ⚖️  GDPR / DSGVO / RGPD / RODO - Personal Identifiers

//🎭 Masked text (safe for AI):
//   My email is [EMAIL] and my CF is [ITALIAN TAX CODE(CF)]

//💬 ⚠️ Data detected: Email, Italian Tax Code (CF). Logging and monitoring recommended.

//❌ NOT safe for public AI models
using System;
using System.Text;
using Caveman.PrivacyGuard;

namespace Caveman.PrivacyGuard.Demo;

internal static class Program
{
    private static readonly PrivacyAnalyzer _analyzer = new() { EnableAutoMasking = true };
    private static PrivacySession? _session;
    private static bool _running = true;

    private static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        SetupConsole();
        ShowHeader();
        ShowMainMenu();

        while (_running)
        {
            Console.Write("\n💬 What can I do for you? (type your message, press ESC to exit): ");

            var input = ReadLineWithEscape();
            if (string.IsNullOrWhiteSpace(input)) continue;
            if (input.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase) ||
                input.Trim().Equals("quit", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            Console.WriteLine();

            if (input.Trim().Equals("/reset", StringComparison.OrdinalIgnoreCase))
            {
                ResetSession();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("🔄 Session reset. New placeholder session started.");
                Console.ResetColor();
                ShowDivider();
                continue;
            }

            if (input.Trim().Equals("/status", StringComparison.OrdinalIgnoreCase))
            {
                ShowSessionStatus();
                ShowDivider();
                continue;
            }

            if (input.Trim().Equals("/whitelist", StringComparison.OrdinalIgnoreCase))
            {
                ShowWhitelist();
                ShowDivider();
                continue;
            }

            if (input.Trim().Equals("/rules", StringComparison.OrdinalIgnoreCase))
            {
                ShowRules();
                ShowDivider();
                continue;
            }

            if (input.Trim().Equals("/export", StringComparison.OrdinalIgnoreCase))
            {
                ExportSession();
                ShowDivider();
                continue;
            }

            if (input.Trim().Equals("/validate", StringComparison.OrdinalIgnoreCase))
            {
                ShowValidation();
                ShowDivider();
                continue;
            }

            AnalyzeAndDisplay(input);
            ShowDivider();
        }

        ShowFooter();
    }

    private static void ResetSession()
    {
        _session = new PrivacySession();
    }

    private static void ShowSessionStatus()
    {
        if (_session == null)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("📭 No active session. Type a message to create one.");
            Console.ResetColor();
            return;
        }

        var entries = _session.GetAll();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"📊 Session Status: {entries.Count} placeholder(s) active");
        Console.ResetColor();

        if (entries.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            foreach (var entry in entries.OrderBy(e => e.Key))
                Console.WriteLine($"   {entry.Key} → {entry.Value.OriginalValue}  ({entry.Value.Category})");
            Console.ResetColor();
        }
    }

    private static void ShowWhitelist()
    {
        var list = _analyzer.GetWhitelist();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"📋 Whitelist: {list.Count} value(s)");
        Console.ResetColor();

        if (list.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            foreach (var v in list)
                Console.WriteLine($"   ⚪ {v}");
            Console.ResetColor();
        }
    }

    private static void ShowRules()
    {
        var categories = _analyzer.GetLoadedCategories();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"📜 Loaded Rules: {categories.Count} categories");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        foreach (var cat in categories.Take(20))
        {
            var rule = _analyzer.GetRule(cat);
            if (rule != null)
                Console.WriteLine($"   • {cat}  (weight: {rule.BaseWeight}, confidence: {(rule.IsHighConfidence ? "high" : "normal")})");
        }
        if (categories.Count > 20)
            Console.WriteLine($"   ... and {categories.Count - 20} more");
        Console.ResetColor();
    }

    private static void ExportSession()
    {
        if (_session == null || _session.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("📭 No active session to export.");
            Console.ResetColor();
            return;
        }

        var json = _session.ToJson();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"📦 Session exported ({_session.Count} entries):");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(json);
        Console.ResetColor();
    }

    private static void ShowValidation()
    {
        var valid = _analyzer.ValidateRules();
        Console.ForegroundColor = valid ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(valid ? "✅ All rules valid." : "❌ Some rules are invalid.");
        Console.ResetColor();
    }

    private static void SetupConsole()
    {
        Console.CursorVisible = false;
        Console.Title = "🛡️ Caveman.PrivacyGuard — EU Privacy Analyzer";
        if (Console.IsOutputRedirected == false)
        {
            try { Console.TreatControlCAsInput = true; } catch { }
        }
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; _running = false; };
    }

    private static void ShowHeader()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ╔══════════════════════════════════════════════════════════╗
  ║  🛡️  CAVEMAN.PRIVACYGUARD v1.2                          ║
  ║  Enterprise EU PII & Privacy Analyzer for AI/LLM         ║
  ║  GDPR • PCI-DSS • NIST • 27 Countries • Multi-Language   ║
  ╚══════════════════════════════════════════════════════════╝
");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Author: Passaro Francesco Paolo");
        Console.WriteLine("  License: MIT");
        Console.WriteLine("  Source: https://github.com/francescopaolopassaro/Caveman.PrivacyGuard");
        Console.ResetColor();
        ShowDivider();
    }

    private static void ShowMainMenu()
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n✨ Ready to analyze your text for privacy risks.");
        Console.WriteLine("🔹 Type any message to check for PII, credentials, or sensitive data.");
        Console.WriteLine("🔹 Type '/reset' to start a new placeholder session.");
        Console.WriteLine("🔹 Type '/status' to show current session state.");
        Console.WriteLine("🔹 Type '/whitelist' to show whitelisted values.");
        Console.WriteLine("🔹 Type '/rules' to show loaded rule categories.");
        Console.WriteLine("🔹 Type '/export' to export session as JSON.");
        Console.WriteLine("🔹 Type '/validate' to validate all loaded rules.");
        Console.WriteLine("🔹 Press ESC anytime to exit.");
        Console.WriteLine("🔹 Type 'exit' or 'quit' to close gracefully.");
        Console.ResetColor();
    }

    private static string? ReadLineWithEscape()
    {
        var sb = new StringBuilder();
        while (true)
        {
            if (!Console.KeyAvailable)
            {
                System.Threading.Thread.Sleep(10);
                continue;
            }

            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Escape)
            {
                Console.WriteLine("\n👋 Exiting...");
                _running = false;
                return null;
            }
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return sb.ToString();
            }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
                Console.Write(key.KeyChar);
            }
        }
    }

    private static void AnalyzeAndDisplay(string input, bool useSession = true)
    {
        PrivacyAnalysisResult result;

        if (useSession)
        {
            _session ??= new PrivacySession();
            result = _analyzer.Analyze(input, "en", _session);
        }
        else
        {
            result = _analyzer.Analyze(input, "en");
        }

        // 🎨 Risk Level Color Coding
        var (fg, bg, symbol) = GetRiskColors(result.Score);
        Console.ForegroundColor = fg;
        Console.BackgroundColor = bg;
        Console.Write($" {symbol} {result.RiskLevel} ");
        Console.ResetColor();
        Console.WriteLine($" | Score: {result.Score}/100");

        // 📊 Details
        if (result.DetectedCategories.Any())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"🔍 Detected ({result.MatchCount} matches):");
            Console.ResetColor();
            foreach (var cat in result.DetectedCategories)
            {
                Console.WriteLine($"   • {cat}");
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✅ No sensitive data detected.");
            Console.ResetColor();
        }

        // 🏷️ Compliance Flags
        if (result.ComplianceFlags.Any())
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n📜 Compliance Flags:");
            Console.ResetColor();
            foreach (var flag in result.ComplianceFlags)
            {
                Console.WriteLine($"   ⚖️  {flag}");
            }
        }

        // 🛡️ Masked Output (if enabled)
        if (!string.IsNullOrEmpty(result.MaskedText))
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n🎭 Masked text (safe for AI):");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"   {result.MaskedText}");
            Console.ResetColor();

            // 🔄 Show session placeholder mapping
            if (result.Session != null)
            {
                var allEntries = result.Session.GetAll();
                if (allEntries.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("\n📋 Session Placeholder Map:");
                    Console.ResetColor();
                    foreach (var entry in allEntries)
                    {
                        Console.WriteLine($"   {entry.Key} → {entry.Value.OriginalValue}  ({entry.Value.Category})");
                    }

                    // 🪄 Simulate AI response restore
                    var keys = string.Join(" and ", allEntries.Keys);
                    var simulatedAIResponse = $"I found the following information: {keys}";
                    var restored = result.Session.Restore(simulatedAIResponse);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n🪄 AI response restored: {restored}");
                    Console.ResetColor();
                }
            }
        }

        // 💬 Warning Message
        Console.ForegroundColor = result.Score <= 15 ? ConsoleColor.Green :
                                  result.Score <= 35 ? ConsoleColor.Yellow :
                                  result.Score <= 60 ? ConsoleColor.DarkYellow :
                                  result.Score <= 85 ? ConsoleColor.Red : ConsoleColor.DarkRed;
        Console.WriteLine($"\n💬 {result.WarningMessage}");
        Console.ResetColor();

        // ✅ AI Safety Badge
        Console.ForegroundColor = result.IsSafeForAI ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(result.IsSafeForAI ? "\n✅ Safe to send to AI/LLM" : "\n❌ NOT safe for public AI models");
        Console.ResetColor();
    }

    private static (ConsoleColor fg, ConsoleColor bg, string symbol) GetRiskColors(int score) => score switch
    {
        <= 15 => (ConsoleColor.Green, ConsoleColor.Black, "✅"),
        <= 35 => (ConsoleColor.Yellow, ConsoleColor.Black, "⚠️"),
        <= 60 => (ConsoleColor.DarkYellow, ConsoleColor.Black, "⛔"),
        <= 85 => (ConsoleColor.Red, ConsoleColor.Black, "🚨"),
        _ => (ConsoleColor.White, ConsoleColor.DarkRed, "🛑")
    };

    private static void ShowDivider()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(new string('─', 60));
        Console.ResetColor();
    }

    private static void ShowFooter()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ╔══════════════════════════════════════════════════════════╗
  ║  👋 Thank you for using Caveman.PrivacyGuard!            ║
  ║  Stay safe. Protect data. Enable AI responsibly. 🛡️🇪🇺   ║
  ╚══════════════════════════════════════════════════════════╝
");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Press any key to exit...");
        Console.ReadKey();
    }
}