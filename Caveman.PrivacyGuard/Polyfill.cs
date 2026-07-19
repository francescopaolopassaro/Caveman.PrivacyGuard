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

using System.Text.RegularExpressions;

#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
    internal sealed class RequiredMemberAttribute : Attribute { }
    internal sealed class CompilerFeatureRequiredAttribute : Attribute
    {
        public CompilerFeatureRequiredAttribute(string _) { }
    }
}

namespace System.Diagnostics.CodeAnalysis
{
    internal sealed class SetsRequiredMembersAttribute : Attribute { }
    internal sealed class MaybeNullWhenAttribute : Attribute
    {
        public MaybeNullWhenAttribute(bool _) { }
    }
}

namespace Caveman.PrivacyGuard
{
    internal static class RegexHelper
    {
        internal const RegexOptions CompiledAndSafe = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;
        internal static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(3);
    }

    internal static class Polyfill
    {
        internal static int Clamp(int value, int min, int max) =>
            value < min ? min : value > max ? max : value;

        internal static double Clamp(double value, double min, double max) =>
            value < min ? min : value > max ? max : value;

        internal static bool IsRegexParseException(Exception ex) =>
            ex is ArgumentException;
    }
}
#else
namespace Caveman.PrivacyGuard
{
    internal static class RegexHelper
    {
        internal const RegexOptions CompiledAndSafe = RegexOptions.Compiled | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;
        internal static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(3);
    }

    internal static class Polyfill
    {
        internal static int Clamp(int value, int min, int max) =>
            Math.Clamp(value, min, max);

        internal static double Clamp(double value, double min, double max) =>
            Math.Clamp(value, min, max);

        internal static bool IsRegexParseException(Exception ex) =>
            ex is RegexParseException;
    }
}
#endif
