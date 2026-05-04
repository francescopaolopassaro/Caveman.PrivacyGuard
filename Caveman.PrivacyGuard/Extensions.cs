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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Caveman.PrivacyGuard
{
    internal static class Extensions
    {
        /// <summary>
        /// Verifica se l'insieme contiene almeno uno degli elementi specificati (case-insensitive).
        /// </summary>
        public static bool ContainsAny(this HashSet<string> source, IEnumerable<string> values)
        {
            if (source == null || values == null) return false;
            return values.Any(v => source.Contains(v, StringComparer.OrdinalIgnoreCase));
        }
    }
}
