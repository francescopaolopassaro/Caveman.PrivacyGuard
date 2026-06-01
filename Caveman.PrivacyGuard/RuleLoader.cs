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
using System.IO;
using System.Reflection;
using System.Threading;
using YamlDotNet.Serialization;
using Caveman.PrivacyGuard.Models;

namespace Caveman.PrivacyGuard;

internal static class RuleLoader
{
    private static readonly Lazy<RulesDocument> _lazyRules = new(LoadEmbedded, LazyThreadSafetyMode.ExecutionAndPublication);

    public static RulesDocument Rules => _lazyRules.Value;

    private static RulesDocument LoadEmbedded()
    {
        var assembly = typeof(PrivacyAnalyzer).Assembly;
        var resourceName = $"{assembly.GetName().Name}.rules.yaml";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
            throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        return Deserialize(stream);
    }

    public static RulesDocument LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Rules YAML file not found.", filePath);
        using var stream = File.OpenRead(filePath);
        return Deserialize(stream);
    }

    public static RulesDocument LoadFromString(string yamlContent)
    {
        var deserializer = new DeserializerBuilder().Build();
        return deserializer.Deserialize<RulesDocument>(yamlContent);
    }

    private static RulesDocument Deserialize(Stream stream)
    {
        var deserializer = new DeserializerBuilder().Build();
        return deserializer.Deserialize<RulesDocument>(new StreamReader(stream));
    }
}
