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
using NUnit.Framework;
using Caveman.PrivacyGuard;
using System.Net;
using System.Net.Http;

namespace Caveman.PrivacyGuard.Tests;

/// <summary>Routes every request to a canned response, so remote-YAML tests never touch the network.</summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _content;

    public StubHttpMessageHandler(string content, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _content = content;
        _statusCode = statusCode;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(new HttpResponseMessage(_statusCode) { Content = new StringContent(_content) });
}

[TestFixture]
public class RemoteYamlConfigTests
{
    private const string SampleYaml = @"
version: ""2.0""
countries:
  - code: ""XX""
    rules:
      - category: ""RemoteTestCategory""
        pattern: '\bREMOTE_MARKER_\d+\b'
        base_weight: 20
";

    [Test]
    public async Task LoadCustomYamlFromUrlAsync_LoadsRulesFromRemoteContent()
    {
        var analyzer = new PrivacyAnalyzer();
        var client = new HttpClient(new StubHttpMessageHandler(SampleYaml));

        await analyzer.LoadCustomYamlFromUrlAsync("https://rules.example.invalid/rules.yaml", client);

        var result = analyzer.Analyze("marker: REMOTE_MARKER_42");
        Assert.That(result.DetectedCategories, Does.Contain("RemoteTestCategory"));
    }

    [Test]
    public void LoadCustomYamlFromUrlAsync_ThrowsOnHttpError()
    {
        var analyzer = new PrivacyAnalyzer();
        var client = new HttpClient(new StubHttpMessageHandler("not found", HttpStatusCode.NotFound));

        Assert.ThrowsAsync<HttpRequestException>(async () =>
            await analyzer.LoadCustomYamlFromUrlAsync("https://rules.example.invalid/missing.yaml", client));
    }
}

[TestFixture]
public class AnalyzeStreamTests
{
    [Test]
    public async Task AnalyzeStreamAsync_YieldsOneResultPerInput_InOrder()
    {
        var analyzer = new PrivacyAnalyzer();
        var inputs = new[] { "email a@example.com", "no pii here", "email b@example.com" };

        var results = new List<PrivacyAnalysisResult>();
        await foreach (var r in analyzer.AnalyzeStreamAsync(inputs))
            results.Add(r);

        Assert.That(results.Count, Is.EqualTo(3));
        Assert.That(results[0].DetectedCategories, Does.Contain("Email"));
        Assert.That(results[1].DetectedCategories, Does.Not.Contain("Email"));
        Assert.That(results[2].DetectedCategories, Does.Contain("Email"));
    }

    [Test]
    public async Task AnalyzeStreamAsync_MatchesAnalyzeBatch_ForSameInputs()
    {
        var analyzer = new PrivacyAnalyzer();
        var inputs = new[] { "CF: RSSMRA85T10H501Z", "IBAN: IT60X0542811101000000123456" };

        var batch = analyzer.AnalyzeBatch(inputs);

        var streamed = new List<PrivacyAnalysisResult>();
        await foreach (var r in analyzer.AnalyzeStreamAsync(inputs))
            streamed.Add(r);

        Assert.That(streamed.Select(r => r.Score), Is.EqualTo(batch.Select(r => r.Score)));
    }

    [Test]
    public void AnalyzeStreamAsync_RespectsCancellation()
    {
        var analyzer = new PrivacyAnalyzer();
        var inputs = Enumerable.Range(0, 1000).Select(i => $"text {i}");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () =>
        {
            await foreach (var _ in analyzer.AnalyzeStreamAsync(inputs, cts.Token)) { }
        });
    }
}
