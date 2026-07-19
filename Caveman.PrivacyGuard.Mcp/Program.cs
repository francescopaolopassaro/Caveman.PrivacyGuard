// ------------------------------------------------------------------------------
// Caveman.PrivacyGuard.Mcp — MCP server for Caveman.PrivacyGuard.
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
// https://github.com/francescopaolopassaro/Caveman.PrivacyGuard
// ------------------------------------------------------------------------------
using Caveman.PrivacyGuard;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;

var builder = Host.CreateApplicationBuilder(args);

builder.Services
    .AddSingleton(new PrivacyAnalyzer { EnableAutoMasking = true })
    .AddSingleton<PrivacySessionManager>()
    .AddSingleton<PromptInjectionGuard>()
    .AddSingleton<AiTransparencyNotice>()
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithToolsFromAssembly(typeof(Program).Assembly);

await builder.Build().RunAsync();
