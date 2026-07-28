# DotnetAudit Lite

A time-boxed, local-first preflight for .NET repositories. The tool generates a
Markdown report without uploading source code.

It checks:

- target frameworks and an embedded .NET 8/9/10 support snapshot;
- `Nullable` and warnings-as-errors settings;
- common CI, Docker, health-check, and OpenTelemetry signals;
- sensitive-looking files and assignments without printing detected values;
- optionally: `dotnet build`, `dotnet test`, and vulnerable transitive packages.

## Run

Requirements: .NET 8 SDK or newer.

```powershell
dotnet run --project DotnetAuditLite.csproj -- `
  --path C:\path\to\repository `
  --output dotnet-preflight-report.md `
  --sarif dotnet-preflight.sarif
```

For a fast scan that does not execute the target repository:

```powershell
dotnet run --project DotnetAuditLite.csproj -- --path C:\path\to\repository --static-only
```

The lifecycle snapshot is based on the
[official Microsoft .NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy)
as of 2026-07-27: .NET 8 and .NET 9 end support on 2026-11-10; .NET 10 ends
support on 2028-11-14. Future versions are deliberately marked for manual
verification instead of guessing.

## GitHub Action

The included composite action builds the tool and performs a static preflight.
It writes Markdown and SARIF 2.1.0 but uploads nothing by itself. A consuming
workflow can publish the Markdown as an artifact and, where GitHub code scanning
is available, optionally upload the SARIF file.

```yaml
- uses: actions/checkout@v4
- uses: ./path/to/DotnetAuditLite
  with:
    path: .
    output: dotnet-preflight-report.md
    sarif-output: dotnet-preflight.sarif
```

Optional upload step:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dotnet-preflight.sarif
```

GitHub code-scanning availability and repository permissions depend on the
repository type and plan. The local Markdown report remains usable without
uploading anything.

## Paid interpretation path

The automated report is designed to be a safe first signal. A fixed-scope human
review can turn it into one of four concrete next steps:

- one-problem diagnosis;
- Legacy .NET Modernization Assessment;
- AI Repo Enablement for .NET;
- reliability, observability or full code audit.

Current formats and contact:
https://dotnet-audit-studio-services.dtauskanov3.chatgpt.site/en

## Boundaries

This is a lead-magnet pre-check, not a replacement for engineering judgment. It
does not promise complete secret discovery, vulnerability coverage, production
reliability, or regulatory compliance. Always review findings before sharing
them outside the repository owner’s organization.
