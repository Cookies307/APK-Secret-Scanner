
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

# Validate and resolve the input directory
if (-not (Test-Path -LiteralPath $InputPath -PathType Container)) {
    Write-Error "Input directory does not exist: $InputPath"
    exit 1
}

$root = (Resolve-Path -LiteralPath $InputPath).Path
$rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

# Default report name and location
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path (Get-Location).Path "APK-Secret-Scan-$timestamp.md"
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Search patterns
$patterns = [ordered]@{
    "Firebase URLs"       = 'firebaseio\.com'
    "AWS Access Key IDs"  = 'AKIA[0-9A-Z]{16}'
    "Private Key Headers" = 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY'
    "MongoDB Connections" = 'mongodb://'
    "JDBC Connections"    = 'jdbc:'
    "API Key References"  = 'apikey|api\.key'
    "Secret Key References" = 'secretkey|secret\.key'
    "Bearer Tokens"       = 'Bearer [A-Za-z0-9]+'
    "HTTP URLs"           = 'http://'
}

# Text file extensions commonly found in decompiled APKs
$extensions = @(
    ".java", ".kt", ".smali", ".xml", ".json",
    ".properties", ".txt", ".html", ".htm",
    ".js", ".ts", ".gradle", ".kts",
    ".yml", ".yaml", ".cfg", ".conf", ".ini",
    ".sh", ".md", ".plist", ".strings",
    ".toml", ".php", ".sql", ".py"
)

Write-Host "[*] Collecting files..." -ForegroundColor Cyan

$files = @(
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        ($extensions -contains $_.Extension.ToLowerInvariant()) -and
        ($_.FullName -ne $outputFullPath)
    }
)

$results = [System.Collections.Generic.List[object]]::new()

Write-Host "[*] Scanning $($files.Count) files..." -ForegroundColor Cyan

foreach ($entry in $patterns.GetEnumerator()) {

    Write-Host "[*] Checking: $($entry.Key)" -ForegroundColor Yellow

    foreach ($file in $files) {

        $matches = Select-String `
            -LiteralPath $file.FullName `
            -Pattern $entry.Value `
            -AllMatches `
            -ErrorAction SilentlyContinue

        foreach ($match in $matches) {

            $relativePath = $file.FullName.Substring($rootPrefix.Length)
            $relativePath = $relativePath -replace '\\', '/'

            $matchedValues = @(
                $match.Matches |
                ForEach-Object { $_.Value } |
                Select-Object -Unique
            ) -join ", "

            $context = ($match.Line -replace '\s+', ' ').Trim()

            if ($context.Length -gt 200) {
                $context = $context.Substring(0, 200) + "..."
            }

            # Escape Markdown table characters
            $relativePath = $relativePath -replace '\|', '\|'
            $matchedValues = $matchedValues -replace '\|', '\|'
            $context = $context -replace '\|', '\|'
            $context = $context -replace '`', "'"

            $results.Add([PSCustomObject]@{
                Category = $entry.Key
                File     = $relativePath
                Line     = $match.LineNumber
                Match    = $matchedValues
                Context  = $context
            })
        }
    }
}

# Build Markdown report
$report = [System.Collections.Generic.List[string]]::new()

$report.Add("# APK Secret Scanner Report")
$report.Add("")
$report.Add("> Automated scan of decompiled Android application files.")
$report.Add("")
$report.Add("## Scan Summary")
$report.Add("")
$report.Add("| Property | Value |")
$report.Add("|---|---|")
$report.Add("| Scan Date | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |")
$report.Add("| Scanned Directory | $([IO.Path]::GetFileName($root)) |")
$report.Add("| Files Scanned | $($files.Count) |")
$report.Add("| Total Matches | $($results.Count) |")
$report.Add("")

$report.Add("## Results by Category")
$report.Add("")
$report.Add("| Category | Matches |")
$report.Add("|---|---:|")

foreach ($entry in $patterns.GetEnumerator()) {
    $count = @($results | Where-Object Category -eq $entry.Key).Count
    $report.Add("| $($entry.Key) | $count |")
}

$report.Add("")
$report.Add("---")
$report.Add("")
$report.Add("## Detailed Results")

foreach ($entry in $patterns.GetEnumerator()) {

    $categoryResults = @(
        $results | Where-Object Category -eq $entry.Key
    )

    $report.Add("")
    $report.Add("### $($entry.Key) ($($categoryResults.Count))")
    $report.Add("")

    if ($categoryResults.Count -eq 0) {
        $report.Add("No matches found.")
        continue
    }

    $report.Add("| File | Line | Matched Value | Context |")
    $report.Add("|---|---:|---|---|")

    foreach ($item in $categoryResults) {
        $report.Add("| $($item.File) | $($item.Line) | $($item.Match) | $($item.Context) |")
    }
}

$report.Add("")
$report.Add("---")
$report.Add("")
$report.Add("## Important Notes")
$report.Add("")
$report.Add("- Each match is an investigation lead, not a confirmed vulnerability.")
$report.Add("- Validate whether exposed values are genuine, active, and sensitive.")
$report.Add("- Review the security impact and access permissions before reporting a finding.")
$report.Add("- HTTP URLs are informational leads and do not automatically indicate insecure communication.")
$report.Add("- This tool performs static pattern matching only. It does not validate credentials or test remote services.")
$report.Add("")
$report.Add("Generated by APK Secret Scanner.")

# Save report
Set-Content -LiteralPath $outputFullPath -Value $report -Encoding UTF8

Write-Host ""
Write-Host "[+] Scan completed!" -ForegroundColor Green
Write-Host "[+] Files scanned: $($files.Count)"
Write-Host "[+] Total matches: $($results.Count)"
Write-Host "[+] Report saved to: $outputFullPath" -ForegroundColor Green
