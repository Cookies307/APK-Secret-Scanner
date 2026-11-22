<#
.SYNOPSIS
    Static secret scanner for decompiled Android APKs (jadx / apktool output).

.DESCRIPTION
    Scans a decompiled APK directory in a single pass per file using compiled regexes,
    assigns a severity to every rule, filters common false positives (placeholders,
    low-entropy values, XML/schema URLs), flags sensitive files by name
    (keystores, google-services.json, .env, ...) and writes Markdown / JSON / CSV reports.

    Every match is a LEAD, not a confirmed vulnerability. Validate before reporting.

.PARAMETER InputPath      Decompiled APK directory.
.PARAMETER ApkPath        Original APK file (used for naming the report only).
.PARAMETER OutputPath     Report base path (extension optional). Default: beside the APK.
.PARAMETER Format         Markdown, Json, Csv (one or more).
.PARAMETER MinSeverity    Hide rules below this severity. Info | Low | Medium | High | Critical.
.PARAMETER MaxFileSizeMB  Skip files larger than this (default 5).
.PARAMETER MaxRowsPerCategory  Row cap per category in the Markdown report (JSON/CSV keep everything).
.PARAMETER Redact         Partially masks the VALUE each rule matched (keeps first 4 and last 2 chars,
                          or '****' for short values) in the Markdown, JSON and CSV reports.
                          Only the matched value is masked: other text on the same line (Context) and
                          file names are NOT, so review a redacted report before sharing it publicly.
.PARAMETER SkipLibraries  Skip common third-party library code (androidx, kotlin, okhttp, gms, ...).
.PARAMETER ExcludeDir     Directory (or file) paths, relative to InputPath, to skip. Matched on whole path
                          segments, case-insensitive, either slash style: -ExcludeDir 'res/drawable','assets\fonts'.
                          'res' skips every folder named res, not names that merely contain "res".

.EXAMPLE
    .\APK-Secret-Scanner.ps1 -InputPath .\app-jadx -ApkPath .\app.apk

.EXAMPLE
    .\APK-Secret-Scanner.ps1 .\app-jadx .\app.apk -Format Markdown,Json -MinSeverity Medium -SkipLibraries -Redact
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputPath,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ApkPath,

    [string]$OutputPath,

    [ValidateSet('Markdown', 'Json', 'Csv')]
    [string[]]$Format = @('Markdown'),

    [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
    [string]$MinSeverity = 'Info',

    [ValidateRange(1, 500)]
    [int]$MaxFileSizeMB = 5,

    [ValidateRange(10, 100000)]
    [int]$MaxRowsPerCategory = 300,

    [switch]$Redact,
    [switch]$SkipLibraries,
    [string[]]$ExcludeDir = @()
)

$ErrorActionPreference = 'Stop'
$script:SevRank = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }

# ----------------------------------------------------------------------------
# Validation and path resolution
# ----------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ApkPath -PathType Leaf)) {
    throw "APK file does not exist: $ApkPath"
}
if (-not (Test-Path -LiteralPath $InputPath -PathType Container)) {
    throw "Input directory does not exist: $InputPath"
}

$apkFullPath = (Resolve-Path -LiteralPath $ApkPath).Path
$root        = (Resolve-Path -LiteralPath $InputPath).Path
$rootPrefix  = $root.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
$apkName     = [IO.Path]::GetFileNameWithoutExtension($apkFullPath)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $basePath = Join-Path (Split-Path -Parent $apkFullPath) "$apkName-Secret-Scan"
}
else {
    $basePath = [IO.Path]::GetFullPath($OutputPath)
    if ([IO.Path]::GetExtension($basePath) -in @('.md', '.json', '.csv')) {
        $basePath = $basePath.Substring(0, $basePath.Length - [IO.Path]::GetExtension($basePath).Length)
    }
}

$outputDirectory = Split-Path -Parent $basePath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$outputFiles = @{}
if ($Format -contains 'Markdown') { $outputFiles['Markdown'] = "$basePath.md" }
if ($Format -contains 'Json')     { $outputFiles['Json']     = "$basePath.json" }
if ($Format -contains 'Csv')      { $outputFiles['Csv']      = "$basePath.csv" }
$outputSet = @($outputFiles.Values)

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function ConvertTo-MarkdownCell {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $Value = $Value -replace '\r?\n', ' '
    $Value = $Value.Replace('|', '\|').Replace('`', "'")
    return $Value.Trim()
}

function Get-ShannonEntropy {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
    $freq = [System.Collections.Generic.Dictionary[char, int]]::new()
    foreach ($c in $Text.ToCharArray()) {
        if ($freq.ContainsKey($c)) { $freq[$c]++ } else { $freq[$c] = 1 }
    }
    $entropy = 0.0
    foreach ($n in $freq.Values) {
        $p = $n / $Text.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return $entropy
}

function Protect-Value {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value.Length -le 8) { return '****' }
    return $Value.Substring(0, 4) + '****' + $Value.Substring($Value.Length - 2)
}

# Neutralise spreadsheet formula injection (=, +, -, @, tab, CR) in CSV cells
function Protect-CsvCell {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value -match '^[=+\-@\t\r]') { return "'" + $Value }
    return $Value
}

# Recursive enumeration that never follows symlinks / junctions
$script:SkippedLinks = 0
function Get-SafeFiles {
    param([string]$Root)
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($item.LinkType) { $script:SkippedLinks++; continue }
            if ($item.PSIsContainer) { $stack.Push($item.FullName) }
            else { $item }
        }
    }
}

function Test-IsBinaryFile {
    param([string]$Path)
    $fs = $null
    try {
        $fs  = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] 4096
        $n   = $fs.Read($buf, 0, $buf.Length)
        for ($i = 0; $i -lt $n; $i++) {
            if ($buf[$i] -eq 0) { return $true }
        }
        return $false
    }
    catch { return $true }
    finally { if ($fs) { $fs.Dispose() } }
}

function New-Rule {
    param(
        [string]$Name,
        [string]$Severity,
        [string]$Pattern,
        [bool]$CaseSensitive = $false,
        [bool]$Generic = $false,
        [double]$MinEntropy = 0
    )
    $opts = [Text.RegularExpressions.RegexOptions]::Compiled
    if (-not $CaseSensitive) { $opts = $opts -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase }
    [PSCustomObject]@{
        Name       = $Name
        Severity   = $Severity
        Rank       = $script:SevRank[$Severity]
        Regex      = [regex]::new($Pattern, $opts, [TimeSpan]::FromSeconds(10))
        Generic    = $Generic
        MinEntropy = $MinEntropy
    }
}

# ----------------------------------------------------------------------------
# Rules  (Name, Severity, Pattern, CaseSensitive, Generic, MinEntropy)
# Generic = apply placeholder + entropy filtering. Group (?<v>...) = the secret value.
# ----------------------------------------------------------------------------
$allRules = @(
    # --- Provider-specific tokens (low false-positive rate) ---
    (New-Rule 'Private Key Headers'      'Critical' '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----' $true)
    (New-Rule 'Stripe Live Secret Keys'  'Critical' '\b[sr]k_live_[0-9a-zA-Z]{24,}\b' $true)
    (New-Rule 'AWS Access Key IDs'       'Medium'   '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b' $true)
    (New-Rule 'AWS Secret Access Keys'   'Critical' '(?i)aws[^\r\n]{0,30}(?:secret|sk)[^\r\n]{0,20}?["''](?<v>[A-Za-z0-9/+=]{40})[\\]?["'']' $false $true 4.0)
    (New-Rule 'Google API Keys'          'High'     'AIza[0-9A-Za-z_\-]{35}' $true)
    (New-Rule 'GitHub Tokens'            'High'     '\bgh[pousr]_[A-Za-z0-9]{36,255}\b' $true)
    (New-Rule 'GitHub Fine-grained Tokens' 'High'   '\bgithub_pat_[0-9A-Za-z_]{22,255}\b' $true)
    (New-Rule 'Slack Tokens'             'High'     '\bxox[baprs]-[0-9A-Za-z\-]{10,72}' $true)
    (New-Rule 'Slack Webhooks'           'High'     'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+' $true)
    (New-Rule 'SendGrid API Keys'        'High'     '\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b' $true)
    (New-Rule 'Telegram Bot Tokens'      'High'     '\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b' $true)

    # --- Tokens and connection strings ---
    (New-Rule 'JWT Tokens'               'Medium'   '\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' $true)
    (New-Rule 'Bearer Tokens'            'Medium'   '\bbearer[ \t]+(?<v>[A-Za-z0-9\-._~+/]{20,}=*)' $false $true 3.0)
    (New-Rule 'MongoDB Credentials'      'High'     'mongodb(?:\+srv)?://[^/\s:@"''<>]+:[^/\s@"''<>]{3,}@[^\s"''<>]+')
    (New-Rule 'Credentials in URLs'      'Medium'   '\b(?!mongodb)[a-z][a-z0-9+.\-]{1,15}://[^/\s:@"''<>]{1,64}:[^/\s@"''<>]{3,64}@[^\s"''<>]+')
    (New-Rule 'Firebase URLs'            'Low'      '(?:https?://)?[a-z0-9][a-z0-9.\-]{0,100}\.(?:firebaseio\.com|firebasedatabase\.app)\b[^\s"''<>]*')
    (New-Rule 'MongoDB Connections'      'Low'      'mongodb(?:\+srv)?://(?![^/\s@"''<>]*:[^/\s@"''<>]{3,}@)[^\s"''<>]+')
    (New-Rule 'JDBC Connections'         'Low'      'jdbc:[a-z0-9]+:[^\s"''<>]*')

    # --- Hardcoded assignments (filtered for placeholders / entropy) ---
    (New-Rule 'Hardcoded Passwords'      'Medium'   '\b(?:password|passwd|pwd|passphrase)\b[\\"'']{0,2}[ \t]*[=:][ \t]*[\\]?["''](?<v>[^"''\\\r\n]{4,})[\\]?["'']' $false $true 0)
    (New-Rule 'Hardcoded API Keys/Secrets' 'Medium' '(?:api[_.\-]?key|apikey|secret[_.\-]?key|secretkey|client[_.\-]?secret|access[_.\-]?token|auth[_.\-]?token)\b[\\"'']{0,2}[ \t]*[=:][ \t]*[\\]?["''](?<v>[^"''\\\r\n]{8,})[\\]?["'']' $false $true 2.5)
    (New-Rule 'Android String Resource Secrets' 'Medium' '<string[ \t]+name="(?:[^"]*[_.\-])?(?:api_?key|key|secret|token|password|passwd)(?:[_.\-][^"]*)?"[^>]*>(?<v>[^<\s]{8,})</string>' $false $true 2.5)

    # --- Keyword references (noisy, informational) ---
    (New-Rule 'API Key References'       'Info'     'apikey|api\.key')
    (New-Rule 'Secret Key References'    'Info'     'secretkey|secret\.key')
    (New-Rule 'HTTP URLs'                'Info'     '\bhttp://(?!(?:schemas\.android\.com|schemas\.microsoft\.com|schemas\.openxmlformats\.org|schemas\.xmlsoap\.org|www\.w3\.org|xmlpull\.org|www\.apache\.org|apache\.org|xml\.apache\.org|ns\.adobe\.com|java\.sun\.com|xml\.org|javax\.xml|purl\.org|www\.opengis\.net|relaxng\.org|sax\.sourceforge\.net|www\.android\.com|developer\.android\.com|localhost|127\.0\.0\.1|10\.0\.2\.2|example\.com|www\.example\.com)\b)[^\s"''<>)]+')
)

$minRank = $script:SevRank[$MinSeverity]
$rules   = @($allRules | Where-Object { $_.Rank -ge $minRank })

$placeholderRx = [regex]::new(
    '(?i)^(?:x+|\*+|0+|changeme|change_me|your[\w\- ]*|<[^>]*>|example\w*|dummy\w*|placeholder\w*|null|none|todo|%\d*\$?s|\$\{[^}]*\}|\{\{.*\}\}|@string/.*)$',
    [Text.RegularExpressions.RegexOptions]::Compiled)

# ----------------------------------------------------------------------------
# File filters
# ----------------------------------------------------------------------------
$binaryExt = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.so', '.dex', '.odex', '.oat', '.art',
        '.arsc', '.class', '.jar', '.aar', '.zip', '.apk', '.ttf', '.otf', '.woff', '.woff2', '.mp3', '.mp4',
        '.ogg', '.wav', '.webm', '.3gp', '.pdf', '.bin', '.exe', '.dll'),
    [StringComparer]::OrdinalIgnoreCase)

$libraryRx = '(?i)(^|/)(?:smali[^/]*|sources|java)/(?:androidx|android/support|kotlin|kotlinx|okhttp3|okio|retrofit2|dagger|javax|io/reactivex|org/jetbrains|com/squareup|com/bumptech|com/google/android/(?:gms|material)|com/google/firebase)/'

$sensitiveNameRx = '(?i)(^|/)(?:google-services\.json|GoogleService-Info\.plist|\.env(?:\..+)?|keystore\.properties|local\.properties|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:jks|keystore|p12|pfx|pem|key|p8|kdbx)|[^/]*credentials[^/]*\.json|[^/]*secrets?[^/]*\.(?:json|xml|properties|ya?ml))$'

$maxBytes = [long]$MaxFileSizeMB * 1MB

# ExcludeDir: normalise slashes, match whole path segments only ("/res/drawable/")
$excludeNorm = @($ExcludeDir | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { '/' + (($_ -replace '\\', '/').Trim('/')) + '/' })

# ----------------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------------
Write-Host "[*] APK            : $([IO.Path]::GetFileName($apkFullPath))" -ForegroundColor Cyan
Write-Host "[*] Rules enabled  : $($rules.Count) (min severity: $MinSeverity)" -ForegroundColor Cyan
Write-Host '[*] Collecting files...' -ForegroundColor Cyan

$allFiles = @(Get-SafeFiles -Root $root |
        Where-Object { $outputSet -notcontains $_.FullName })

Write-Host "[*] Found $($allFiles.Count) files. Scanning..." -ForegroundColor Cyan

$results        = [System.Collections.Generic.List[object]]::new()
$sensitiveFiles = [System.Collections.Generic.List[object]]::new()
$seen           = [System.Collections.Generic.HashSet[string]]::new()
$stats          = @{ Scanned = 0; Binary = 0; TooLarge = 0; Library = 0; Excluded = 0; Unreadable = 0; Timeouts = 0; Links = $script:SkippedLinks }
$stopwatch      = [Diagnostics.Stopwatch]::StartNew()
$counter        = 0

foreach ($file in $allFiles) {
    $counter++
    if ($counter % 250 -eq 0) {
        Write-Progress -Activity 'Scanning decompiled APK' -Status "$counter / $($allFiles.Count) files - $($results.Count) matches" -PercentComplete ([int](100 * $counter / $allFiles.Count))
    }

    $rel = ($file.FullName.Substring($rootPrefix.Length)) -replace '\\', '/'

    if ($rel -match '(^|/)\.git/') { $stats.Excluded++; continue }
    $skip = $false
    $relPadded = "/$rel/"
    foreach ($ex in $excludeNorm) {
        if ($relPadded.IndexOf($ex, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break }
    }
    if ($skip) { $stats.Excluded++; continue }

    # Sensitive file names are reported even if the file is binary (but not if excluded)
    if ($rel -match $sensitiveNameRx) {
        $sensitiveFiles.Add([PSCustomObject]@{ File = $rel; SizeKB = [math]::Round($file.Length / 1KB, 1) })
    }

    if ($SkipLibraries -and $rel -match $libraryRx) { $stats.Library++; continue }
    if ($binaryExt.Contains($file.Extension)) { $stats.Binary++; continue }
    if ($file.Length -gt $maxBytes) { $stats.TooLarge++; continue }
    if ($file.Length -eq 0) { continue }
    if (Test-IsBinaryFile -Path $file.FullName) { $stats.Binary++; continue }

    try { $text = [IO.File]::ReadAllText($file.FullName) }
    catch { $stats.Unreadable++; continue }

    $stats.Scanned++
    $lineStarts = $null

    foreach ($rule in $rules) {
        # MatchCollection is lazy in .NET Core: force evaluation inside the try so timeouts are caught here
        try { $hits = @($rule.Regex.Matches($text)) }
        catch [Text.RegularExpressions.RegexMatchTimeoutException] { $stats.Timeouts++; continue }

        if ($hits.Count -eq 0) { continue }

        # Build line index lazily, only for files that have matches
        if ($null -eq $lineStarts) {
            $lineStarts = [System.Collections.Generic.List[int]]::new()
            $lineStarts.Add(0)
            $nl = $text.IndexOf("`n")
            while ($nl -ge 0) {
                $lineStarts.Add($nl + 1)
                $nl = $text.IndexOf("`n", $nl + 1)
            }
        }

        foreach ($m in $hits) {
            $val = if ($m.Groups['v'].Success) { $m.Groups['v'].Value } else { $m.Value }

            if ($rule.Generic) {
                if ($placeholderRx.IsMatch($val)) { continue }
                if ($rule.MinEntropy -gt 0 -and (Get-ShannonEntropy $val) -lt $rule.MinEntropy) { continue }
            }

            $idx = $lineStarts.BinarySearch($m.Index)
            if ($idx -lt 0) { $idx = (-bnot $idx) - 1 }
            $lineNo = $idx + 1

            $key = "$($rule.Name)|$rel|$lineNo|$val"
            if (-not $seen.Add($key)) { continue }

            # Extract the line and a window around the match
            $start = $lineStarts[$idx]
            $end   = $text.IndexOf("`n", $start)
            if ($end -lt 0) { $end = $text.Length }
            $line = $text.Substring($start, $end - $start).TrimEnd("`r")

            if ($line.Length -gt 200) {
                $col  = $m.Index - $start
                $from = [Math]::Max(0, $col - 80)
                $len  = [Math]::Min($line.Length - $from, 200)
                $ctx  = $line.Substring($from, $len)
                if ($from -gt 0) { $ctx = '...' + $ctx }
                if ($from + $len -lt $line.Length) { $ctx += '...' }
            }
            else { $ctx = $line }
            $ctx = ($ctx -replace '\s+', ' ').Trim()

            $shown = $val
            if ($Redact) {
                $shown = Protect-Value $val
                if ($val.Length -gt 0) { $ctx = $ctx.Replace($val, $shown) }
            }

            $results.Add([PSCustomObject]@{
                    Severity = $rule.Severity
                    Rank     = $rule.Rank
                    Category = $rule.Name
                    File     = $rel
                    Line     = $lineNo
                    Match    = $shown
                    Context  = $ctx
                })
        }
    }
}

Write-Progress -Activity 'Scanning decompiled APK' -Completed
$stopwatch.Stop()

$sorted = @($results | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Category, File, Line)
$sensitiveFiles = @($sensitiveFiles | Sort-Object File -Unique)

# ----------------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------------
$scanDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

if ($outputFiles.ContainsKey('Markdown')) {
    $report = [System.Collections.Generic.List[string]]::new()
    $report.Add('# APK Secret Scanner Report')
    $report.Add('')
    $report.Add('> Automated static scan of decompiled Android application files.')
    $report.Add('')
    if (-not $Redact) {
        $report.Add('> **WARNING: this report may contain secrets in plaintext (not redacted).**')
        $report.Add('> Do not commit, upload, or share it. Re-run with `-Redact` to produce a shareable version.')
        $report.Add('')
    }
    $report.Add('## Scan Summary')
    $report.Add('')
    $report.Add('| Property | Value |')
    $report.Add('|---|---|')
    $report.Add("| APK File | $(ConvertTo-MarkdownCell ([IO.Path]::GetFileName($apkFullPath))) |")
    $report.Add("| Scan Date | $scanDate |")
    $report.Add("| Scanned Directory | $(ConvertTo-MarkdownCell ([IO.Path]::GetFileName($root))) |")
    $report.Add("| Files Scanned | $($stats.Scanned) |")
    $report.Add("| Skipped (binary / too large / library / excluded) | $($stats.Binary) / $($stats.TooLarge) / $($stats.Library) / $($stats.Excluded) |")
    $report.Add("| Minimum Severity | $MinSeverity |")
    $report.Add("| Values Redacted | $([bool]$Redact) |")
    $report.Add("| Symlinks / Junctions Skipped | $($stats.Links) |")
    $report.Add("| Duration | $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s |")
    $report.Add("| Total Matches | $($sorted.Count) |")
    $report.Add('')

    $report.Add('## Matches by Severity')
    $report.Add('')
    $report.Add('| Severity | Matches |')
    $report.Add('|---|---:|')
    foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $c = @($sorted | Where-Object { $_.Severity -eq $sev }).Count
        $report.Add("| $sev | $c |")
    }
    $report.Add('')

    $report.Add('## Results by Category')
    $report.Add('')
    $report.Add('| Category | Severity | Matches |')
    $report.Add('|---|---|---:|')
    foreach ($rule in ($rules | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Name)) {
        $c = @($sorted | Where-Object { $_.Category -eq $rule.Name }).Count
        $report.Add("| $($rule.Name) | $($rule.Severity) | $c |")
    }
    $report.Add('')

    $topFiles = @($sorted | Where-Object { $_.Rank -ge 2 } | Group-Object File | Sort-Object Count -Descending | Select-Object -First 10)
    if ($topFiles.Count -gt 0) {
        $report.Add('## Top Files (Medium and above)')
        $report.Add('')
        $report.Add('| File | Matches |')
        $report.Add('|---|---:|')
        foreach ($g in $topFiles) { $report.Add("| $(ConvertTo-MarkdownCell $g.Name) | $($g.Count) |") }
        $report.Add('')
    }

    $report.Add('## Sensitive Files by Name')
    $report.Add('')
    if ($sensitiveFiles.Count -eq 0) {
        $report.Add('No sensitive file names found.')
    }
    else {
        $report.Add('| File | Size (KB) |')
        $report.Add('|---|---:|')
        foreach ($sf in $sensitiveFiles) { $report.Add("| $(ConvertTo-MarkdownCell $sf.File) | $($sf.SizeKB) |") }
    }
    $report.Add('')
    $report.Add('---')
    $report.Add('')
    $report.Add('## Detailed Results')

    foreach ($rule in ($rules | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Name)) {
        $catResults = @($sorted | Where-Object { $_.Category -eq $rule.Name })
        if ($catResults.Count -eq 0) { continue }

        $report.Add('')
        $report.Add("### $($rule.Name) ($($catResults.Count)) - $($rule.Severity)")
        $report.Add('')
        $report.Add('| File | Line | Matched Value | Context |')
        $report.Add('|---|---:|---|---|')

        foreach ($item in ($catResults | Select-Object -First $MaxRowsPerCategory)) {
            $report.Add("| $(ConvertTo-MarkdownCell $item.File) | $($item.Line) | ``$(ConvertTo-MarkdownCell $item.Match)`` | ``$(ConvertTo-MarkdownCell $item.Context)`` |")
        }
        if ($catResults.Count -gt $MaxRowsPerCategory) {
            $report.Add('')
            $report.Add("_Showing first $MaxRowsPerCategory of $($catResults.Count). Use -Format Json or Csv for the full list._")
        }
    }

    $report.Add('')
    $report.Add('---')
    $report.Add('')
    $report.Add('## Important Notes')
    $report.Add('')
    $report.Add('- Each match is an investigation lead, not a confirmed vulnerability.')
    $report.Add('- Validate whether exposed values are genuine, active, and sensitive.')
    $report.Add('- Review the security impact and access permissions before reporting a finding.')
    $report.Add('- Generic rules filter placeholders and low-entropy values, which can hide real but weak secrets.')
    $report.Add('- HTTP URLs and keyword references are informational and do not automatically indicate a vulnerability.')
    $report.Add('- Binary files (.dex, .so, .arsc, images) are not scanned. Use strings/jadx output for those.')
    $report.Add('- This tool performs static pattern matching only. It does not validate credentials or test remote services.')
    $report.Add('')
    $report.Add('Generated by APK Secret Scanner.')

    [IO.File]::WriteAllLines($outputFiles['Markdown'], $report, [Text.UTF8Encoding]::new($false))
}

if ($outputFiles.ContainsKey('Json')) {
    $json = [ordered]@{
        apk            = [IO.Path]::GetFileName($apkFullPath)
        scanDate       = $scanDate
        redacted       = [bool]$Redact
        filesScanned   = $stats.Scanned
        totalMatches   = $sorted.Count
        sensitiveFiles = $sensitiveFiles
        findings       = @($sorted | Select-Object Severity, Category, File, Line, Match, Context)
    }
    [IO.File]::WriteAllText($outputFiles['Json'], ($json | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}

if ($outputFiles.ContainsKey('Csv')) {
    $sorted | Select-Object Severity,
        @{ Name = 'Category'; Expression = { Protect-CsvCell $_.Category } },
        @{ Name = 'File';     Expression = { Protect-CsvCell $_.File } },
        Line,
        @{ Name = 'Match';    Expression = { Protect-CsvCell $_.Match } },
        @{ Name = 'Context';  Expression = { Protect-CsvCell $_.Context } } |
        Export-Csv -LiteralPath $outputFiles['Csv'] -NoTypeInformation -Encoding UTF8
}

# ----------------------------------------------------------------------------
# Console summary
# ----------------------------------------------------------------------------
Write-Host ''
Write-Host '[+] Scan completed!' -ForegroundColor Green
Write-Host "[+] APK            : $([IO.Path]::GetFileName($apkFullPath))"
Write-Host "[+] Files scanned  : $($stats.Scanned)  (binary: $($stats.Binary), too large: $($stats.TooLarge), library: $($stats.Library), unreadable: $($stats.Unreadable))"
Write-Host "[+] Total matches  : $($sorted.Count)"

$sevColors = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Gray'; Info = 'DarkGray' }
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $c = @($sorted | Where-Object { $_.Severity -eq $sev }).Count
    if ($c -gt 0) { Write-Host ("    {0,-9}: {1}" -f $sev, $c) -ForegroundColor $sevColors[$sev] }
}
if ($sensitiveFiles.Count -gt 0) { Write-Host "[!] Sensitive files: $($sensitiveFiles.Count)" -ForegroundColor Yellow }
if ($stats.Links -gt 0) { Write-Host "[!] Skipped $($stats.Links) symlink/junction entries (not followed for safety)" -ForegroundColor Yellow }
if (-not $Redact -and $sorted.Count -gt 0) { Write-Host '[!] Reports contain secrets in plaintext. Do NOT commit or share them (use -Redact for a shareable version).' -ForegroundColor Yellow }
if ($stats.Timeouts -gt 0) { Write-Host "[!] Regex timeouts : $($stats.Timeouts) (some files may be partially scanned)" -ForegroundColor Yellow }
Write-Host "[+] Duration       : $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s"
foreach ($k in $outputFiles.Keys) { Write-Host "[+] $k report: $($outputFiles[$k])" -ForegroundColor Green }
