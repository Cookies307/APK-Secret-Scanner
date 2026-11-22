# APK Secret Scanner

A lightweight PowerShell tool for scanning decompiled Android applications (JADX / Apktool output) for potential hardcoded secrets and sensitive information.

## Features

- Detects potential API keys, passwords, tokens, private keys, and database connection strings.
- Identifies Firebase URLs, AWS keys, GitHub tokens, and insecure HTTP endpoints.
- Flags sensitive files such as `.env`, keystores, and `google-services.json`.
- Filters common placeholders and low-entropy values.
- Supports Markdown, JSON, and CSV reports.
- Severity-based filtering and optional redaction.
- Runs locally without uploading scan data.

## Requirements

- Windows with PowerShell.
- Decompiled APK output from JADX or Apktool.
- No additional PowerShell modules required.

## Usage

Clone the repository:

```powershell
git clone https://github.com/Cookies307/APK-Secret-Scanner.git
cd APK-Secret-Scanner
```

Run a scan:

```powershell
.\APK-Secret-Scanner.ps1 -InputPath ".\app-jadx" -ApkPath ".\app.apk"
```

Generate multiple report formats:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\APK-Secret-Scanner.ps1" -InputPath ".\app-jadx" -ApkPath ".\app.apk" -Format Markdown
```

## Options

| Parameter | Description |
|---|---|
| `-InputPath` | Decompiled APK directory (required). |
| `-ApkPath` | Original APK path (required; used for report naming). |
| `-OutputPath` | Custom report output path. |
| `-Format` | Markdown, Json, or Csv. |
| `-MinSeverity` | Filter findings by severity. |
| `-Redact` | Partially masks matched values in reports. |
| `-SkipLibraries` | Skips common third-party libraries. |
| `-ExcludeDir` | Excludes specific directories or files. |
| `-MaxFileSizeMB` | Maximum file size to scan (default: 5 MB). |

## Important Notes

- A match is an investigation lead, not a confirmed vulnerability.
- Results require manual validation.
- The scanner does not validate credentials or test remote endpoints.
- Redaction only masks matched values; context and filenames may still contain sensitive information. Review reports before sharing.
- Use only on applications you own or are authorized to assess.

## License

MIT License
