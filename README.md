# APK Secret Scanner

A lightweight PowerShell tool for scanning decompiled Android applications for potential hardcoded secrets and insecure endpoints.

APK Secret Scanner performs recursive pattern matching against common indicators of exposed credentials, API keys, private keys, database connection strings, Bearer tokens, Firebase URLs, and HTTP endpoints.

It generates a structured Markdown report to make manual security review easier.

## Features

- Recursive scanning of decompiled Android application files.
- Supports common JADX and Apktool output directories.
- Detects potential:
  - Firebase database URLs
  - AWS Access Key IDs
  - RSA, EC, and OpenSSH private key headers
  - MongoDB connection strings
  - JDBC connection strings
  - API key references
  - Secret key references
  - Bearer tokens
  - HTTP URLs
- Categorizes matches by detection pattern.
- Displays file paths and line numbers.
- Includes matched values and source-line context.
- Generates a structured Markdown report.
- Runs locally without uploading application files or scan results.

## Requirements

- Windows 10 or later.
- Windows PowerShell 5.1 or PowerShell 7+.
- Decompiled Android application output from JADX or Apktool.

No additional PowerShell modules are required.

## Installation

Clone the repository:

```powershell
git clone https://github.com/Cookies307/APK-Secret-Scanner.git
```

Navigate to the project directory:

```powershell
cd APK-Secret-Scanner
```

## Usage

### 1. Scan a decompiled APK directory

```powershell
.\Scan-APKSecrets.ps1 -InputPath "PATH_TO_DECOMPILED_OUTPUT"
```

### 2. Specify a custom report location

```powershell
.\Scan-APKSecrets.ps1 `
    -InputPath "PATH_TO_DECOMPILED_OUTPUT" `
    -OutputPath ".\reports\scan-report.md"
```

The output directory is created automatically if it does not exist.

### 3. Scan Apktool output

```powershell
.\Scan-APKSecrets.ps1 `
    -InputPath "C:\Pentest\Apktool_Output" `
    -OutputPath ".\reports\apktool-report.md"
```

### 4. Scan JADX output

```powershell
.\Scan-APKSecrets.ps1 `
    -InputPath "C:\Pentest\JADX_Output" `
    -OutputPath ".\reports\jadx-report.md"
```

### 5. Execution Policy

If PowerShell blocks script execution, use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Scan-APKSecrets.ps1 -InputPath "PATH_TO_DECOMPILED_OUTPUT"
```

## Detection Patterns

| Category | Detection Pattern |
|---|---|
| Firebase URLs | `firebaseio.com` |
| AWS Access Keys | `AKIA` followed by 16 uppercase alphanumeric characters |
| Private Keys | RSA, EC, and OpenSSH private key headers |
| MongoDB Connections | `mongodb://` |
| JDBC Connections | `jdbc:` |
| API Key References | `apikey`, `api.key` |
| Secret Key References | `secretkey`, `secret.key` |
| Bearer Tokens | `Bearer` followed by an alphanumeric value |
| HTTP URLs | `http://` |

## Output

The scanner generates a Markdown report containing:

- Scan summary.
- Number of scanned files.
- Total matches.
- Results grouped by category.
- File paths.
- Line numbers.
- Matched values.
- Source-line context.

Open the generated `.md` file in VS Code or any Markdown viewer.

## Example Report Structure

```text
APK Secret Scanner Report

Scan Summary
    Scan Date
    Scanned Directory
    Files Scanned
    Total Matches

Results by Category
    Firebase URLs
    AWS Access Key IDs
    Private Key Headers
    MongoDB Connections
    JDBC Connections
    API Key References
    Secret Key References
    Bearer Tokens
    HTTP URLs

Detailed Results
    File Path
    Line Number
    Matched Value
    Context
```

## How to Interpret Results

**Important: A match is an investigation lead, not a confirmed security vulnerability.**

Manually validate each result before reporting it.

| Detection | What to Verify |
|---|---|
| Firebase URL | Database exposure and access permissions |
| AWS Access Key ID | Whether a genuine credential is exposed and its permissions |
| Private Key Header | Whether a complete private key is present |
| MongoDB URI | Whether credentials or sensitive connection details are exposed |
| JDBC URI | Whether database connection information is exposed |
| API Key Reference | Whether an actual sensitive key is hardcoded |
| Secret Key Reference | Whether the value is a genuine secret |
| Bearer Token | Whether the token is genuine, valid, and sensitive |
| HTTP URL | Whether sensitive communication occurs without appropriate transport protection |

## Limitations

- Static pattern matching only.
- Does not validate credentials or tokens.
- Does not test remote endpoints.
- Does not determine whether detected values are active or exploitable.
- May produce false positives.
- Scans supported text-file extensions; binary assets are not analyzed.
- HTTP URLs are informational matches and are not automatically vulnerabilities.

Additional manual analysis and authorized security testing are required to verify potential findings.

## Security and Privacy

The scanner runs locally on the user's machine.

It does not upload APK files, source code, credentials, or generated reports to external services.

Generated reports may contain sensitive information. Review and sanitize reports before sharing them or publishing them.

## Responsible Use

Use this tool only on applications you own or have explicit authorization to assess.

This project is intended to support authorized Android application security testing and research.

## Contributing

Contributions are welcome!

You can contribute by:

- Suggesting additional detection patterns.
- Improving report formatting.
- Reducing false positives.
- Improving PowerShell compatibility.
- Reporting bugs or proposing enhancements through GitHub Issues.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
