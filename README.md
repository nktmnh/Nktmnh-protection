# nktmnhprotection

A WPF .NET 8 desktop app for local static malware triage, file hashing, PE inspection, IOC extraction, offline YARA-lite rule matching, and simulated file reputation checks.

## Safety

- Static analysis only. The app does not execute scanned samples.
- Reputation lookup is mocked by default and does not upload files.
- YARA-lite rules are loaded from a local folder.

## Features

- Drag and drop files, multiple files, or folders for recursive scanning.
- MD5, SHA-1, and SHA-256 hashing with 1 MB chunked reads.
- File type detection from magic bytes.
- Overall file entropy.
- Windows PE analysis:
  - Architecture, compile timestamp, subsystem, characteristics.
  - Section list and section entropy.
  - Imports, exports, imphash.
  - Digital signature presence.
  - Suspicious static indicators such as high entropy, writable executable sections, and suspicious imports.
- IOC extraction:
  - URLs, domains, IPv4 addresses, emails, registry keys, and suspicious strings.
- Offline YARA-lite matching:
  - Text strings.
  - Simple hex patterns such as `{ 4D 5A ?? }`.
  - Basic `any of them`, `all of them`, `$a or $b`, and `$a and $b` conditions.
- Configurable worker count.
- Result filter by text and status.
- Row details for hashes, PE summary, IOC summary, PE indicators, imphash, URLs, and matched rules.
- Copy SHA-256 and open containing folder.
- Export JSON and CSV reports.
- English / Vietnamese localization.
- Published EXE icon generated from `app.jpg`.

## Build

```powershell
cd nktmnhprotection
dotnet build
```

## Publish

```powershell
dotnet publish -c Release
```

The single-file EXE is generated under:

```text
nktmnhprotection\bin\Release\net8.0-windows\win-x64\publish\
```

## Rules

A starter rule file is included:

```text
Rules\SampleRules.yar
```

Open the app, click **Rules Folder**, and select the `Rules` folder to enable matching.

## Project Structure

```text
nktmnhprotection/
  Converters/
  Helpers/
  Localization/
  Models/
  Rules/
  Services/
  App.xaml
  MainWindow.xaml
  MainWindow.xaml.cs
  nktmnhprotection.csproj
```

## Notes

This app is intended for local defensive analysis and learning. Treat unknown files as unsafe and analyze them in a controlled environment.

## Author

Developed and maintained by **nktmnh**.
