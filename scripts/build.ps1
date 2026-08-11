param(
    [string]$Version
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = (Get-Content -LiteralPath (Join-Path $root "VERSION") -Raw).Trim()
}
if ($Version -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Version may contain only letters, numbers, dots, underscores, and hyphens."
}

$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Get-ChildItem -LiteralPath $dist -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "mycodex-relay-*.zip" -or $_.Name -like "mycodex-relay-*.tar.gz" -or $_.Name -eq "SHA256SUMS.txt" } |
    Remove-Item -Force

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Dir = "windows-x64"; Binary = "mycodex-relay.exe"; Scripts = "windows-x64"; Docs = "windows"; Format = "zip" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Dir = "linux-x64"; Binary = "mycodex-relay"; Scripts = "linux"; Docs = "linux"; Format = "tar.gz" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Dir = "linux-arm64"; Binary = "mycodex-relay"; Scripts = "linux"; Docs = "linux"; Format = "tar.gz" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Dir = "macos-intel"; Binary = "mycodex-relay"; Scripts = "darwin-x64"; Docs = "macos"; Format = "tar.gz" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Dir = "macos-apple-silicon"; Binary = "mycodex-relay"; Scripts = "darwin-arm64"; Docs = "macos"; Format = "tar.gz" }
)

foreach ($legacyDirName in @("darwin-x64", "darwin-arm64")) {
    $legacyDir = Join-Path $dist $legacyDirName
    if (Test-Path -LiteralPath $legacyDir) {
        Remove-Item -LiteralPath $legacyDir -Recurse -Force
    }
}

$archives = @()
foreach ($target in $targets) {
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH
    $targetDir = Join-Path $dist $target.Dir
    $resolvedTarget = [System.IO.Path]::GetFullPath($targetDir)
    $resolvedDist = [System.IO.Path]::GetFullPath($dist).TrimEnd('\') + '\'
    if (-not $resolvedTarget.StartsWith($resolvedDist, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe package target: $resolvedTarget"
    }
    if (Test-Path -LiteralPath $targetDir) {
        Remove-Item -LiteralPath $targetDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    $output = Join-Path $targetDir $target.Binary
    go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$Version" -o $output ./cmd/mycodex-relay
    Write-Host "Built $output"

    Copy-Item -LiteralPath (Join-Path $root "resources\release\common\README.md") -Destination $targetDir
    Copy-Item -LiteralPath (Join-Path $root "resources\release\$($target.Docs)\DEPLOYMENT.md") -Destination $targetDir
    Set-Content -LiteralPath (Join-Path $targetDir "VERSION.txt") -Value $Version -Encoding ASCII

    if ($target.Scripts -ne "") {
        $scriptDir = Join-Path $PSScriptRoot (Join-Path "package" $target.Scripts)
        if (Test-Path $scriptDir) {
            Copy-Item -Path (Join-Path $scriptDir "*") -Destination $targetDir -Force
        }
    }

    $requiredFiles = @($target.Binary, "README.md", "DEPLOYMENT.md", "VERSION.txt")
    foreach ($script in Get-ChildItem -LiteralPath $scriptDir -File) {
        $requiredFiles += $script.Name
    }
    foreach ($relativePath in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $targetDir $relativePath) -PathType Leaf)) {
            throw "Package $($target.Dir) is missing $relativePath"
        }
    }

    $archiveBase = "mycodex-relay-$Version-$($target.Dir)"
    if ($target.Format -eq "zip") {
        $archivePath = Join-Path $dist "$archiveBase.zip"
        Compress-Archive -LiteralPath $targetDir -DestinationPath $archivePath -CompressionLevel Optimal
    }
    else {
        $archivePath = Join-Path $dist "$archiveBase.tar.gz"
        & tar -C $dist -czf $archivePath $target.Dir
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create $archivePath"
        }
    }
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or (Get-Item -LiteralPath $archivePath).Length -eq 0) {
        throw "Package archive was not created: $archivePath"
    }
    $archiveEntries = @(& tar -tf $archivePath)
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to verify $archivePath"
    }
    foreach ($relativePath in $requiredFiles) {
        $expectedEntry = "$($target.Dir)/$($relativePath.Replace('\', '/'))"
        if ($archiveEntries -notcontains $expectedEntry) {
            throw "Archive $archivePath is missing $expectedEntry"
        }
    }
    $archives += $archivePath
    Write-Host "Packaged $archivePath"
}

$checksumPath = Join-Path $dist "SHA256SUMS.txt"
$checksumLines = foreach ($archivePath in $archives) {
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $([System.IO.Path]::GetFileName($archivePath))"
}
[System.IO.File]::WriteAllLines(
    $checksumPath,
    $checksumLines,
    [System.Text.UTF8Encoding]::new($false))
if ($checksumLines.Count -ne $targets.Count) {
    throw "Expected $($targets.Count) checksums, found $($checksumLines.Count)"
}
Write-Host "Wrote $checksumPath"
