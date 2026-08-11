[CmdletBinding()]
param(
    [string]$Owner = "gcw_SpGZ48lW",

    [string]$Repo = "mycodex-updates",

    [string]$RepoUrl,

    [string]$Token = $env:GITCODE_TOKEN,

    [string]$ReleaseNotesZhCn = "",

    [string]$ReleaseNotesEnUs = "",

    [string]$DockerHost,

    [string]$RemoteDockerCommand = "/usr/local/bin/docker",

    [switch]$PrepareOnly,

    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$version = (Get-Content -LiteralPath (Join-Path $repoRoot "VERSION") -Raw).Trim()
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$') {
    throw "VERSION must be a semantic version such as 1.0.0 or 1.0.0-rc.1."
}

if ([string]::IsNullOrWhiteSpace($RepoUrl)) {
    $RepoUrl = "https://gitcode.com/$Owner/$Repo.git"
}

$releaseTag = "relay-v$version"
$dist = Join-Path $repoRoot "dist"
$nativeChecksumPath = Join-Path $dist "SHA256SUMS.txt"
$dockerChecksumPath = Join-Path $dist "DOCKER-SHA256SUMS.txt"
$nativeArchiveNames = @(
    "mycodex-relay-$version-windows-x64.zip",
    "mycodex-relay-$version-linux-x64.tar.gz",
    "mycodex-relay-$version-linux-arm64.tar.gz",
    "mycodex-relay-$version-macos-intel.tar.gz",
    "mycodex-relay-$version-macos-apple-silicon.tar.gz"
)
$dockerArchiveNames = @(
    "mycodex-relay-$version-docker-linux-amd64.tar.gz",
    "mycodex-relay-$version-docker-linux-arm64.tar.gz"
)
$apiBase = "https://api.gitcode.com/api/v5/repos/$Owner/$Repo"
$script:CachedGitCodeToken = $null

function Get-GitCodeToken {
    if (-not [string]::IsNullOrWhiteSpace($script:CachedGitCodeToken)) {
        return $script:CachedGitCodeToken
    }
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $script:CachedGitCodeToken = $Token.Trim()
        return $script:CachedGitCodeToken
    }

    foreach ($scope in @("User", "Machine")) {
        $stored = [Environment]::GetEnvironmentVariable("GITCODE_TOKEN", $scope)
        if (-not [string]::IsNullOrWhiteSpace($stored)) {
            $script:CachedGitCodeToken = $stored.Trim()
            return $script:CachedGitCodeToken
        }
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "git"
    $psi.Arguments = "credential-manager get"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.EnvironmentVariables["GCM_INTERACTIVE"] = "Never"
    $psi.EnvironmentVariables["GIT_TERMINAL_PROMPT"] = "0"
    $process = [System.Diagnostics.Process]::Start($psi)
    $process.StandardInput.Write("protocol=https`nhost=gitcode.com`nusername=$Owner`n`n")
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(15000)) {
        try { $process.Kill() } catch {}
        throw "Timed out while reading the GitCode token. Set `$env:GITCODE_TOKEN and retry."
    }
    $output = $process.StandardOutput.ReadToEnd()
    $errorOutput = $process.StandardError.ReadToEnd()
    if ($process.ExitCode -ne 0) {
        throw "Unable to read the GitCode token from Git Credential Manager: $errorOutput"
    }
    $passwordLine = $output -split "`n" |
        Where-Object { $_ -like "password=*" } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($passwordLine)) {
        throw "GitCode token is missing. Set `$env:GITCODE_TOKEN or store it in Git Credential Manager."
    }
    $script:CachedGitCodeToken = $passwordLine.Substring(9).Trim()
    return $script:CachedGitCodeToken
}

function Test-PublicTag {
    $result = (& git ls-remote --tags $RepoUrl "refs/tags/$releaseTag" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query the GitCode release tag $releaseTag."
    }
    return -not [string]::IsNullOrWhiteSpace($result)
}

function New-GitCodeRelease {
    $body = ($ReleaseNotesZhCn + "`n`n" + $ReleaseNotesEnUs).Trim()
    $request = @{
        access_token = Get-GitCodeToken
        tag_name = $releaseTag
        name = "MyCodex Relay $version"
        body = $body
        target_commitish = "main"
    }
    [void](Invoke-RestMethod -Method Post -Uri "$apiBase/releases" -Body $request -TimeoutSec 120)
}

function Send-GitCodeReleaseFile {
    param([string]$Path)

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $fileName = Split-Path $resolvedPath -Leaf
    $tokenValue = [Uri]::EscapeDataString((Get-GitCodeToken))
    $encodedFileName = [Uri]::EscapeDataString($fileName)
    $upload = Invoke-RestMethod `
        -Method Get `
        -Uri "$apiBase/releases/$releaseTag/upload_url?access_token=$tokenValue&file_name=$encodedFileName" `
        -TimeoutSec 120
    $headers = @{}
    foreach ($property in $upload.headers.PSObject.Properties) {
        $headers[$property.Name] = [string]$property.Value
    }
    [void](Invoke-WebRequest `
        -Method Put `
        -Uri $upload.url `
        -Headers $headers `
        -InFile $resolvedPath `
        -ContentType "application/octet-stream" `
        -TimeoutSec 900 `
        -UseBasicParsing)
    Write-Host "Uploaded Relay asset: $releaseTag / $fileName"
}

function Confirm-PublicAsset {
    param([object]$Candidate)

    $url = "$apiBase/releases/$releaseTag/attach_files/$([Uri]::EscapeDataString($Candidate.Name))/download"
    $temporary = [IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $url -OutFile $temporary -TimeoutSec 900 -UseBasicParsing
        $actualSize = (Get-Item -LiteralPath $temporary).Length
        $actualSha256 = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSize -ne $Candidate.Size -or $actualSha256 -ne $Candidate.Sha256) {
            throw "Published asset differs from the local candidate: $($Candidate.Name). Bump VERSION instead of replacing this tag."
        }
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-ChecksummedCandidates {
    param(
        [string]$ChecksumPath,
        [string[]]$ArchiveNames
    )

    if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
        throw "Checksum file was not found: $ChecksumPath"
    }

    $expectedHashes = @{}
    foreach ($line in Get-Content -LiteralPath $ChecksumPath -Encoding UTF8) {
        if ($line -notmatch '^([0-9a-fA-F]{64})\s+(.+)$') {
            throw "Invalid SHA256SUMS.txt line: $line"
        }
        $expectedHashes[$matches[2].Trim()] = $matches[1].ToLowerInvariant()
    }
    if ($expectedHashes.Count -ne $ArchiveNames.Count) {
        throw "$([IO.Path]::GetFileName($ChecksumPath)) must describe exactly $($ArchiveNames.Count) archives."
    }

    $candidates = @()
    foreach ($name in $ArchiveNames) {
        $path = Join-Path $dist $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Relay release archive was not found: $path"
        }
        if (-not $expectedHashes.ContainsKey($name)) {
            throw "$([IO.Path]::GetFileName($ChecksumPath)) does not contain $name."
        }
        $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sha256 -ne $expectedHashes[$name]) {
            throw "Local checksum mismatch for $name."
        }
        $candidates += [PSCustomObject]@{
            Name = $name
            Path = $path
            Size = (Get-Item -LiteralPath $path).Length
            Sha256 = $sha256
        }
    }
    $candidates += [PSCustomObject]@{
        Name = [IO.Path]::GetFileName($ChecksumPath)
        Path = $ChecksumPath
        Size = (Get-Item -LiteralPath $ChecksumPath).Length
        Sha256 = (Get-FileHash -LiteralPath $ChecksumPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $candidates
}

function Get-ReleaseCandidates {
    $candidates = @()
    $candidates += @(Get-ChecksummedCandidates -ChecksumPath $nativeChecksumPath -ArchiveNames $nativeArchiveNames)
    $candidates += @(Get-ChecksummedCandidates -ChecksumPath $dockerChecksumPath -ArchiveNames $dockerArchiveNames)
    return $candidates
}

$sourceRemotes = @(& git -C $repoRoot remote)
if ($sourceRemotes -contains "gitcode") {
    throw "Refusing to run while the Relay source repository has a gitcode remote."
}

if (-not $SkipBuild) {
    & (Join-Path $repoRoot "scripts\build.ps1") -Version $version
    if ($LASTEXITCODE -ne 0) {
        throw "Relay release build failed."
    }
    $dockerBuildArguments = @{ Version = $version }
    if (-not [string]::IsNullOrWhiteSpace($DockerHost)) {
        $dockerBuildArguments.DockerHost = $DockerHost
        $dockerBuildArguments.RemoteDockerCommand = $RemoteDockerCommand
    }
    & (Join-Path $repoRoot "scripts\docker\Build-DockerRelease.ps1") @dockerBuildArguments
}
$candidates = @(Get-ReleaseCandidates)

if ($PrepareOnly) {
    Write-Host "Prepared MyCodex Relay binary release without publishing:"
    Write-Host "  Version: $version"
    Write-Host "  Tag:     $releaseTag"
    foreach ($candidate in $candidates) {
        Write-Host "  Asset:   $($candidate.Name)"
    }
    return
}

$worktreeStatus = (& git -C $repoRoot status --porcelain | Out-String).Trim()
if (-not [string]::IsNullOrWhiteSpace($worktreeStatus)) {
    throw "Live publication requires a clean Relay source working tree."
}
[void](Get-GitCodeToken)

if (Test-PublicTag) {
    foreach ($candidate in $candidates) {
        Confirm-PublicAsset -Candidate $candidate
    }
    Write-Host "GitCode already contains the identical immutable Relay release: $releaseTag"
    return
}

New-GitCodeRelease
foreach ($candidate in $candidates) {
    Send-GitCodeReleaseFile -Path $candidate.Path
}
foreach ($candidate in $candidates) {
    Confirm-PublicAsset -Candidate $candidate
}

Write-Host "Published MyCodex Relay binary release:"
Write-Host "  Version: $version"
Write-Host "  Tag:     $releaseTag"
Write-Host "  URL:     https://gitcode.com/$Owner/$Repo/releases/$releaseTag"
