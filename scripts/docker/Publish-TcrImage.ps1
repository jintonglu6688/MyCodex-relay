[CmdletBinding()]
param(
    [string]$Version,

    [string]$Revision,

    [string]$DockerHost,

    [string]$RemoteDockerCommand = "/usr/local/bin/docker"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = (Get-Content -LiteralPath (Join-Path $repoRoot "VERSION") -Raw).Trim()
}
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$') {
    throw "Version must be a semantic version such as 1.0.0 or 1.0.0-rc.1."
}

if ([string]::IsNullOrWhiteSpace($Revision)) {
    $Revision = (& git -C $repoRoot rev-parse --short=12 HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Revision)) {
        $Revision = "unknown"
    }
}
if ($Revision -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Revision may contain only letters, numbers, dots, underscores, and hyphens."
}
if (-not [string]::IsNullOrWhiteSpace($DockerHost) -and $DockerHost -notmatch '^[A-Za-z0-9._@:-]+$') {
    throw "DockerHost contains unsupported characters."
}
if ($RemoteDockerCommand -notmatch '^/[A-Za-z0-9._/-]+$') {
    throw "RemoteDockerCommand must be an absolute path without spaces."
}

$image = "ccr.ccs.tencentyun.com/mycodex/mycodex-relay:$Version"
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("mycodex-relay-tcr-" + [Guid]::NewGuid().ToString("N"))
$temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
if (-not $resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($resolvedTemporaryRoot)).StartsWith("mycodex-relay-tcr-", [StringComparison]::Ordinal)) {
    throw "Unsafe temporary directory: $resolvedTemporaryRoot"
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Get-BuildArguments {
    param([string]$Context)

    return @(
        "buildx", "build",
        "--platform", "linux/amd64,linux/arm64",
        "--build-arg", "VERSION=$Version",
        "--build-arg", "REVISION=$Revision",
        "--tag", $image,
        "--push",
        $Context
    )
}

function Publish-LocalImage {
    Invoke-External -FilePath "docker" -Arguments @("buildx", "version")
    Invoke-External -FilePath "docker" -Arguments (Get-BuildArguments -Context $repoRoot)
}

function Publish-RemoteImage {
    $remoteRoot = "/tmp/mycodex-relay-tcr-" + [Guid]::NewGuid().ToString("N")
    if (-not $remoteRoot.StartsWith("/tmp/mycodex-relay-tcr-", [StringComparison]::Ordinal)) {
        throw "Unsafe remote temporary directory: $remoteRoot"
    }

    $contextRoot = Join-Path $temporaryRoot "context"
    New-Item -ItemType Directory -Force -Path $contextRoot | Out-Null
    foreach ($file in @("Dockerfile", "go.mod", "go.sum")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $file) -Destination $contextRoot
    }
    foreach ($directory in @("cmd", "internal")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $directory) -Destination $contextRoot -Recurse
    }
    $contextArchive = Join-Path $temporaryRoot "context.tar.gz"
    Invoke-External -FilePath "tar" -Arguments @("-C", $contextRoot, "-czf", $contextArchive, ".")

    try {
        Invoke-External -FilePath "ssh" -Arguments @($DockerHost, "mkdir -p '$remoteRoot/context'")
        Invoke-External -FilePath "scp" -Arguments @($contextArchive, "${DockerHost}:$remoteRoot/context.tar.gz")
        Invoke-External -FilePath "ssh" -Arguments @(
            $DockerHost,
            "tar -xzf '$remoteRoot/context.tar.gz' -C '$remoteRoot/context'"
        )

        $remoteArguments = Get-BuildArguments -Context "$remoteRoot/context"
        Invoke-External -FilePath "ssh" -Arguments @(
            $DockerHost,
            "$RemoteDockerCommand $($remoteArguments -join ' ')"
        )
    }
    finally {
        & ssh $DockerHost "rm -rf -- '$remoteRoot'" 2>$null
    }
}

try {
    New-Item -ItemType Directory -Force -Path $temporaryRoot | Out-Null
    if ([string]::IsNullOrWhiteSpace($DockerHost)) {
        Publish-LocalImage
    }
    else {
        Publish-RemoteImage
    }
    Write-Host "Published multi-platform image: $image"
}
finally {
    if (Test-Path -LiteralPath $resolvedTemporaryRoot) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
