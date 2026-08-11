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

$dist = Join-Path $repoRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$targets = @(
    [PSCustomObject]@{ Platform = "linux/amd64"; Suffix = "linux-amd64" },
    [PSCustomObject]@{ Platform = "linux/arm64"; Suffix = "linux-arm64" }
)
$image = "mycodex-relay:$Version"
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("mycodex-relay-docker-release-" + [Guid]::NewGuid().ToString("N"))
$temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
if (-not $resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($resolvedTemporaryRoot)).StartsWith("mycodex-relay-docker-release-", [StringComparison]::Ordinal)) {
    throw "Unsafe temporary directory: $resolvedTemporaryRoot"
}
New-Item -ItemType Directory -Force -Path $temporaryRoot | Out-Null

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

function New-DockerBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RawImagePath,
        [Parameter(Mandatory = $true)][object]$Target
    )

    $bundleName = "mycodex-relay-$Version-docker-$($Target.Suffix)"
    $bundleRoot = Join-Path $temporaryRoot $bundleName
    $bundleDockerDir = Join-Path $bundleRoot "docker"
    New-Item -ItemType Directory -Force -Path $bundleDockerDir | Out-Null
    Copy-Item -LiteralPath $RawImagePath -Destination (Join-Path $bundleRoot "mycodex-relay-image.tar")
    Copy-Item -LiteralPath (Join-Path $repoRoot "docker\compose.release.yaml") -Destination (Join-Path $bundleRoot "compose.yaml")
    Copy-Item -LiteralPath (Join-Path $repoRoot "docker\relay-config.example.json") -Destination $bundleDockerDir
    Copy-Item -LiteralPath (Join-Path $repoRoot "docker\README.md") -Destination $bundleDockerDir
    [IO.File]::WriteAllText((Join-Path $bundleRoot ".env"), "MYCODEX_RELAY_VERSION=$Version`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $bundleRoot "VERSION.txt"), "$Version`n", [Text.UTF8Encoding]::new($false))

    $archivePath = Join-Path $dist "$bundleName.tar.gz"
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    Invoke-External -FilePath "tar" -Arguments @("-C", $temporaryRoot, "-czf", $archivePath, $bundleName)
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or (Get-Item -LiteralPath $archivePath).Length -eq 0) {
        throw "Docker release archive was not created: $archivePath"
    }

    $entries = @(& tar -tzf $archivePath)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Docker release archive: $archivePath"
    }
    foreach ($entry in @(
        "$bundleName/mycodex-relay-image.tar",
        "$bundleName/compose.yaml",
        "$bundleName/.env",
        "$bundleName/VERSION.txt",
        "$bundleName/docker/relay-config.example.json",
        "$bundleName/docker/README.md"
    )) {
        if ($entries -notcontains $entry) {
            throw "Docker release archive is missing $entry."
        }
    }
    Write-Host "Packaged $archivePath"
    return $archivePath
}

function Build-LocalImages {
    Invoke-External -FilePath "docker" -Arguments @("buildx", "version")
    foreach ($target in $targets) {
        $rawImagePath = Join-Path $temporaryRoot "image-$($target.Suffix).tar"
        Invoke-External -FilePath "docker" -Arguments @(
            "buildx", "build",
            "--platform", $target.Platform,
            "--build-arg", "VERSION=$Version",
            "--build-arg", "REVISION=$Revision",
            "--tag", $image,
            "--output", "type=docker,dest=$rawImagePath",
            $repoRoot
        )
        [void](New-DockerBundle -RawImagePath $rawImagePath -Target $target)
    }
}

function Build-RemoteImages {
    $remoteRoot = "/tmp/mycodex-relay-release-" + [Guid]::NewGuid().ToString("N")
    if (-not $remoteRoot.StartsWith("/tmp/mycodex-relay-release-", [StringComparison]::Ordinal)) {
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

        foreach ($target in $targets) {
            $remoteImagePath = "$remoteRoot/image-$($target.Suffix).tar"
            $command = "$RemoteDockerCommand buildx build" +
                " --platform '$($target.Platform)'" +
                " --build-arg 'VERSION=$Version'" +
                " --build-arg 'REVISION=$Revision'" +
                " --tag '$image'" +
                " --output 'type=docker,dest=$remoteImagePath'" +
                " '$remoteRoot/context'"
            Invoke-External -FilePath "ssh" -Arguments @($DockerHost, $command)
            $rawImagePath = Join-Path $temporaryRoot "image-$($target.Suffix).tar"
            Invoke-External -FilePath "scp" -Arguments @("${DockerHost}:$remoteImagePath", $rawImagePath)
            [void](New-DockerBundle -RawImagePath $rawImagePath -Target $target)
        }
    }
    finally {
        & ssh $DockerHost "rm -rf -- '$remoteRoot'" 2>$null
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($DockerHost)) {
        Build-LocalImages
    }
    else {
        Build-RemoteImages
    }

    $archivePaths = foreach ($target in $targets) {
        Join-Path $dist "mycodex-relay-$Version-docker-$($target.Suffix).tar.gz"
    }
    $checksumLines = foreach ($archivePath in $archivePaths) {
        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            throw "Docker release archive was not found: $archivePath"
        }
        $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($archivePath))"
    }
    $checksumPath = Join-Path $dist "DOCKER-SHA256SUMS.txt"
    [IO.File]::WriteAllLines($checksumPath, $checksumLines, [Text.UTF8Encoding]::new($false))
    if ($checksumLines.Count -ne $targets.Count) {
        throw "Expected $($targets.Count) Docker checksums, found $($checksumLines.Count)."
    }
    Write-Host "Wrote $checksumPath"
}
finally {
    if (Test-Path -LiteralPath $resolvedTemporaryRoot) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
