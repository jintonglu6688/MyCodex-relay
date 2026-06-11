param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Remove-Item -Path (Join-Path $dist "mycodex-relay-*") -Force -ErrorAction SilentlyContinue

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Dir = "windows-x64"; Binary = "mycodex-relay.exe"; Scripts = "windows-x64" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Dir = "linux-x64"; Binary = "mycodex-relay"; Scripts = "" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Dir = "linux-arm64"; Binary = "mycodex-relay"; Scripts = "" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Dir = "darwin-x64"; Binary = "mycodex-relay"; Scripts = "darwin-x64" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Dir = "darwin-arm64"; Binary = "mycodex-relay"; Scripts = "darwin-arm64" }
)

foreach ($target in $targets) {
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH
    $targetDir = Join-Path $dist $target.Dir
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    $output = Join-Path $targetDir $target.Binary
    go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$Version" -o $output ./cmd/mycodex-relay
    Write-Host "Built $output"

    if ($target.Scripts -ne "") {
        $scriptDir = Join-Path $PSScriptRoot (Join-Path "package" $target.Scripts)
        if (Test-Path $scriptDir) {
            Copy-Item -Path (Join-Path $scriptDir "*") -Destination $targetDir -Force
        }
    }
}
