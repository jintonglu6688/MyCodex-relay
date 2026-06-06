param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Name = "mycodex-relay-windows-x64.exe" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Name = "mycodex-relay-linux-x64" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Name = "mycodex-relay-linux-arm64" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Name = "mycodex-relay-macos-x64" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Name = "mycodex-relay-macos-arm64" }
)

foreach ($target in $targets) {
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH
    $output = Join-Path $dist $target.Name
    go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$Version" -o $output ./cmd/mycodex-relay
    Write-Host "Built $output"
}
