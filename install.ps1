# install.ps1 - Automated installer for wreq
[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\wreq"
)

$ErrorActionPreference = "Stop"

$repo = "shekel588/wreq-cli"
if ($Version -eq "latest") {
    $apiUrl = "https://api.github.com/repos/$repo/releases/latest"
    Write-Host "Fetching latest release information for $repo..." -ForegroundColor Cyan
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "wreq-installer" }
        $tag = $release.tag_name
    } catch {
        Write-Error "Failed to fetch release info: $_"
        exit 1
    }
} else {
    $tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
}

$zipUrl = "https://github.com/$repo/releases/download/$tag/wreq-windows-x64.zip"
$shaUrl = "https://github.com/$repo/releases/download/$tag/wreq-windows-x64.zip.sha256"

$tempDir = Join-Path $env:TEMP "wreq-install-$tag"
if (!(Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

$tempZip = Join-Path $tempDir "wreq-windows-x64.zip"
$tempSha = Join-Path $tempDir "wreq-windows-x64.zip.sha256"

Write-Host "Downloading wreq ($tag)..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip
Invoke-WebRequest -Uri $shaUrl -OutFile $tempSha

Write-Host "Verifying SHA256 integrity..." -ForegroundColor Cyan
$expectedSha = (Get-Content -Raw $tempSha).Trim().Split(" ")[0].ToLower()
$actualSha = (Get-FileHash -Algorithm SHA256 $tempZip).Hash.ToLower()

if ($expectedSha -ne $actualSha) {
    Remove-Item -Recurse -Force $tempDir
    Write-Error "Security verification failed! Checksum mismatch.`nExpected: $expectedSha`nActual:   $actualSha"
    exit 1
}
Write-Host "Integrity verified (SHA256: $actualSha)" -ForegroundColor Green

if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "Extracting to $InstallDir..." -ForegroundColor Cyan
Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
Remove-Item -Recurse -Force $tempDir

# Ensure directory is in User PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -split ";" -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to User PATH." -ForegroundColor Yellow
}

$exePath = Join-Path $InstallDir "wreq.exe"
if (Test-Path $exePath) {
    Write-Host "`nwreq successfully installed!" -ForegroundColor Green
    & $exePath --version
} else {
    Write-Error "Installation failed: $exePath not found after extraction."
}
