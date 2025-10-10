param(
    [switch]$Clean,
    [switch]$Wheel,
    [switch]$All,
    [switch]$Help
)

$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Cyan"

$ProjectName = "syshardn"
$Version = if (Test-Path "pyproject.toml") {
    (Select-String -Path "pyproject.toml" -Pattern '^version\s*=\s*"([^"]+)"').Matches.Groups[1].Value
} else {
    "0.1.0"
}
$Platform = "windows"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

if ($Help) {
    Write-Host "Usage: .\build.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Clean      Clean build directories before building"
    Write-Host "  -Wheel      Build Python wheel only"
    Write-Host "  -All        Build both executable and wheel"
    Write-Host "  -Help       Show this help message"
    exit 0
}

function Print-Section {
    param($Title)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $Blue
    Write-Host "  $Title" -ForegroundColor $Blue
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $Blue
}

$BuildWheel = $Wheel -or $All
$BuildExe = !$Wheel -or $All

if ($Clean) {
    Print-Section "Cleaning Build Directories"
    Write-Host "Removing build artifacts..." -ForegroundColor $Yellow
    
    Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "*.spec.bak" -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path . -Include "*.egg-info" -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path . -Include "__pycache__" -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path . -Include "*.pyc" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
    
    Write-Host "✓ Clean complete" -ForegroundColor $Green
}

Print-Section "Running Tests"
if (Get-Command pytest -ErrorAction SilentlyContinue) {
    Write-Host "Running test suite..." -ForegroundColor $Yellow
    python -m pytest tests/ -v --tb=short
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ All tests passed" -ForegroundColor $Green
    } else {
        Write-Host "✗ Tests failed! Build aborted." -ForegroundColor $Red
        exit 1
    }
} else {
    Write-Host "⚠ pytest not found, skipping tests" -ForegroundColor $Yellow
}

if ($BuildExe) {
    Print-Section "Building Standalone Executable"

    if (!(Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
        Write-Host "Installing PyInstaller..." -ForegroundColor $Yellow
        pip install pyinstaller
    }
    
    Write-Host "Building with PyInstaller..." -ForegroundColor $Yellow
    pyinstaller syshardn.spec --clean

    if (Test-Path "dist\$ProjectName.exe") {
        $OutputName = "$ProjectName-v$Version-$Platform-$Arch.exe"
        Move-Item "dist\$ProjectName.exe" "dist\$OutputName" -Force
        
        Write-Host ""
        Write-Host "✓ Executable built successfully!" -ForegroundColor $Green
        Write-Host "  Location: " -NoNewline -ForegroundColor $Green
        Write-Host "dist\$OutputName"

        $Size = (Get-Item "dist\$OutputName").Length / 1MB
        Write-Host "  Size: " -NoNewline -ForegroundColor $Green
        Write-Host ("{0:N2} MB" -f $Size)
        
        Print-Section "Testing Executable"
        Write-Host "Running basic tests..." -ForegroundColor $Yellow
        
        & "dist\$OutputName" --help | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Help command: OK" -ForegroundColor $Green
        }
        
        & "dist\$OutputName" list-rules | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ List rules: OK" -ForegroundColor $Green
        } else {
            Write-Host "✗ List rules failed" -ForegroundColor $Red
        }

        Print-Section "Creating Distribution Archive"
        Write-Host "Creating archive..." -ForegroundColor $Yellow
        
        $ArchiveName = "$ProjectName-v$Version-$Platform-$Arch.zip"
        Compress-Archive -Path "dist\$OutputName","rules" -DestinationPath "dist\$ArchiveName" -Force

        $Hash = (Get-FileHash "dist\$ArchiveName" -Algorithm SHA256).Hash
        $Hash | Out-File "dist\$ArchiveName.sha256" -Encoding ASCII
        
        Write-Host "✓ Archive created: $ArchiveName" -ForegroundColor $Green
        Write-Host "✓ Checksum: $ArchiveName.sha256" -ForegroundColor $Green
        
    } else {
        Write-Host "✗ Build failed! Executable not found." -ForegroundColor $Red
        exit 1
    }
}

if ($BuildWheel) {
    Print-Section "Building Python Wheel"

    python -c "import build" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing build tools..." -ForegroundColor $Yellow
        pip install build wheel
    }
    
    Write-Host "Building wheel package..." -ForegroundColor $Yellow
    python -m build

    $WheelFile = Get-ChildItem -Path "dist\*.whl" | Select-Object -First 1
    if ($WheelFile) {
        Write-Host "✓ Wheel built successfully!" -ForegroundColor $Green
        Write-Host "  Location: " -NoNewline -ForegroundColor $Green
        Write-Host $WheelFile.FullName

        $Size = $WheelFile.Length / 1KB
        Write-Host "  Size: " -NoNewline -ForegroundColor $Green
        Write-Host ("{0:N2} KB" -f $Size)

        $Hash = (Get-FileHash $WheelFile.FullName -Algorithm SHA256).Hash
        $Hash | Out-File "$($WheelFile.FullName).sha256" -Encoding ASCII
    } else {
        Write-Host "✗ Wheel build failed!" -ForegroundColor $Red
        exit 1
    }
}

Print-Section "Build Summary"
Write-Host "Build completed successfully!" -ForegroundColor $Green
Write-Host ""
Write-Host "Distribution files:"
Get-ChildItem -Path "dist" | ForEach-Object {
    $Size = if ($_.Length -gt 1MB) { "{0:N2} MB" -f ($_.Length / 1MB) } else { "{0:N2} KB" -f ($_.Length / 1KB) }
    Write-Host "  $($_.Name) ($Size)"
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor $Blue
Write-Host "  1. Test the executable: .\dist\$ProjectName-v$Version-$Platform-$Arch.exe list-rules"
Write-Host "  2. Transfer to target systems for testing"
Write-Host "  3. Run as Administrator for actual checks"
Write-Host ""
Write-Host "Quick test commands:" -ForegroundColor $Yellow
Write-Host "  .\dist\$ProjectName-v$Version-$Platform-$Arch.exe --help"
Write-Host "  .\dist\$ProjectName-v$Version-$Platform-$Arch.exe list-rules"
Write-Host "  .\dist\$ProjectName-v$Version-$Platform-$Arch.exe check --level moderate --dry-run"
Write-Host ""
Write-Host "✓ Done!" -ForegroundColor $Green
