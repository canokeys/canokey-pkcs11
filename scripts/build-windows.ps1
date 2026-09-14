param(
    [ValidateSet('x86', 'x64', 'arm64')][string]$Arch = 'x64',
    [ValidateSet('Debug', 'Release')][string]$Config = 'Release'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vs) { throw 'Visual Studio C++ tools are required' }
$triple = @{'x86'='i686-pc-windows-msvc'; 'x64'='x86_64-pc-windows-msvc'; 'arm64'='aarch64-pc-windows-msvc'}[$Arch]
$build = Join-Path $repo "build-windows-$Arch-$Config"
New-Item -ItemType Directory -Force $build | Out-Null
$batch = Join-Path $build 'build.cmd'
# One native VS environment controls both the C linker and Cargo target build.
@"
@echo off
call "$vs\Common7\Tools\VsDevCmd.bat" -arch=$Arch -host_arch=x64
if errorlevel 1 exit /b 1
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
cmake -S "$repo" -B "$build" -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_C_COMPILER_TARGET=$triple -DCMAKE_CXX_COMPILER_TARGET=$triple -DCMAKE_BUILD_TYPE=$Config -DCNK_RUST_TARGET=$triple -DBUILD_UNIT_TESTING=OFF -DBUILD_REAL_TESTING=ON -DBUILD_PROTOCOL_TESTING=ON
if errorlevel 1 exit /b 1
cmake --build "$build"
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $batch -Encoding ascii
& cmd.exe /d /c $batch
if ($LASTEXITCODE -ne 0) { throw "Windows $Arch $Config build failed" }
