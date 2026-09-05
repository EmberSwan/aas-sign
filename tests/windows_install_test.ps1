# Native Windows acceptance checks. The fixture certificate exists only in
# LocalMachine\Root and LocalMachine\TrustedPeople for this test and is removed
# even if deployment fails. MSIX deployment checks machine certificate trust.
param(
    [Parameter(Mandatory=$true)][string]$Driver,
    [Parameter(Mandatory=$true)][string]$Companion,
    [Parameter(Mandatory=$true)][string]$Key,
    [Parameter(Mandatory=$true)][string]$CertDer,
    [Parameter(Mandatory=$true)][string]$Workspace
)
$ErrorActionPreference = 'Stop'
# Python inherits PowerShell 7's module search path in CI. Prefer this Windows
# PowerShell host's modules for Cert: and Get-FileHash instead of mixing versions.
$nativeModules = Join-Path $PSHOME 'Modules'
$env:PSModulePath = $nativeModules + [IO.Path]::PathSeparator + $env:PSModulePath
foreach ($module in @('Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')) {
    Import-Module (Join-Path $nativeModules "$module\$module.psd1") -ErrorAction Stop
}
$Driver = (Resolve-Path $Driver).Path
$Companion = (Resolve-Path $Companion).Path
$Workspace = (Resolve-Path $Workspace).Path
$Key = (Resolve-Path $Key).Path
$CertDer = (Resolve-Path $CertDer).Path
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$SignTool = Get-ChildItem "$sdk\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
$MakeAppx = Get-ChildItem "$sdk\*\x64\makeappx.exe" | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (!$SignTool -or !$MakeAppx) { throw 'Windows SDK SignTool and MakeAppx are required' }
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertDer)
$thumbprint = $certificate.Thumbprint
$preexisting = Test-Path "Cert:\LocalMachine\Root\$thumbprint"
$preexistingMachine = Test-Path "Cert:\LocalMachine\TrustedPeople\$thumbprint"
if (Get-AppxPackage -Name osslsigncode) { throw 'Fixture package identity already exists on this machine' }
function Check-Native([string]$operation) {
    if ($LASTEXITCODE -ne 0) { throw "$operation failed with exit $LASTEXITCODE" }
}
try {
    # The machine store avoids the current-user root import confirmation dialog.
    Write-Host 'Trusting the temporary fixture certificate'
    if (!$preexisting) { Import-Certificate -FilePath $CertDer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null }
    if (!$preexistingMachine) { Import-Certificate -FilePath $CertDer -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null }
    Write-Host 'Verifying native Authenticode signatures'
    foreach ($extension in @('exe', 'msi', 'msix')) {
        $file = Get-ChildItem -LiteralPath $Workspace -Filter "artifact space *.$extension" | Select-Object -First 1
        & $SignTool verify /pa /v $file.FullName
        Check-Native "SignTool verify $extension"
    }
    Write-Host 'Testing recursive MSI installation and repair'
    & "$PSScriptRoot/windows_msi_install_test.ps1" -Driver $Driver -Companion $Companion -Key $Key -CertDer $CertDer -SignTool $SignTool -Workspace $Workspace

    # Repack with the SDK to exercise the native package/bundle writer as well
    # as the portable fixture generator used in the cross-platform tests.
    $unpacked = Join-Path $Workspace 'sdk-unpacked'
    $unsigned = Join-Path $Workspace 'inner.msix'
    & $MakeAppx unpack /p $unsigned /d $unpacked /o
    Check-Native 'MakeAppx unpack'
    # The upstream APPX fixture predates MSIX extensions. Bundle payloads named
    # .msix require Windows 10 1809 or later in the temporary test manifest.
    $manifestPath = Join-Path $unpacked 'AppxManifest.xml'
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
    foreach ($family in $manifest.Package.Dependencies.TargetDeviceFamily) {
        $family.MinVersion = '10.0.17763.0'
        $family.MaxVersionTested = '10.0.17763.0'
    }
    $manifest.Save($manifestPath)
    $packages = Join-Path $Workspace 'sdk-packages'
    New-Item -ItemType Directory -Path $packages | Out-Null
    $package = Join-Path $packages 'app.msix'
    & $MakeAppx pack /d $unpacked /p $package /o
    Check-Native 'MakeAppx pack'
    # The companion preserves embedded packages. Windows deployment requires
    # their signatures too, so sign the package before creating the bundle.
    & $Driver $Companion $Key $CertDer $package
    Check-Native 'Sign package with Azure test adapter'
    $bundle = Join-Path $Workspace 'sdk.msixbundle'
    & $MakeAppx bundle /d $packages /p $bundle /bv 2.5.0.0 /o
    Check-Native 'MakeAppx bundle'
    & $Driver $Companion $Key $CertDer $bundle
    Check-Native 'Sign bundle with Azure test adapter'
    foreach ($target in @($package, $bundle)) {
        & $SignTool verify /pa /v $target
        Check-Native 'SignTool verify package'
        Write-Host "Deploying $target"
        Add-AppxPackage -Path $target -ForceApplicationShutdown -ErrorAction Stop
        $installed = Get-AppxPackage -Name osslsigncode
        if (!$installed) { throw 'Signed package was not installed' }
        $installed | Remove-AppxPackage -ErrorAction Stop
    }
    Write-Host 'Windows MSIX package and bundle deployment passed'
} finally {
    Get-AppxPackage -Name osslsigncode | Remove-AppxPackage -ErrorAction Continue
    if (!$preexisting) { Remove-Item "Cert:\LocalMachine\Root\$thumbprint" -ErrorAction SilentlyContinue }
    if (!$preexistingMachine) { Remove-Item "Cert:\LocalMachine\TrustedPeople\$thumbprint" -ErrorAction SilentlyContinue }
    $certificate.Dispose()
}
