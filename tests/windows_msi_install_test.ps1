param(
    [Parameter(Mandatory=$true)][string]$Driver,
    [Parameter(Mandatory=$true)][string]$Companion,
    [Parameter(Mandatory=$true)][string]$Key,
    [Parameter(Mandatory=$true)][string]$CertDer,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][string]$Workspace
)
$ErrorActionPreference = 'Stop'
$fixtures = Join-Path $PSScriptRoot '../modules/osslsigncode/tests/files'
$work = Join-Path $Workspace ('msi-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$package = Join-Path $work 'installation.msi'
$cabinet = Join-Path $work 'payload.cab'
$payload = Join-Path $work 'FoobarEXE'
$destination = Join-Path $work 'installed'
$installed = Join-Path $destination 'FoobarAppl10.exe'
$productCode = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'

function Set-MsiField($record, $name, $index, $value) {
    $record.GetType().InvokeMember($name, 'SetProperty', $null, $record, @($index, $value)) | Out-Null
}
function Invoke-Msi($arguments, $logName, $allowedCodes = @(0, 3010)) {
    $log = Join-Path $work $logName
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList ($arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")) -Wait -PassThru
    if ($process.ExitCode -notin $allowedCodes) {
        if (Test-Path $log) { Get-Content $log -Tail 100 | Write-Host }
        throw "msiexec failed with $($process.ExitCode): $arguments"
    }
}
function Assert-PayloadSignature {
    if (!(Test-Path $installed)) { throw "MSI did not install $installed" }
    & $SignTool verify /pa /v $installed
    if ($LASTEXITCODE -ne 0) { throw 'Installed MSI payload signature did not verify' }
}

# The upstream fixture has a valid installation database but a zero-byte file.
# Populate it with the upstream PE fixture without executing installer actions.
Copy-Item (Join-Path $fixtures 'unsigned.msi') $package
Copy-Item (Join-Path $fixtures 'unsigned.exe') $payload
& makecab.exe /D CompressionType=MSZIP $payload $cabinet
if ($LASTEXITCODE -ne 0) { throw 'makecab failed' }
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($package, 1)
try {
    $record = $installer.CreateRecord(2)
    $record.SetStream(1, $cabinet)
    Set-MsiField $record 'StringData' 2 'Sample.cab'
    $view = $database.OpenView('UPDATE `_Streams` SET `Data` = ? WHERE `Name` = ?')
    $view.Execute($record); $view.Close()
    Set-MsiField $record 'IntegerData' 1 ([int](Get-Item $payload).Length)
    Set-MsiField $record 'StringData' 2 'FoobarEXE'
    $view = $database.OpenView('UPDATE `File` SET `FileSize` = ? WHERE `File` = ?')
    $view.Execute($record); $view.Close()
    foreach ($property in @('ProductCode', 'UpgradeCode')) {
        $value = if ($property -eq 'ProductCode') { $productCode } else { '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}' }
        Set-MsiField $record 'StringData' 1 $value
        Set-MsiField $record 'StringData' 2 $property
        $view = $database.OpenView('UPDATE `Property` SET `Value` = ? WHERE `Property` = ?')
        $view.Execute($record); $view.Close()
    }
    Set-MsiField $record 'StringData' 1 ('{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}')
    Set-MsiField $record 'StringData' 2 'MainExecutable'
    $view = $database.OpenView('UPDATE `Component` SET `ComponentId` = ? WHERE `Component` = ?')
    $view.Execute($record); $view.Close()
    $database.Commit()
} finally {
    if ($view) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null }
    if ($record) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null }
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

& $Driver $Companion $Key $CertDer $package --recursive
if ($LASTEXITCODE -ne 0) { throw 'Recursive MSI fixture signing failed' }
& $SignTool verify /pa /v $package
if ($LASTEXITCODE -ne 0) { throw 'Reconstructed MSI signature did not verify' }
$attemptedInstall = $false
try {
    $attemptedInstall = $true
    Invoke-Msi -arguments @('/i', "`"$package`"", "INSTALLDIR=`"$destination`"", 'ALLUSERS=""', 'MSIINSTALLPERUSER=1') -logName 'install.log'
    Assert-PayloadSignature
    $before = (Get-FileHash -Algorithm SHA256 $installed).Hash
    Remove-Item $installed
    Invoke-Msi -arguments @('/fa', $productCode) -logName 'repair.log'
    Assert-PayloadSignature
    if ((Get-FileHash -Algorithm SHA256 $installed).Hash -ne $before) { throw 'Repair changed the signed payload' }
} finally {
    if ($attemptedInstall) {
        Invoke-Msi -arguments @('/x', $productCode) -logName 'uninstall.log' -allowedCodes @(0, 3010, 1605)
    }
}
if (Test-Path $installed) { throw 'Uninstall left the installed fixture payload behind' }
Write-Host 'Windows recursive MSI installation, repair, and uninstall passed'
