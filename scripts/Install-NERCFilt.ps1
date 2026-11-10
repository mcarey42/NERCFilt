#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs, uninstalls or reports on the NERCFilt password filter.

.DESCRIPTION
    Install (default): checks that the DLL matches this machine's architecture
    and that Windows is new enough, warns about LSA Protection, copies
    NERCFilt.dll to System32, registers it with LSA and offers a restart.
    An existing NERCFilt.dll (possibly loaded by LSASS) is renamed, not
    overwritten.

    -Uninstall: unregisters NERCFilt and removes the DLL. If LSASS still has
    it loaded, the file is removed after the next restart.

    -Status: shows the installed version and SHA-256 (for baselines),
    registration state, LSA Protection state, the effective policy and
    recent Code Integrity events about NERCFilt.dll.

    LSA reads its list of password filters only at boot, so installing and
    uninstalling take effect after a restart.

.PARAMETER Path
    The NERCFilt.dll to install. Defaults to the copy next to this script.

.PARAMETER Force
    Install even though LSA Protection is enabled. The unsigned DLL will not
    load under LSA Protection, so passwords will NOT be filtered.

.PARAMETER Uninstall
    Unregister and remove NERCFilt.

.PARAMETER Status
    Report on the current installation; changes nothing.

.PARAMETER NoRestartPrompt
    Do not offer to restart (for scripted deployments).

.EXAMPLE
    .\Install-NERCFilt.ps1

.EXAMPLE
    .\Install-NERCFilt.ps1 -Status

.EXAMPLE
    .\Install-NERCFilt.ps1 -Uninstall

.LINK
    https://github.com/mcarey42/NERCFilt
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive installer output.')]
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string] $Path = (Join-Path $PSScriptRoot 'NERCFilt.dll'),

    [Parameter(ParameterSetName = 'Install')]
    [switch] $Force,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch] $Uninstall,

    [Parameter(Mandatory, ParameterSetName = 'Status')]
    [switch] $Status,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [switch] $NoRestartPrompt
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$System32 = Join-Path $env:SystemRoot 'System32'
$Target = Join-Path $System32 'NERCFilt.dll'
$Regsvr32 = Join-Path $System32 'regsvr32.exe'
$LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$PolicyKey = 'HKLM:\SOFTWARE\NERCFilt'
$PackageName = 'NERCFilt'

# Must match NERCFilt/PasswordPolicy.h.
$CipMinimumLength = 8
$MaximumLength = 256
$CipMinimumClasses = 3
$MaximumClasses = 4

function Get-RegistryValue([string] $Key, [string] $Name) {
    $item = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-NotificationPackageList {
    $value = Get-RegistryValue $LsaKey 'Notification Packages'
    if ($null -eq $value) { return }
    return [string[]] $value
}

function Test-Registered {
    return @(Get-NotificationPackageList) -contains $PackageName
}

function Get-OSArchitecture {
    # The machine-wide value is the native architecture even when this
    # PowerShell is running under emulation.
    return Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'PROCESSOR_ARCHITECTURE'
}

function Get-PEArchitecture([string] $File) {
    $stream = [IO.File]::OpenRead($File)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "$File is not a Windows DLL." }
        $stream.Position = 0x3C
        $stream.Position = $reader.ReadInt32()
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "$File is not a Windows DLL." }
        switch ($reader.ReadUInt16()) {
            0x8664 { return 'AMD64' }
            0xAA64 { return 'ARM64' }
            0x014C { return 'x86' }
            default { return 'unknown' }
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PackageSuffix([string] $Architecture) {
    if ($Architecture -eq 'AMD64') { return 'x64' }
    return $Architecture
}

function Test-LsaProtection {
    foreach ($name in 'RunAsPPL', 'RunAsPPLBoot') {
        $value = Get-RegistryValue $LsaKey $name
        if ($null -ne $value -and [int] $value -ne 0) { return $true }
    }
    return $false
}

function Invoke-Regsvr32([string[]] $Arguments) {
    $process = Start-Process -FilePath $Regsvr32 -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "regsvr32 $($Arguments -join ' ') failed (exit code $($process.ExitCode))."
    }
}

function Get-EffectiveSetting([string] $Name, [int] $Default, [int] $Minimum, [int] $Maximum) {
    $raw = Get-RegistryValue $PolicyKey $Name
    $effective = $Default
    $shown = 'not set'
    if ($raw -is [int]) {
        # Same clamping as the DLL. REG_DWORD reads back as a signed Int32.
        $requested = [int64] [BitConverter]::ToUInt32([BitConverter]::GetBytes([int] $raw), 0)
        $effective = [Math]::Min([Math]::Max($requested, [int64] $Minimum), [int64] $Maximum)
        $shown = "$requested"
    }
    elseif ($null -ne $raw) {
        $shown = 'ignored (not a REG_DWORD)'
    }
    return "$effective  (registry: $shown)"
}

function Request-Restart {
    if ($NoRestartPrompt) {
        Write-Host 'Restart this machine for the change to take effect.'
        return
    }
    $choice = $Host.UI.PromptForChoice('Restart required',
        'LSA reads its password filters at boot. Restart now?',
        [Management.Automation.Host.ChoiceDescription[]] @('&Yes', '&No'), 1)
    if ($choice -eq 0 -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart')) {
        Restart-Computer -Force
    }
    else {
        Write-Host 'Restart this machine for the change to take effect.'
    }
}

function Install-Filter {
    if (-not [Environment]::Is64BitProcess) {
        throw 'Run this script from 64-bit PowerShell; 32-bit PowerShell is redirected away from System32.'
    }
    if ([Environment]::OSVersion.Version.Build -lt 14393) {
        throw 'NERCFilt requires Windows Server 2016 or Windows 10 1607 (build 14393) or later.'
    }

    $source = (Resolve-Path -LiteralPath $Path).ProviderPath
    $os = Get-OSArchitecture
    $dll = Get-PEArchitecture $source
    if ($os -ne $dll) {
        throw "$source is the $(Get-PackageSuffix $dll) build, but Windows is $(Get-PackageSuffix $os). Use the NERCFilt-<version>-$(Get-PackageSuffix $os).zip package."
    }

    if (Test-LsaProtection) {
        $message = 'LSA Protection (RunAsPPL) is enabled. LSASS loads only plug-ins signed to ' +
                   "Microsoft's requirements for protected LSA. This build is unsigned: it will NOT load, " +
                   'and passwords will NOT be filtered.'
        if (-not $Force) { throw "$message Re-run with -Force to install anyway." }
        Write-Warning $message
    }

    if (-not $PSCmdlet.ShouldProcess($Target, "Install $source and register it with LSA")) { return }

    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $Target) {
        if ((Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash -eq $sourceHash) {
            Write-Host "$Target is already this version."
        }
        else {
            # LSASS may have the old DLL loaded: it cannot be overwritten, but it can be renamed.
            $oldName = 'NERCFilt.dll.old-{0:yyyyMMddHHmmss}' -f (Get-Date)
            Rename-Item -LiteralPath $Target -NewName $oldName
            Write-Host "Previous version renamed to $oldName; delete it after the restart."
            Copy-Item -LiteralPath $source -Destination $Target
        }
    }
    else {
        Copy-Item -LiteralPath $source -Destination $Target
    }

    Invoke-Regsvr32 @('/s', "`"$Target`"")
    if (-not (Test-Registered)) { throw 'Registration did not add NERCFilt to the LSA Notification Packages.' }

    $version = (Get-Item -LiteralPath $Target).VersionInfo.FileVersion
    Write-Host "Installed NERCFilt $version"
    Write-Host "  $Target"
    Write-Host "  SHA-256 $sourceHash"
    Request-Restart
}

function Uninstall-Filter {
    if (-not $PSCmdlet.ShouldProcess($Target, 'Unregister and remove NERCFilt')) { return }

    if (Test-Path -LiteralPath $Target) {
        Invoke-Regsvr32 @('/u', '/s', "`"$Target`"")
    }
    elseif (Test-Registered) {
        # The DLL is gone but the registration is not: remove the entry directly.
        $remaining = @(Get-NotificationPackageList | Where-Object { $_ -ne $PackageName })
        Set-ItemProperty -LiteralPath $LsaKey -Name 'Notification Packages' -Value ([string[]] $remaining) -Type MultiString
    }
    if (Test-Registered) { throw 'NERCFilt is still listed in the LSA Notification Packages.' }
    Write-Host 'NERCFilt unregistered.'

    if (Test-Path -LiteralPath $Target) {
        try {
            Remove-Item -LiteralPath $Target
            Write-Host "Removed $Target."
        }
        catch {
            Write-Host "$Target is in use by LSASS; delete it after the restart."
        }
    }
    Request-Restart
}

function Show-Status {
    $os = Get-OSArchitecture
    Write-Host "Windows            $([Environment]::OSVersion.Version) ($(Get-PackageSuffix $os))"

    if (Test-Path -LiteralPath $Target) {
        $item = Get-Item -LiteralPath $Target
        $hash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
        Write-Host "Installed          $($item.VersionInfo.FileVersion) ($(Get-PackageSuffix (Get-PEArchitecture $Target)))"
        Write-Host "  SHA-256          $hash"
    }
    else {
        Write-Host "Installed          no ($Target not found)"
    }

    Write-Host "Registered         $(if (Test-Registered) { 'yes' } else { 'no' })"
    Write-Host "  Packages         $(@(Get-NotificationPackageList) -join ', ')"

    $loaded = 'unknown (LSASS modules not readable)'
    try {
        $modules = (Get-Process -Name lsass).Modules | Where-Object { $_.ModuleName -eq 'NERCFilt.dll' }
        $loaded = if ($modules) { 'yes' } else { 'no (restart required after install?)' }
    }
    catch {
        Write-Verbose "Could not read LSASS modules: $_"
    }
    Write-Host "Loaded by LSASS    $loaded"

    if (Test-LsaProtection) {
        Write-Host 'LSA Protection     ENABLED - the unsigned DLL will not load'
    }
    else {
        Write-Host 'LSA Protection     not enabled'
    }

    Write-Host "Minimum length     $(Get-EffectiveSetting 'MinimumLength' $CipMinimumLength $CipMinimumLength $MaximumLength)"
    Write-Host "Character classes  $(Get-EffectiveSetting 'MinimumCharacterClasses' $CipMinimumClasses $CipMinimumClasses $MaximumClasses)"

    $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*NERCFilt*' })
    Write-Host "Code Integrity     $($events.Count) event(s) about NERCFilt.dll in the last 7 days"
    foreach ($e in $events | Select-Object -First 3) {
        Write-Host "  $($e.TimeCreated) [$($e.Id)] $(($e.Message -split "`n")[0])"
    }
}

if ($Uninstall) {
    Uninstall-Filter
}
elseif ($Status) {
    Show-Status
}
else {
    Install-Filter
}
