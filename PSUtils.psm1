<#
.SYNOPSIS
    Relaunches a PowerShell script with administrative privileges using Windows Terminal or PowerShell; supports PS5/PS7, parameter validation, and script-scope caching.

.DESCRIPTION
    This function checks whether the current session has administrative privileges.
    If not, it relaunches the specified script with elevated permissions using either
    Windows Terminal (when available) or the chosen PowerShell executable. It detects
    the runtime environment, supports PowerShell 5.1 and PowerShell 7, validates
    path parameters, and caches configuration in script scope for subsequent calls.

.PARAMETER ScriptPath
    Path to the script file that needs elevation.
    Defaults to the invoked script path.

.PARAMETER WorkingDirectory
    Working directory for the elevated process.
    Defaults to the invoked script's directory.

.PARAMETER Powershell5Path
    Path to PowerShell 5.1 executable.
    Defaults to '$PSHome\powershell.exe'.

.PARAMETER Powershell7Path
    Path to PowerShell 7 executable.
    Defaults to '$env:ProgramFiles\PowerShell\7\pwsh.exe'.

.PARAMETER PowershellVersion
    Which PowerShell version to use for elevation.
    Valid values: 'Auto', '5', '7'.
    Defaults to 'Auto'.

.PARAMETER TerminalPath
    Path to Windows Terminal executable.
    Defaults to '$env:LocalAppData\Microsoft\WindowsApps\wt.exe'.

.PARAMETER TerminalMode
    Terminal usage mode.
    Valid values: 'Auto', 'UseTerminal', 'NoTerminal'.
    Defaults to 'Auto'.

.PARAMETER ExecutionPolicy
    Execution policy to use for the elevated script.
    Valid values: 'Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass', 'Undefined'.
    Defaults to 'RemoteSigned'.

.EXAMPLE
    Invoke-Elevation

.EXAMPLE
    Invoke-Elevation -ScriptPath "C:\Scripts\MyScript.ps1" -ExecutionPolicy Bypass

.NOTES
    - Requires Windows 10 or higher operating system.
    - Supports PowerShell 5.1 and 7.
    - If elevating the running script, the original process exits after starting the elevated one.

.LINK
    https://github.com/b12robot/PSUtils
#>
function Invoke-Elevation {
    [CmdletBinding()]
    param(
        [Alias('Path')]
        [string]$ScriptPath = $MyInvocation.PSCommandPath,

        [Alias('WorkDir')]
        [string]$WorkingDirectory = $MyInvocation.PSScriptRoot,

        [Alias('PowershellPath', 'PSPath', 'PS5Path')]
        [string]$Powershell5Path = "$PSHome\powershell.exe",

        [Alias('PwshPath', 'PS7Path')]
        [string]$Powershell7Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe",

        [ValidateSet('Auto', '5', '7')]
        [Alias('PSVersion')]
        [string]$PowershellVersion = 'Auto',

        [Alias('WTPath')]
        [string]$TerminalPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\wt.exe",

        [ValidateSet('Auto', 'UseTerminal', 'NoTerminal')]
        [Alias('WTMode')]
        [string]$TerminalMode = 'Auto',

        [ValidateSet('Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass', 'Undefined')]
        [Alias('ExePolicy')]
        [string]$ExecutionPolicy = 'RemoteSigned'
    )

    # Exit if already running as administrator
    if (([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    # Set working directory if not provided
    if (-not $PSBoundParameters.ContainsKey('WorkingDirectory') -and $PSBoundParameters.ContainsKey('ScriptPath')) {
        $WorkingDirectory = Split-Path -Path $ScriptPath -Parent
    }
    elseif (-not $PSBoundParameters.ContainsKey('WorkingDirectory') -and -not $Script:GlobalWorkingDirectory -and $Script:GlobalScriptPath) {
        $WorkingDirectory = Split-Path -Path $Script:GlobalScriptPath -Parent
    }

    # Cache parameters and validate paths
    $CacheMap = [ordered]@{
        ScriptPath        = @{ Global = 'GlobalScriptPath'        ; Type = 'Leaf' }
        WorkingDirectory  = @{ Global = 'GlobalWorkingDirectory'  ; Type = 'Container' }
        Powershell5Path   = @{ Global = 'GlobalPowershell5Path'   ; Type = 'Leaf' }
        Powershell7Path   = @{ Global = 'GlobalPowershell7Path'   ; Type = 'Leaf' }
        TerminalPath      = @{ Global = 'GlobalTerminalPath'      ; Type = 'Leaf' }
        PowershellVersion = @{ Global = 'GlobalPowershellVersion' ; Type = $null }
        TerminalMode      = @{ Global = 'GlobalTerminalMode'      ; Type = $null }
        ExecutionPolicy   = @{ Global = 'GlobalExecutionPolicy'   ; Type = $null }
    }

    foreach ($LocalName in $CacheMap.Keys) {
        $Config = $CacheMap[$LocalName]
        $GlobalName = $Config.Global
        $ValidationType = $Config.Type
        $GlobalValue = Get-Variable -Name $GlobalName -ValueOnly -Scope Script -ErrorAction SilentlyContinue
        $LocalValue = Get-Variable -Name $LocalName -ValueOnly -ErrorAction SilentlyContinue

        if ($LocalValue -ne $GlobalValue) {
            if ($PSBoundParameters.ContainsKey($LocalName)) {
                if ($ValidationType -in @('Leaf', 'Container')) {
                    if (-not (Test-Path -Path $LocalValue -PathType $ValidationType)) {
                        Write-Host "Invalid $LocalName path: '$LocalValue'" -ForegroundColor Red
                        return
                    }
                }
                Set-Variable -Name $GlobalName -Value $LocalValue -Scope Script
            }
            elseif ($GlobalValue) {
                Set-Variable -Name $LocalName -Value $GlobalValue
            }
        }
    }

    # Ensure ScriptPath is valid
    if (-not $ScriptPath) {
        Write-Host "Invalid script path: '$ScriptPath'" -ForegroundColor Red
        return
    }

    # Determine PowerShell version usage
    switch ($PowershellVersion) {
        'Auto' {
            if (($PSVersionTable.PSVersion.Major -eq 5) -and $Powershell5Path) {
                $PowershellExe = $Powershell5Path
            }
            elseif (($PSVersionTable.PSVersion.Major -eq 7) -and $Powershell7Path) {
                $PowershellExe = $Powershell7Path
            }
            else {
                Write-Host "Unable to locate PowerShell 5.1 or PowerShell 7 executables." -ForegroundColor Red
                return
            }
            break
        }
        '5' {
            if ($Powershell5Path) {
                $PowershellExe = $Powershell5Path
            }
            else {
                Write-Host "Unable to locate PowerShell 5.1 executable." -ForegroundColor Red
                return
            }
            break
        }
        '7' {
            if ($Powershell7Path) {
                $PowershellExe = $Powershell7Path
            }
            else {
                Write-Host "Unable to locate PowerShell 7 executable." -ForegroundColor Red
                return
            }
            break
        }
    }

    # Determine Windows Terminal usage
    switch ($TerminalMode) {
        'Auto' {
            if ($TerminalPath) {
                $Terminal = $true
            }
            else {
                $Terminal = $false
            }
            break
        }
        'UseTerminal' {
            if ($TerminalPath) {
                $Terminal = $true
            }
            else {
                Write-Host "Unable to locate Windows Terminal executable." -ForegroundColor Red
                return
            }
            break
        }
        'NoTerminal' {
            $Terminal = $false
            break
        }
    }

    # Prepare process arguments
    if ($Terminal) {
        $Executable = $TerminalPath
        $Arguments = @(
            'new-tab', 
            '--title', 'PowerShell', 
            '--startingDirectory', "`"$WorkingDirectory`"", 
            '--', 
            "`"$PowershellExe`"", 
            '-NoProfile', 
            '-ExecutionPolicy', $ExecutionPolicy, 
            '-File', "`"$ScriptPath`""
        )
    }
    else {
        $Executable = $PowershellExe
        $Arguments = @(
            '-NoProfile', 
            '-ExecutionPolicy', $ExecutionPolicy, 
            '-File', "`"$ScriptPath`""
        )
    }

    # Launch elevated process
    try {
        Write-Host "Requesting elevation to administrator privileges..." -ForegroundColor Cyan
        Start-Process -FilePath $Executable -ArgumentList $Arguments -Verb 'RunAs' -WorkingDirectory $WorkingDirectory -ErrorAction 'Stop'
        if ($ScriptPath -eq $MyInvocation.PSCommandPath) {
            exit 0
        } else {
            return
        }
    }
    catch {
        Write-Host "Elevation failed. $($_.Exception.Message)" -ForegroundColor Red
        if ($ScriptPath -eq $MyInvocation.PSCommandPath) {
            exit 1
        } else {
            return
        }
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateScript( { Test-Path -Path $_ -IsValid } )]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $false)]
        [ValidateSet('ToConsole','NoConsole')]
        [string]$Output
    )

    if ($PSBoundParameters.ContainsKey('LogPath')) {
        if ($LogPath -ne $Script:GlobalLogPath) {
            $Script:GlobalLogPath = $LogPath
        }
    }
    elseif ($Script:GlobalLogPath) {
        $LogPath = $Script:GlobalLogPath
    }
    else {
        $LogPath = [System.IO.Path]::ChangeExtension($MyInvocation.PSCommandPath, '.log')
    }

    if ($PSBoundParameters.ContainsKey('Output')) {
        if ($Output -ne $Script:GlobalOutput) {
            $Script:GlobalOutput = $Output
        }
    }
    elseif ($Script:GlobalOutput) {
        $Output = $Script:GlobalOutput
    }
    else {
        $Output = 'ToConsole'
    }

    try {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $Level = $Level.ToUpper()
        $PaddedLevel = $Level.PadRight(7)
        $Entry = "$Timestamp [$PaddedLevel] $Message"
        Add-Content -Path $LogPath -Value $Entry -Encoding UTF8
        if ($Output -eq 'ToConsole') {
            switch ($Level) {
                'ERROR'   { Write-Host $Entry -ForegroundColor Red; break }
                'WARNING' { Write-Host $Entry -ForegroundColor Yellow; break }
                'SUCCESS' { Write-Host $Entry -ForegroundColor Green; break }
                default   { Write-Host $Entry -ForegroundColor Cyan }
            }
        }
    }
    catch {
        Write-Host "Failed to write to log file: $LogPath" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

Export-ModuleMember -Function Invoke-Elevation, Write-Log
