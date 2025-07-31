<#
.SYNOPSIS
    Elevates PowerShell script execution with administrative privileges.

.DESCRIPTION
    This function checks if the current session has administrative privileges. 
    If not, it re-launches the script with elevated permissions using either 
    Windows Terminal or PowerShell directly. It intelligently detects the 
    execution environment and uses the appropriate method for elevation.
    
    The function supports both PowerShell 5.1 and PowerShell 7, caches 
    configuration parameters across calls, and provides flexible path 
    configuration options.

.PARAMETER ScriptPath
    Path to the script file that needs elevation. Defaults to the current script path.
    Must be a valid file path.

.PARAMETER WorkingDirectory
    Working directory for the elevated process. Defaults to the script's directory.
    Must be a valid directory path.

.PARAMETER TerminalPath
    Path to Windows Terminal executable. Defaults to the standard Windows Apps location.
    Used when running within Windows Terminal environment. If not found, falls back to PowerShell.

.PARAMETER PowershellPath
    Path to PowerShell 5.1 executable. Defaults to the current PowerShell installation.
    Used when PowershellVersion is set to '5'

.PARAMETER Powershell7Path
    Path to PowerShell 7 executable. Defaults to the standard Program Files location.
    Used when PowershellVersion is set to '7'

.PARAMETER PowershellVersion
    Specifies which PowerShell version to use for elevation.
    Valid values: '5', '7'
    Defaults to '5'

.PARAMETER ExecutionPolicy
    Execution policy to use for the elevated script. Defaults to 'RemoteSigned'.
    Valid values: Restricted, AllSigned, RemoteSigned, Unrestricted, Bypass, Undefined

.EXAMPLE
    Invoke-Elevation
    Elevates the current script with default settings using PowerShell 5.1.

.EXAMPLE
    Invoke-Elevation -ScriptPath "C:\Scripts\MyScript.ps1" -ExecutionPolicy Bypass
    Elevates a specific script with bypass execution policy.

.EXAMPLE
    Invoke-Elevation -WorkingDirectory "C:\MyProject" -PowershellVersion PS7
    Elevates current script with custom working directory using PowerShell 7.

.EXAMPLE
    Invoke-Elevation -TerminalPath "C:\Custom\Path\wt.exe" -ExecutionPolicy Unrestricted
    Elevates current script using custom Windows Terminal path.

.NOTES
    - Requires Windows operating system.
    - Requires PowerShell 5.1 or later.
    - Supports both PowerShell 5.1 and PowerShell 7 execution environments.
    - If elevation is successful, the current script will exit (when elevating itself).
    - Uses Windows Terminal if available, otherwise falls back to PowerShell.
    - Caches all variables across calls.
    - Function validates all path parameters before execution.

.LINK
    https://github.com/b12robot/PSUtils
#>
function Invoke-Elevation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ScriptPath = $MyInvocation.PSCommandPath,

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = $MyInvocation.PSScriptRoot,

        [Parameter(Mandatory = $false)]
        [string]$PowershellPath = "$PSHome\powershell.exe",

        [Parameter(Mandatory = $false)]
        [string]$Powershell7Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe",

        [Parameter(Mandatory = $false)]
        [string]$TerminalPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\wt.exe",

        [Parameter(Mandatory = $false)]
        [ValidateSet('Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass', 'Undefined')]
        [string]$ExecutionPolicy = 'RemoteSigned',

        [Parameter(Mandatory = $false)]
        [switch]$NoTerminal = $false,

        [Parameter(Mandatory = $false)]
        [switch]$UsePowerShell5 = $false,

        [Parameter(Mandatory = $false)]
        [switch]$UsePowerShell7 = $false
    )

    if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        # If ScriptPath is specified but WorkingDirectory is not.
        if (-not $PSBoundParameters.ContainsKey('WorkingDirectory') -and $PSBoundParameters.ContainsKey('ScriptPath')) {
            $WorkingDirectory = Split-Path -Path $ScriptPath -Parent
        }
        elseif (-not $PSBoundParameters.ContainsKey('WorkingDirectory') -and -not $Script:GlobalWorkingDirectory -and $Script:GlobalScriptPath) {
            $WorkingDirectory = Split-Path -Path $Script:GlobalScriptPath -Parent
        }

        # If Powershell7Path is specified but UsePowerShell7 is not true.
        if (-not $PSBoundParameters.ContainsKey('UsePowerShell7') -and $PSBoundParameters.ContainsKey('Powershell7Path')) {
            $UsePowerShell7 = $true
        }
        elseif (-not $PSBoundParameters.ContainsKey('UsePowerShell7') -and -not $Script:GlobalUsePowerShell7 -and $Script:GlobalPowershell7Path) {
            $UsePowerShell7 = $true
        }

        # Cache and validate parameters
        $CacheMap = [ordered]@{
            ScriptPath        = @{ Global = 'GlobalScriptPath'      ; Type = 'Leaf' }
            WorkingDirectory  = @{ Global = 'GlobalWorkingDirectory'; Type = 'Container' }
            TerminalPath      = @{ Global = 'GlobalTerminalPath'    ; Type = 'Leaf' }
            PowershellPath    = @{ Global = 'GlobalPowershellPath'  ; Type = 'Leaf' }
            Powershell7Path   = @{ Global = 'GlobalPowershell7Path' ; Type = 'Leaf' }
            ExecutionPolicy   = @{ Global = 'GlobalExecutionPolicy' ; Type = 'Value' }
            NoTerminal        = @{ Global = 'GlobalNoTerminal'      ; Type = 'Value' }
            UsePowerShell7    = @{ Global = 'GlobalUsePowerShell7'  ; Type = 'Value' }
        }

        foreach ($LocalName in $CacheMap.Keys) {
            $Config = $CacheMap[$LocalName]
            $GlobalName = $Config.Global
            $ValidationType = $Config.Type
            $CachedValue = Get-Variable -Name $GlobalName -ValueOnly -Scope Script -ErrorAction SilentlyContinue
            $LocalValue = Get-Variable -Name $LocalName -ValueOnly -ErrorAction SilentlyContinue

            if ($LocalValue -ne $CachedValue) {
                if ($ValidationType -in @('Leaf', 'Container')) {
                    if (-not (Test-Path -Path $LocalValue -PathType $ValidationType)) {
                        Write-Host "Please specify a valid path.`nInvalid path for the -$LocalName parameter: $LocalValue" -ForegroundColor Red
                        return
                    }
                }
                if ($PSBoundParameters.ContainsKey($LocalName)) {
                    Set-Variable -Name $GlobalName -Value $LocalValue -Scope Script
                }
                elseif ($CachedValue) {
                    Set-Variable -Name $LocalName -Value $CachedValue
                }
            }
        }

        # Select PowershellExe
        if ($UsePowerShell7) {
            $PowershellExe = $Powershell7Path
        }
        else {
            $PowershellExe = $PowershellPath
        }

        if ($NoTerminal -or -not $TerminalPath) {
            $Executable = $PowershellExe
            $Arguments = @(
                '-NoProfile', 
                '-ExecutionPolicy', $ExecutionPolicy, 
                '-File', "`"$ScriptPath`""
            )
        }
        else {
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

        # Start the process with elevated privileges.
        try {
            Write-Host 'Requesting administrative privileges...' -ForegroundColor Cyan
            Start-Process -FilePath $Executable -ArgumentList $Arguments -Verb 'RunAs' -WorkingDirectory $WorkingDirectory -ErrorAction 'Stop'
            if ($ScriptPath -eq $MyInvocation.PSCommandPath) {
                exit 0
            } else {
                return
            }
        }
        catch {
            Write-Host 'Failed to elevate privileges.' -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            if ($ScriptPath -eq $MyInvocation.PSCommandPath) {
                exit 1
            } else {
                return
            }
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
        [ValidateNotNullOrEmpty()]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $false)]
        [ValidateSet('ToConsole','NoConsole')]
        [string]$Output
    )

    if (-not $PSBoundParameters.ContainsKey('LogPath')) {
        if (-not $Script:GlobalLogPath) {
            $Script:GlobalLogPath = [System.IO.Path]::ChangeExtension($MyInvocation.PSCommandPath, '.log')
        }
        $LogPath = $Script:GlobalLogPath
    }
    else {
        $Script:GlobalLogPath = $LogPath
    }

    if (-not $PSBoundParameters.ContainsKey('Output')) {
        if (-not $Script:GlobalConsole) {
            $Script:GlobalConsole = 'ToConsole'
        }
        $Output = $Script:GlobalConsole
    }
    else {
        $Script:GlobalConsole = $Output
    }

    try {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $Level = $Level.ToUpper()
        $Entry = "$Timestamp [$Level] - $Message"
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
    }
}

Export-ModuleMember -Function Invoke-Elevation, Write-Log
