<#
.SYNOPSIS
    Elevates PowerShell script execution with administrative privileges.

.DESCRIPTION
    This function checks if the current session has administrative privileges. 
    If not, it re-launches the script with elevated permissions using either 
    Windows Terminal or PowerShell directly. It intelligently detects the 
    execution environment and uses the appropriate method for elevation.

.PARAMETER ScriptPath
    Path to the script file that needs elevation. Defaults to the current script path.
    Must be a valid file path.

.PARAMETER WorkingDirectory
    Working directory for the elevated process. Defaults to the script's directory.
    Must be a valid directory path.

.PARAMETER TerminalPath
    Path to Windows Terminal executable. Defaults to the standard Windows Apps location.
    Used when running within Windows Terminal environment.

.PARAMETER PowershellPath
    Path to PowerShell executable. Defaults to the current PowerShell installation.
    Used as fallback or when not running in Windows Terminal.

.PARAMETER ExecutionPolicy
    Execution policy to use for the elevated script. Defaults to 'RemoteSigned'.
    Valid values: Restricted, AllSigned, RemoteSigned, Unrestricted, Bypass, Undefined.

.EXAMPLE
    Invoke-Elevation
    Elevates the current script with default settings.

.EXAMPLE
    Invoke-Elevation -ScriptPath "C:\Scripts\MyScript.ps1" -ExecutionPolicy Bypass
    Elevates a specific script with bypass execution policy.

.EXAMPLE
    Invoke-Elevation -WorkingDirectory "C:\MyProject" -ExecutionPolicy Unrestricted
    Elevates current script with custom working directory and execution policy.

.NOTES
    - Requires Windows operating system
    - Will exit current process if elevation is successful
    - Uses Windows Terminal if available, otherwise falls back to PowerShell
    - Maintains global variables for terminal and PowerShell paths across calls
#>
function Invoke-Elevation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ScriptPath = $MyInvocation.PSCommandPath,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$WorkingDirectory = $MyInvocation.PSScriptRoot,

        [Parameter(Mandatory = $false)]
        [string]$TerminalPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\wt.exe",

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$PowershellPath = "$PSHome\powershell.exe",

        [Parameter(Mandatory = $false)]
        [ValidateSet('Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass', 'Undefined')]
        [string]$ExecutionPolicy = 'RemoteSigned'
    )

    # Change WorkingDirectory if ScriptPath is provided but WorkingDirectory is not.
    if ($PSBoundParameters.ContainsKey('ScriptPath')) {
        if (-not $PSBoundParameters.ContainsKey('WorkingDirectory')) {
            $WorkingDirectory = Split-Path -Path $ScriptPath -Parent
        }
    }

    # Validate TerminalPath.
    if ($TerminalPath -ne $Script:GlobalTerminalPath) {
        if (-not (Test-Path $TerminalPath -PathType Leaf)) {
            $TerminalPath = $null
        }
    }

    # Change GlobalTerminalPath if TerminalPath is provided else use GlobalPowershellPath.
    if ($PSBoundParameters.ContainsKey('TerminalPath')) {
        # Set GlobalTerminalPath if not equal to TerminalPath.
        if ($TerminalPath -ne $Script:GlobalTerminalPath) {
            $Script:GlobalTerminalPath = $TerminalPath
        }
    }
    else {
        # Use GlobalTerminalPath if exists.
        if ($Script:GlobalTerminalPath) {
            $TerminalPath = $Script:GlobalTerminalPath
        }
    }

    # Change GlobalPowershellPath if PowershellPath is provided else use GlobalPowershellPath.
    if ($PSBoundParameters.ContainsKey('PowershellPath')) {
        # Set GlobalPowershellPath if not equal to PowershellPath.
        if ($PowershellPath -ne $Script:GlobalPowershellPath) {
            $Script:GlobalPowershellPath = $PowershellPath
        }
    }
    else {
        # Use GlobalPowershellPath if exists.
        if ($Script:GlobalPowershellPath) {
            $PowershellPath = $Script:GlobalPowershellPath
        }
    }

    # If current user is not an administrator, request elevation.
    if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Requesting administrative privileges...' -ForegroundColor Cyan
        # if Terminal application exits, use TerminalPath to elevate script else use PowershellPath.
        if ($TerminalPath) {
            $Executable = $TerminalPath
            $Arguments = @(
                'new-tab', 
                '--title', 'PowerShell', 
                '--startingDirectory', "`"$WorkingDirectory`"", 
                '--', 
                "`"$PowershellPath`"", 
                '-NoProfile', 
                '-ExecutionPolicy', $ExecutionPolicy, 
                '-File', "`"$ScriptPath`""
            )
        }
        else {
            $Executable = $PowershellPath
            $Arguments = @(
                '-NoProfile', 
                '-ExecutionPolicy', $ExecutionPolicy, 
                '-File', "`"$ScriptPath`""
            )
        }

        # Start the process with elevated privileges.
        try {
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
