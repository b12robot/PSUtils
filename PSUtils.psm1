<#
.SYNOPSIS
    Relaunches a PowerShell script with administrative privileges using Windows Terminal or PowerShell; supports PS5/PS7, parameter validation, and script-scope caching.

.DESCRIPTION
    This function checks whether the current session has administrative privileges.
    If not, it relaunches the specified script with elevated permissions using either
    Windows Terminal (when available) or the chosen PowerShell executable. It detects
    the runtime environment, supports PowerShell 5 and 7, validates
    path parameters, and caches configuration in script scope for subsequent calls.

.PARAMETER ScriptPath
    Path to the script file that needs elevation.
    Default: the invoked script path.

.PARAMETER WorkingDirectory
    Working directory for the elevated process.
    Default: the invoked script's directory.

.PARAMETER Powershell5Path
    Path to PowerShell 5 executable.
    Default: '$PSHome\powershell.exe'

.PARAMETER Powershell7Path
    Path to PowerShell 7 executable.
    Default: '$env:ProgramFiles\PowerShell\7\pwsh.exe'

.PARAMETER PowershellVersion
    Which PowerShell version to use for elevation.
    Valid values: 'Auto', '5', '7'
    Default: 'Auto'

.PARAMETER TerminalPath
    Path to Windows Terminal executable.
    Default: '$env:LocalAppData\Microsoft\WindowsApps\wt.exe'

.PARAMETER TerminalMode
    Terminal usage mode.
    Valid values: 'Auto', 'UseTerminal', 'NoTerminal'
    Default: 'Auto'

.PARAMETER ExecutionPolicy
    Execution policy to use for the elevated script.
    Valid values: 'Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass', 'Undefined'
    Default: 'RemoteSigned'

.EXAMPLE
    Invoke-Elevation

.EXAMPLE
    Invoke-Elevation -ScriptPath "C:\Scripts\MyScript.ps1" -ExecutionPolicy Bypass

.NOTES
    - Requires Windows 10 or 11 operating system.
    - Requires PowerShell 5 or 7 version.
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
        [string]$Powershell5Path,

        [Alias('PwshPath', 'PS7Path')]
        [string]$Powershell7Path,

        [ValidateSet('Auto', '5', '7')]
        [Alias('PSVersion')]
        [string]$PowershellVersion = 'Auto',

        [Alias('WTPath')]
        [string]$TerminalPath,

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

    # Validate paths and cache parameters
    $CacheMap = [ordered]@{
        ScriptPath        = @{ Global = 'GlobalScriptPath'        ; Type = 'Leaf'      ; Exe = $null }
        WorkingDirectory  = @{ Global = 'GlobalWorkingDirectory'  ; Type = 'Container' ; Exe = $null }
        Powershell5Path   = @{ Global = 'GlobalPowershell5Path'   ; Type = 'Leaf'      ; Exe = 'powershell.exe' }
        Powershell7Path   = @{ Global = 'GlobalPowershell7Path'   ; Type = 'Leaf'      ; Exe = 'pwsh.exe' }
        TerminalPath      = @{ Global = 'GlobalTerminalPath'      ; Type = 'Leaf'      ; Exe = 'wt.exe' }
        PowershellVersion = @{ Global = 'GlobalPowershellVersion' ; Type = $null       ; Exe = $null }
        TerminalMode      = @{ Global = 'GlobalTerminalMode'      ; Type = $null       ; Exe = $null }
        ExecutionPolicy   = @{ Global = 'GlobalExecutionPolicy'   ; Type = $null       ; Exe = $null }
    }

    foreach ($LocalName in $CacheMap.Keys) {
        $Config = $CacheMap[$LocalName]
        $GlobalName = $Config.Global
        $ValidationType = $Config.Type
        $ExeName = $Config.Exe
        $LocalValue = Get-Variable -Name $LocalName -ValueOnly -ErrorAction SilentlyContinue
        $GlobalValue = Get-Variable -Name $GlobalName -ValueOnly -Scope Script -ErrorAction SilentlyContinue

        if ($LocalValue -ne $GlobalValue) {
            if ($PSBoundParameters.ContainsKey($LocalName)) {
                if (-not [string]::IsNullOrWhiteSpace($LocalValue)) {
                    if ($ValidationType -in @('Leaf', 'Container')) {
                        if (-not (Test-Path -Path $LocalValue -PathType $ValidationType)) {
                            Set-Variable -Name $LocalName -Value $null
                            continue
                        }
                    }
                    Set-Variable -Name $GlobalName -Value $LocalValue -Scope Script
                }
            }
            elseif ($GlobalValue) {
                Set-Variable -Name $LocalName -Value $GlobalValue
            }
            elseif ($ExeName) {
                $GetCmd = Get-Command $ExeName -ErrorAction SilentlyContinue
                if ($GetCmd) {
                    $AutoValue = $GetCmd.Path
                    Set-Variable -Name $LocalName -Value $AutoValue
                    Set-Variable -Name $GlobalName -Value $AutoValue -Scope Script
                }
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
                Write-Host "Unable to locate PowerShell 5 or PowerShell 7 executables." -ForegroundColor Red
                return
            }
            break
        }
        '5' {
            if ($Powershell5Path) {
                $PowershellExe = $Powershell5Path
            }
            else {
                Write-Host "Unable to locate PowerShell 5 executable." -ForegroundColor Red
                $Script:GlobalScriptPath = $null
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
                $Script:GlobalScriptPath = $null
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
                $Script:GlobalTerminalPath = $null
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
        Write-Host "Failed to elevate script file: '$ScriptPath'" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        if ($ScriptPath -eq $MyInvocation.PSCommandPath) {
            exit 1
        } else {
            return
        }
    }
}

<#
.SYNOPSIS
    Provides a flexible logging function for scripts and modules. 
    It writes messages with a timestamp and severity level (INFO, SUCC, WARN, EROR) 
    to a log file and optionally to the console with color-coded output.

.DESCRIPTION
    The Write-Log function is designed to simplify logging within PowerShell scripts.  
    It automatically manages a global log file path and output mode if they are not specified.  
    Messages are written with a timestamp and log level, and when console output is enabled, 
    messages are displayed with colors for quick visual identification.

.PARAMETER Message
    The log message text to be recorded.
    This parameter is mandatory.

.PARAMETER LogPath
    Specifies the path of the log file.
    Default: the invoked script path with .log extension.

.PARAMETER Level
    Specifies the severity level of the log entry.  
    Valid values: 'INFO', 'SUCC', 'WARN', 'EROR'
    Default: 'INFO'

.PARAMETER Output
    Controls whether the message is also written to the console.  
    Valid values: 'ToConsole', 'NoConsole'  
    Default: 'ToConsole'

.EXAMPLE
    Write-Log -Message "Script execution started."
    Writes an INFO log entry with timestamp to the default log file and console.

.EXAMPLE
    Write-Log -Message "Package installed successfully" -Level SUCC -Output ToConsole
    Writes a success log entry in green to the console and appends it to the log file.

.EXAMPLE
    Write-Log -Message "Disk space is low" -Level WARN -LogPath "C:\Logs\system.log" -Output NoConsole
    Writes a warning log entry to the specified log file only, without console output.

.NOTES
    - Requires Windows 10 or 11 operating system.
    - Requires PowerShell 5 or 7 version.
.LINK
    https://github.com/b12robot/PSUtils
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [ValidateScript( { Test-Path -Path $_ -IsValid } )]
        [string]$LogPath,

        [ValidateSet('INFO','SUCC','WARN','EROR')]
        [string]$Level = 'INFO',

        [ValidateSet('ToConsole','NoConsole')]
        [string]$Output
    )

    # Determine LogPath parameter
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

    # Determine Output parameter
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

    # Write log entry to file
    try {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $Entry = "$Timestamp [$($Level.ToUpper())] $Message"
        Add-Content -Path $LogPath -Value $Entry -Encoding UTF8
        if ($Output -eq 'ToConsole') {
            switch ($Level) {
                'EROR'  { Write-Host $Entry -ForegroundColor Red    ; break }
                'WARN'  { Write-Host $Entry -ForegroundColor Yellow ; break }
                'SUCC'  { Write-Host $Entry -ForegroundColor Green  ; break }
                default { Write-Host $Entry -ForegroundColor Cyan }
            }
        }
    }
    catch {
        Write-Host "Failed to write log file: '$LogPath'" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
}

Export-ModuleMember -Function Invoke-Elevation, Write-Log
