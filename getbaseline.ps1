
#Prerequisites

#install module to write output values to Word
install-module -name PSWriteOffice -Force
Connect-azAccount 

#get all the Privileged role assignments
$privRoles = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -match "Owner" -or $_.RoleDefinitionName -match "Contributor" -or $_.RoleDefinitionName -match "Global Administrator" } | Select-object DisplayName, RoleDefinitionName, Scope

#count privileged roles
$users = Get-aduser.count




$privRoles
#Inactive users 30,60,90,180 days - Requires an EntraID Premium license
$Inactiveusers= get-MgUser -Property DisplayName, UserPrincipalName, SignInActivity, UserType

#VMs and Encryption
#Get Subscription status for encryption at host is enabled
Get-AzProviderFeature -FeatureName "EncryptionAtHost" -ProviderNamespace "Microsoft.Compute"

#if Registratiion stat is "notregistered" cannot encrypt data at host
#to enable encryption at host, must be enabled at the subscription level

#enable encryption at host
#Register-AzProviderFeature -FeatureName "EncryptionAtHost" -ProviderNamespace "Microsoft.Compute"

#Check for VMs for update settings to enabled

#enable client extension for Windows
Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -ExtensionType 'ConfigurationforWindows' -Name 'AzurePolicyforWindows' -TypeHandlerVersion 1.0 -ResourceGroupName '<myResourceGroup>' -Location '<myLocation>' -VMName 'todd-test' -EnableAutomaticUpgrade $true

