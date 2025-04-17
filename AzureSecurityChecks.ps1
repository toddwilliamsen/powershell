# Ensure the ImportExcel module is installed: Install-Module -Name ImportExcel -Scope CurrentUser
Install-Module ImportExcel
# Prepare data storage for Azure and Kubernetes checks
$azureSecurityResults = @()
$kubernetesSecurityResults = @()

# Azure Security Checks
Write-Output "Starting Azure Security Checks..."
Connect-AzAccount

# Check Azure Security Center settings
$securitySettings = Get-AzSecurityPricing
foreach ($setting in $securitySettings) {
    $azureSecurityResults += [PSCustomObject]@{
        Category = "Azure Security Center"
        Name     = $setting.Name
        Detail   = "Security Tier: $($setting.PricingTier)"
    }
}

# Check Network Security Groups (NSGs)
$nsgs = Get-AzNetworkSecurityGroup
foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules) {
        $azureSecurityResults += [PSCustomObject]@{
            Category = "NSG Rules"
            Name     = $nsg.Name
            Detail   = "Rule: $($rule.Name), Priority: $($rule.Priority), Access: $($rule.Access), Direction: $($rule.Direction)"
        }
    }
}

# List resources without tags
$resources = Get-AzResource
foreach ($resource in $resources) {
    if (-not $resource.Tags) {
        $azureSecurityResults += [PSCustomObject]@{
            Category = "Untagged Resources"
            Name     = $resource.Name
            Detail   = "Resource Type: $($resource.ResourceType)"
        }
    }
}

# Kubernetes Security Checks
Write-Output "Starting Kubernetes Security Checks..."

# Check for Pods running with elevated privileges
$pods = kubectl get pods --all-namespaces -o json | ConvertFrom-Json
foreach ($pod in $pods.items) {
    if ($pod.spec.securityContext.runAsUser -eq 0) {
        $kubernetesSecurityResults += [PSCustomObject]@{
            Category = "Pods Running as Root"
            Name     = $pod.metadata.name
            Detail   = "Namespace: $($pod.metadata.namespace)"
        }
    }
}

# Check for Network Policies
$networkPolicies = kubectl get networkpolicies --all-namespaces
if ($networkPolicies) {
    $kubernetesSecurityResults += [PSCustomObject]@{
        Category = "Network Policies"
        Name     = "Network Policies Found"
        Detail   = "Policies are configured."
    }
} else {
    $kubernetesSecurityResults += [PSCustomObject]@{
        Category = "Network Policies"
        Name     = "No Network Policies"
        Detail   = "No policies configured!"
    }
}

# Check for unused Service Accounts
$serviceAccounts = kubectl get serviceaccounts --all-namespaces -o json | ConvertFrom-Json
foreach ($sa in $serviceAccounts.items) {
    $bindings = kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | ConvertFrom-Json
    if (-not ($bindings | Where-Object { $_.subjects.name -eq $sa.metadata.name })) {
        $kubernetesSecurityResults += [PSCustomObject]@{
            Category = "Unused Service Accounts"
            Name     = $sa.metadata.name
            Detail   = "Namespace: $($sa.metadata.namespace)"
        }
    }
}

# Export results to Excel
Write-Output "Exporting results to Excel..."

# Save Azure results to AzureSecurity.xlsx
$azureSecurityResults | Export-Excel -Path "AzureSecurity.xlsx" -WorksheetName "AzureSecurity"

# Save Kubernetes results to KubernetesSecurity.xlsx
$kubernetesSecurityResults | Export-Excel -Path "KubernetesSecurity.xlsx" -WorksheetName "KubernetesSecurity"

Write-Output "Results exported to AzureSecurity.xlsx and KubernetesSecurity.xlsx!"
