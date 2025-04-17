#get resource groups with the Tag
connect-azaccount -identity
$rg = Get-AzResourceGroup 
Foreach($resource in $rg) {
    #stop VMs
    Stop-AzVM -force
    stop-azAksCluster
}



