#########################################################
# ********************* TO DO ***************************
# Add check to see if Regulatory Compliance is enabled
# Add error-control and logging
#########################################################

# Connect to Azure
Connect-AzAccount

#Get current subscription
$context = get-azcontext
$sub = $context.Subscription
#subscription ID
$sub.id

#Generate new SAS key that expires in 24 hours
$resourceGroupName = "Closet"
$accountName = "storagecloset"
$expiryTime = (Get-Date).AddDays(1)
$sasToken = New-AzStorageAccountSASToken -ResourceGroupName $resourceGroupName -AccountName $accountName -Service Blob,File -ResourceType Service,Container,Object -Permission "rw" -ExpiryTime $expiryTime
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -AccountName $accountName
$sasUrl = $storageAccount.PrimaryEndpoints.Blob + $sasToken
$storageContext = New-AzStorageContext -SasToken $sasURL

#import PowerShell Modules
Install-module -name Az.ResourceGraph
Import-module -name Az.ResourceGraph
Import-module ZeroTrustAssessment -Force
install-module -name Az.Security -force
import-module -name Az.Security
Install-Module Az.PolicyInsights -force
Import-module Az.PolicyInsights

#Queries
#Report on Managed Identities
$ManagedIdentities = @'
// Run query to see Managed Identities
resources
| where type =~ 'Microsoft.ManagedIdentity/userAssignedIdentities'
| project id,name,type,resourceGroup,location,subscriptionId,tenantId,kind,tags
| extend typeDisplayName=case(type =~ 'microsoft.managedidentity/userassignedidentities','Managed Identity',type)
| extend locationDisplayName=case(location =~ 'eastus','East US',location =~ 'southcentralus','South Central US',location =~ 'westus2','West US 2',location =~ 'westus3','West US 3',location =~ 'australiaeast','Australia East',location =~ 'southeastasia','Southeast Asia',location =~ 'northeurope','North Europe',location =~ 'swedencentral','Sweden Central',location =~ 'uksouth','UK South',location =~ 'westeurope','West Europe',location =~ 'centralus','Central US',location =~ 'southafricanorth','South Africa North',location =~ 'centralindia','Central India',location =~ 'eastasia','East Asia',location =~ 'indonesiacentral','Indonesia Central',location =~ 'japaneast','Japan East',location =~ 'japanwest','Japan West',location =~ 'koreacentral','Korea Central',location =~ 'newzealandnorth','New Zealand North',location =~ 'canadacentral','Canada Central',location =~ 'francecentral','France Central',location =~ 'germanywestcentral','Germany West Central',location =~ 'italynorth','Italy North',location =~ 'norwayeast','Norway East',location =~ 'polandcentral','Poland Central',location =~ 'spaincentral','Spain Central',location =~ 'switzerlandnorth','Switzerland North',location =~ 'mexicocentral','Mexico Central',location =~ 'uaenorth','UAE North',location =~ 'brazilsouth','Brazil South',location =~ 'israelcentral','Israel Central',location =~ 'qatarcentral','Qatar Central',location =~ 'centralusstage','Central US (Stage)',location =~ 'eastusstage','East US (Stage)',location =~ 'eastus2stage','East US 2 (Stage)',location =~ 'northcentralusstage','North Central US (Stage)',location =~ 'southcentralusstage','South Central US (Stage)',location =~ 'westusstage','West US (Stage)',location =~ 'westus2stage','West US 2 (Stage)',location =~ 'asia','Asia',location =~ 'asiapacific','Asia Pacific',location =~ 'australia','Australia',location =~ 'brazil','Brazil',location =~ 'canada','Canada',location =~ 'europe','Europe',location =~ 'france','France',location =~ 'germany','Germany',location =~ 'global','Global',location =~ 'india','India',location =~ 'israel','Israel',location =~ 'italy','Italy',location =~ 'japan','Japan',location =~ 'korea','Korea',location =~ 'newzealand','New Zealand',location =~ 'norway','Norway',location =~ 'poland','Poland',location =~ 'qatar','Qatar',location =~ 'singapore','Singapore',location =~ 'southafrica','South Africa',location =~ 'sweden','Sweden',location =~ 'switzerland','Switzerland',location =~ 'uae','United Arab Emirates',location =~ 'uk','United Kingdom',location =~ 'unitedstates','United States',location =~ 'unitedstateseuap','United States EUAP',location =~ 'eastasiastage','East Asia (Stage)',location =~ 'southeastasiastage','Southeast Asia (Stage)',location =~ 'brazilus','Brazil US',location =~ 'eastus2','East US 2',location =~ 'northcentralus','North Central US',location =~ 'westus','West US',location =~ 'jioindiawest','Jio India West',location =~ 'westcentralus','West Central US',location =~ 'southafricawest','South Africa West',location =~ 'australiacentral','Australia Central',location =~ 'australiacentral2','Australia Central 2',location =~ 'australiasoutheast','Australia Southeast',location =~ 'jioindiacentral','Jio India Central',location =~ 'koreasouth','Korea South',location =~ 'southindia','South India',location =~ 'westindia','West India',location =~ 'canadaeast','Canada East',location =~ 'francesouth','France South',location =~ 'germanynorth','Germany North',location =~ 'norwaywest','Norway West',location =~ 'switzerlandwest','Switzerland West',location =~ 'ukwest','UK West',location =~ 'uaecentral','UAE Central',location =~ 'brazilsoutheast','Brazil Southeast',location)
| where (type !~ ('dell.storage/filesystems'))
| where (type !~ ('microsoft.weightsandbiases/instances'))
| where (type !~ ('pinecone.vectordb/organizations'))
| where (type !~ ('mongodb.atlas/organizations'))
| where (type !~ ('lambdatest.hyperexecute/organizations'))
| where (type !~ ('commvault.contentstore/cloudaccounts'))
| where (type !~ ('arizeai.observabilityeval/organizations'))
| where (type !~ ('paloaltonetworks.cloudngfw/globalrulestacks'))
| where (type !~ ('microsoft.liftrpilot/organizations'))
| where (type !~ ('purestorage.block/storagepools/avsstoragecontainers'))
| where (type !~ ('purestorage.block/reservations'))
| where (type !~ ('purestorage.block/storagepools'))
| where (type !~ ('solarwinds.observability/organizations'))
| where (type !~ ('microsoft.agfoodplatform/farmbeats'))
| where (type !~ ('microsoft.agricultureplatform/agriservices'))
| where (type !~ ('microsoft.appsecurity/policies'))
| where (type !~ ('microsoft.arc/allfairfax'))
| where (type !~ ('microsoft.arc/all'))
| where (type !~ ('microsoft.cdn/profiles/securitypolicies'))
| where (type !~ ('microsoft.cdn/profiles/secrets'))
| where (type !~ ('microsoft.cdn/profiles/rulesets'))
| where (type !~ ('microsoft.cdn/profiles/rulesets/rules'))
| where (type !~ ('microsoft.cdn/profiles/afdendpoints/routes'))
| where (type !~ ('microsoft.cdn/profiles/origingroups'))
| where (type !~ ('microsoft.cdn/profiles/origingroups/origins'))
| where (type !~ ('microsoft.cdn/profiles/afdendpoints'))
| where (type !~ ('microsoft.cdn/profiles/customdomains'))
| where (type !~ ('microsoft.chaos/privateaccesses'))
| where (type !~ ('microsoft.sovereign/transparencylogs'))
| where (type !~ ('microsoft.sovereign/landingzoneconfigurations'))
| where (type !~ ('microsoft.cloudtest/accounts'))
| where (type !~ ('microsoft.cloudtest/hostedpools'))
| where (type !~ ('microsoft.cloudtest/images'))
| where (type !~ ('microsoft.cloudtest/pools'))
| where (type !~ ('microsoft.compute/virtualmachineflexinstances'))
| where (type !~ ('microsoft.compute/standbypoolinstance'))
| where (type !~ ('microsoft.compute/computefleetscalesets'))
| where (type !~ ('microsoft.compute/computefleetinstances'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))
| where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/namespaces'))
| where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/namespaces'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/extensions'))
| where (type !~ ('microsoft.kubernetesconfiguration/extensions'))
| where (type !~ ('microsoft.portalservices/extensions/deployments'))
| where (type !~ ('microsoft.portalservices/extensions'))
| where (type !~ ('microsoft.portalservices/extensions/slots'))
| where (type !~ ('microsoft.portalservices/extensions/versions'))
| where (type !~ ('microsoft.deviceregistry/devices'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/updates'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/deviceclasses'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/deployments'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/agents'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/activedeployments'))
| where (type !~ ('microsoft.documentdb/fleets'))
| where (type !~ ('private.easm/workspaces'))
| where (type !~ ('microsoft.workloads/epicvirtualinstances'))
| where (type !~ ('microsoft.fairfieldgardens/provisioningresources'))
| where (type !~ ('microsoft.fairfieldgardens/provisioningresources/provisioningpolicies'))
| where (type !~ ('microsoft.healthmodel/healthmodels'))
| where (type !~ ('microsoft.hybridcompute/machinessoftwareassurance'))
| where (type !~ ('microsoft.hybridcompute/machinespaygo'))
| where (type !~ ('microsoft.hybridcompute/machinesesu'))
| where (type !~ ('microsoft.hybridcompute/machinessovereign'))
| where (type !~ ('microsoft.hybridcompute/arcserverwithwac'))
| where (type !~ ('microsoft.network/networkvirtualappliances'))
| where (type !~ ('microsoft.network/virtualhubs')) or ((kind =~ ('routeserver')))
| where (type !~ ('microsoft.devhub/iacprofiles'))
| where (type !~ ('microsoft.dashboard/dashboards'))
| where (type !~ ('private.monitorgrafana/dashboards'))
| where (type !~ ('microsoft.insights/diagnosticsettings'))
| where not((type =~ ('microsoft.network/serviceendpointpolicies')) and ((kind =~ ('internal'))))
| where (type !~ ('microsoft.resources/resourcegraphvisualizer'))
| where (type !~ ('microsoft.orbital/l2connections'))
| where (type !~ ('microsoft.orbital/groundstations'))
| where (type !~ ('microsoft.orbital/geocatalogs'))
| where (type !~ ('microsoft.orbital/edgesites'))
| where (type !~ ('microsoft.recommendationsservice/accounts/modeling'))
| where (type !~ ('microsoft.recommendationsservice/accounts/serviceendpoints'))
| where (type !~ ('microsoft.recoveryservicesintd2/vaults'))
| where (type !~ ('microsoft.recoveryservicesintd/vaults'))
| where (type !~ ('microsoft.recoveryservicesbvtd2/vaults'))
| where (type !~ ('microsoft.recoveryservicesbvtd/vaults'))
| where (type !~ ('microsoft.relationships/servicegroupmember'))
| where (type !~ ('microsoft.relationships/dependencyof'))
| where (type !~ ('microsoft.resources/virtualsubscriptionsforresourcepicker'))
| where (type !~ ('microsoft.resources/deletedresources'))
| where (type !~ ('microsoft.deploymentmanager/rollouts'))
| where (type !~ ('microsoft.features/featureprovidernamespaces/featureconfigurations'))
| where (type !~ ('microsoft.saashub/cloudservices/hidden'))
| where (type !~ ('microsoft.providerhub/providerregistrations'))
| where (type !~ ('microsoft.providerhub/providerregistrations/customrollouts'))
| where (type !~ ('microsoft.providerhub/providerregistrations/defaultrollouts'))
| where (type !~ ('microsoft.edge/configurations'))
| where (type !~ ('microsoft.storagediscovery/storagediscoveryworkspaces'))
| where not((type =~ ('microsoft.synapse/workspaces/sqlpools')) and ((kind =~ ('v3'))))
| where (type !~ ('microsoft.mission/virtualenclaves/workloads'))
| where (type !~ ('microsoft.mission/virtualenclaves'))
| where (type !~ ('microsoft.mission/communities/transithubs'))
| where (type !~ ('microsoft.mission/virtualenclaves/enclaveendpoints'))
| where (type !~ ('microsoft.mission/enclaveconnections'))
| where (type !~ ('microsoft.mission/communities/communityendpoints'))
| where (type !~ ('microsoft.mission/communities'))
| where (type !~ ('microsoft.mission/catalogs'))
| where (type !~ ('microsoft.mission/approvals'))
| where (type !~ ('microsoft.workloads/insights'))
| where (type !~ ('microsoft.hanaonazure/sapmonitors'))
| where (type !~ ('microsoft.zerotrustsegmentation/segmentationmanagers'))
| where (type !~ ('microsoft.cloudhealth/healthmodels'))
| where (type !~ ('microsoft.connectedcache/enterprisemcccustomers/enterprisemcccachenodes'))
| where not((type =~ ('microsoft.sql/servers')) and ((kind =~ ('v12.0,analytics'))))
| where not((type =~ ('microsoft.sql/servers/databases')) and ((kind in~ ('system','v2.0,system','v12.0,system','v12.0,system,serverless','v12.0,user,datawarehouse,gen2,analytics'))))
| project name,typeDisplayName,resourceGroup,locationDisplayName,subscriptionId,id,type,kind,location,tags
| sort by (tolower(tostring(name))) asc
'@

# NIST 800-53 rev 5 query
$nistQuery = @'
// Regulatory compliance CSV report query for standard "NIST SP 800 53 R5" 
    securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments" | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" complianceControlId "/regulatoryComplianceAssessments" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId ==  "NIST SP 800 53 R5" 
    | extend failedResources = toint(properties.failedResources), passedResources = toint(properties.passedResources),skippedResources = toint(properties.skippedResources)
    | where failedResources + passedResources + skippedResources > 0 or properties.assessmentType == "MicrosoftManaged"
    | join kind = leftouter(
    securityresources
    | where type == "microsoft.security/assessments") on subscriptionId, name | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | extend complianceState = tostring(properties.state)
    | extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))
    | extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)
    | extend resourceId = trim(' ', tolower(tostring(case(resourceSource =~ 'azure', properties1.resourceDetails.Id,
                                                        resourceSource =~ 'gcp', properties1.resourceDetails.GcpResourceId,
                                                        resourceSource =~ 'aws' and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,
                                                        resourceSource =~ 'aws', properties1.resourceDetails.AwsResourceId,
                                                        extract('^(.+)/providers/Microsoft.Security/assessments/.+$',1,recommendationId)))))
    | extend regexResourceId = extract_all(@"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$", resourceId)[0]
    | extend resourceType = iff(resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType), iff(regexResourceId[1] != "", regexResourceId[1], iff(regexResourceId[0] != "", regexResourceId[0], "subscriptions")))
    | extend resourceName = tostring(regexResourceId[2])
    | extend recommendationName = name
    | extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))
    | extend description = tostring(properties1.metadata.description)
    | extend remediationSteps = tostring(properties1.metadata.remediationDescription)
    | extend severity = tostring(properties1.metadata.severity)
    | extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal) | mvexpand statusPerInitiative = properties1.statusPerInitiative
                | extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ "NIST SP 800 53 R5"
                | summarize arg_max(expectedInitiative, *) by complianceControlId, recommendationId
                | extend state = iff(expectedInitiative, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))
                | extend notApplicableReason = iff(expectedInitiative, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))
                | project-away expectedInitiative 
    | project complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup = resourceGroup1 ,resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName, description, remediationSteps, severity, state, notApplicableReason, azurePortalRecommendationLink| join kind = leftouter (securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId == "NIST SP 800 53 R5"
    | where properties.state != "Unsupported"
    | extend controlName = tostring(properties.description)
    | project controlId = name, controlName
    | distinct controlId, controlName) on $right.controlId == $left.complianceControlId
            | project-away controlId
            | distinct *
            | order by complianceControlId asc, recommendationId asc
'@

#CIS Azure Foundations v2.0.0 query
$cisAzQuery = @'
// Regulatory compliance CSV report query for standard "CIS Azure Foundations v2.0.0" 
    securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments" | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" complianceControlId "/regulatoryComplianceAssessments" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId ==  "CIS Azure Foundations v2.0.0" 
    | extend failedResources = toint(properties.failedResources), passedResources = toint(properties.passedResources),skippedResources = toint(properties.skippedResources)
    | where failedResources + passedResources + skippedResources > 0 or properties.assessmentType == "MicrosoftManaged"
    | join kind = leftouter(
    securityresources
    | where type == "microsoft.security/assessments") on subscriptionId, name | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | extend complianceState = tostring(properties.state)
    | extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))
    | extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)
    | extend resourceId = trim(' ', tolower(tostring(case(resourceSource =~ 'azure', properties1.resourceDetails.Id,
                                                        resourceSource =~ 'gcp', properties1.resourceDetails.GcpResourceId,
                                                        resourceSource =~ 'aws' and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,
                                                        resourceSource =~ 'aws', properties1.resourceDetails.AwsResourceId,
                                                        extract('^(.+)/providers/Microsoft.Security/assessments/.+$',1,recommendationId)))))
    | extend regexResourceId = extract_all(@"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$", resourceId)[0]
    | extend resourceType = iff(resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType), iff(regexResourceId[1] != "", regexResourceId[1], iff(regexResourceId[0] != "", regexResourceId[0], "subscriptions")))
    | extend resourceName = tostring(regexResourceId[2])
    | extend recommendationName = name
    | extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))
    | extend description = tostring(properties1.metadata.description)
    | extend remediationSteps = tostring(properties1.metadata.remediationDescription)
    | extend severity = tostring(properties1.metadata.severity)
    | extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal) | mvexpand statusPerInitiative = properties1.statusPerInitiative
                | extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ "CIS Azure Foundations v2.0.0"
                | summarize arg_max(expectedInitiative, *) by complianceControlId, recommendationId
                | extend state = iff(expectedInitiative, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))
                | extend notApplicableReason = iff(expectedInitiative, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))
                | project-away expectedInitiative 
    | project complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup = resourceGroup1 ,resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName, description, remediationSteps, severity, state, notApplicableReason, azurePortalRecommendationLink| join kind = leftouter (securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId == "CIS Azure Foundations v2.0.0"
    | where properties.state != "Unsupported"
    | extend controlName = tostring(properties.description)
    | project controlId = name, controlName
    | distinct controlId, controlName) on $right.controlId == $left.complianceControlId
            | project-away controlId
            | distinct *
            | order by complianceControlId asc, recommendationId asc
'@

# Azure Kubernetes CIS Benchmark v1.5.0 Query
$AKSquery = @' 
// Regulatory compliance CSV report query for standard "CIS Azure Kubernetes Service (AKS) Benchmark v1.5.0" 
// Change the 'complianceStandardId' column condition to select a different standard
    securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments" | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" complianceControlId "/regulatoryComplianceAssessments" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId ==  "CIS Azure Kubernetes Service (AKS) Benchmark v1.5.0" 
    | extend failedResources = toint(properties.failedResources), passedResources = toint(properties.passedResources),skippedResources = toint(properties.skippedResources)
    | where failedResources + passedResources + skippedResources > 0 or properties.assessmentType == "MicrosoftManaged"
    | join kind = leftouter(
    securityresources
    | where type == "microsoft.security/assessments") on subscriptionId, name | extend scope = properties.scope
     | where isempty(scope) or  scope in~("Subscription", "MultiCloudAggregation")
    | extend complianceState = tostring(properties.state)
    | extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))
    | extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)
    | extend resourceId = trim(' ', tolower(tostring(case(resourceSource =~ 'azure', properties1.resourceDetails.Id,
                                                        resourceSource =~ 'gcp', properties1.resourceDetails.GcpResourceId,
                                                        resourceSource =~ 'aws' and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,
                                                        resourceSource =~ 'aws', properties1.resourceDetails.AwsResourceId,
                                                        extract('^(.+)/providers/Microsoft.Security/assessments/.+$',1,recommendationId)))))
    | extend regexResourceId = extract_all(@"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$", resourceId)[0]
    | extend resourceType = iff(resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType), iff(regexResourceId[1] != "", regexResourceId[1], iff(regexResourceId[0] != "", regexResourceId[0], "subscriptions")))
    | extend resourceName = tostring(regexResourceId[2])
    | extend recommendationName = name
    | extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))
    | extend description = tostring(properties1.metadata.description)
    | extend remediationSteps = tostring(properties1.metadata.remediationDescription)
    | extend severity = tostring(properties1.metadata.severity)
    | extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal) | mvexpand statusPerInitiative = properties1.statusPerInitiative
                | extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ "CIS Azure Kubernetes Service (AKS) Benchmark v1.5.0"
                | summarize arg_max(expectedInitiative, *) by complianceControlId, recommendationId
                | extend state = iff(expectedInitiative, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))
                | extend notApplicableReason = iff(expectedInitiative, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))
                | project-away expectedInitiative 
    | project complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup = resourceGroup1 ,resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName, description, remediationSteps, severity, state, notApplicableReason, azurePortalRecommendationLink| join kind = leftouter (securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" *
    | extend complianceStandardId = replace( "-", " ", complianceStandardId)
    | where complianceStandardId == "CIS Azure Kubernetes Service (AKS) Benchmark v1.5.0"
    | where properties.state != "Unsupported"
    | extend controlName = tostring(properties.description)
    | project controlId = name, controlName
    | distinct controlId, controlName) on $right.controlId == $left.complianceControlId
            | project-away controlId
            | distinct *
            | order by complianceControlId asc, recommendationId asc
'@

#check to see if Defender for Cloud is Enabled
if(get-AzSecurityPricing -Name 'CloudPosture' -PricingTier -eq "Free") {
    Write-host "Microsoft Defender for Cloud is not enabled"
    $response = Read-host "Would you like to enable Microsoft Defender for Cloud & Regulatory Compliance? (yes/no)"
        if($response -eq "yes") {
            set-AzSecurityPricing -Name 'CloudPosture' -PricingTier "Standard"

    #enable Regulatory Compliance Standards

    $nist80053 = Get-AzPolicySetDefinition | Where-Object {$_.DisplayName -eq "NIST SP 800-53 Rev. 5"}

    #trigger Policy Scan
    write-host "Starting Compliance Scan...."
    Write-host "Compliance scan may take a while depends on the number of resources"
    start-azpolicyComplianceScan 
    
    write-host "Compiling Azure CIS 2.0 benchmark Policy Results"        
    $CISAZresults = search-azgraph -Query $cisAzQuery
    $CISAZresults | Export-Csv -Path "~/Documents/CISAZcompliance.csv" -NoTypeInformation

    Write-host "Compiling Azure Kubernetes Compliance Policy Results"
    $AKSresults = search-azgraph -Query $aksquery
    $aksresults | Export-Csv -Path "~/Documents/AKScompliance.csv" -NoTypeInformation
 
    Write-host "Compiling NIST 800-53 Compliance Policy Results"
    $NISTresults = search-azgraph -Query $nistQuery   
    $NISTresults | Export-Csv -Path "~/Documents/NISTcompliance.csv" -NoTypeInformation

    Write-host "Compiling list of Managed Identities"
    $ManagedIdentitiesResults = search-azgraph -Query $ManagedIdentities  
    $ManagedIdentitiesResults | Export-Csv -Path "~/Documents/managedIdentities.csv" -NoTypeInformation
   
    #Zero Trust Assessment
    Write-host "Running Zero Trust Assessment"
    Invoke-ZTAssessment -OutputFolder '~/Documents/'
} else {
    Write-host "Azure Defender for Cloud is not enabled"
}
}
#Upload Files to Azure Secured Storage 
 set-azstorageblobcontent -context $storagecontext -container "Files" -File "~/Documents/managedIdentities.csv"

Write-host "Disconnecting from Azure"
 disconnect-AzAccount
a