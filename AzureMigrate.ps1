Param(
    [bool][parameter(Mandatory=$false,Position = 0)] $Migrate=$false,
    [bool][parameter(Mandatory=$false,Position = 1)] $Commit=$false,
    [bool][parameter(Mandatory=$false,Position = 2)] $Abort=$false
)



#------------------------------------------
# Helper functions
#------------------------------------------
Function PrettyTime()
{
    return "[" + (Get-Date -Format o) + "]"
}

Function Log($msg)
{
    Write-Verbose $( $(PrettyTime) + " " + $msg) -Verbose
}

Function Choice($title, $message, $yesvalue, $novalue, [scriptblock]$yesresult, [scriptblock]$noresult)
{
    #Confirmation prompt code, don't worry about this in the context of the migration
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "$yesvalue"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "$novalue"
    
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
    
    switch($result)
    {
        0 {$yesresult.Invoke()}
        1 {$noresult.Invoke()}
    }
}

#------------------------------------------

#Log if we are migrating or not right now
if($Migrate)
{
    Log "Migration flagged in script parameters. Items will be Prepared to migrate."
}
else
{
    Log "Validation only. Migration not flagged in this script run, add -Migrate flag to script to add preparation steps."
}

if($Commit)
{
    Log "Previous migrations will be committed. This flag means you have already run the script with -Migrate on the target subscription. Cancel if you have not."
}
else
{
    Log "Not committing in this run."
}

if($Migrate -and $Commit)
{
    Log "This is an aggressive schedule. Configurations will not be able to be validated before being committed and cannot be rolled back to ASM state after this."
    Choice "Aggressive migration" "Confirm that you want preparation and migration steps to happen without taking time to review. This cannot be rolled back." "Continue with migration" "Stop operation" {Log "Confirmed. Continuing with migration."} {Log "Exiting script.";exit}
}

#------------------------------------------
# Migration functions
#------------------------------------------
    
Function LoginToAzure
{
    #Login to ARM Account
    Log "Login to Azure RM model."
    Login-AzureRmAccount -ErrorAction Stop

    #Retrieve Subscriptions from Resource Manager
    Log "Retrieve available subscriptions and count."
    $RMSubs = Get-AzureRMSubscription | Sort SubscriptionName

    #Check number of subs
    if($RMSubs.count -gt 1)
    {
        Log "More than 1 subscription associated. Input subscription name manually."
        ($RMSubs).SubscriptionName; ""
        $RMSubscriptionName = Read-Host -Prompt "Enter subscription name" 
    }
    else
    {
        $RMSubscriptionName = $RMSubs.SubscriptionName
    }

    #Target subscription
    Log "Select Azure (ARM) Subscription: $RMSubscriptionName."
    Select-AzureRmSubscription -SubscriptionName $RMSubscriptionName -ErrorAction Stop

    #Register Migration provider and then wait until it finishes registering
    Log "Register Migration provider and wait until registration is complete."
    Register-AzureRmResourceProvider -ProviderNamespace Microsoft.ClassicInfrastructureMigrate
    do
    {
        $registration=Get-AzureRmResourceProvider -ProviderNamespace Microsoft.ClassicInfrastructureMigrate
        Start-Sleep 10
    }
    while($registration.RegistrationState -ne "Registered")
    Log "Migration provider registered."

    #Login to classic model(ASM)
    Log "Login to classic model."
    Add-AzureAccount -ErrorAction Stop

    #Retrieve subscriptions from classic model
    Log "Retrieve available subscriptions and count."
    $ClassicSubs=Get-AzureSubscription | Sort SubscriptionName

    if($ClassicSubs.count -gt 1)
    {
        Log "More than 1 subscription. Checking for subscription name match with Azure RM input."
        if(($ClassicSubs).SubscriptionName -contains $RMSubscriptionName)
        {
            Log "$RMSubscriptionName matches."
            $ClassicSubscriptionName=$RMSubscriptionName
        }
        else
        {
            Log "No subscription match. Breaking as there is an issue here"
            exit
        }
    }

    #Target subscriptions from classic model
    Log "Select Azure (ASM) Subscription: $ClassicSubscriptionName."
    Select-AzureSubscription –SubscriptionName $ClassicSubscriptionName -ErrorAction Stop
}

#Check for Virtual Networks, check for validation issues if they exist
Function Vnet
{
    Log "Identify virtual network(s)."
    $VNetConfig=(Get-AzureVNetConfig)
    [xml]$VNetXML=[xml]$VNetconfig.XMLConfiguration
    $AllVNets=$VNetxml.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.ChildNodes.Name
    if($AllVNets.Count -eq 0)
    {
        Log "No virtual networks to migrate."
        return
    }

    foreach($vnet in $AllVNets)
    {
        Log "Working on $vnet."
        #Check for a gateway. If one exists, we will need to deprovision it. While it will migrate, it will not work in ARM.
        $vnetGateway = Get-AzureVNetGateway -VNetName $vnet
        $GatewayExists = $false
        if($VNetGateway.State -eq "Provisioned")
        {
            Log "$vnet has a gateway. Will need to be removed."
            $GatewayExists = $true
        }
        else
        {
            Log "No gateway on $vnet. Preparation will proceed as configured."
        }
    
        #Run validation tests.
        Log "Running validation tests."
        $ValidationMessage = Move-AzureVirtualNetwork -Validate -VirtualNetworkName $vnet

        if($ValidationMessage.ValidationMessages.Count -gt 0 -and $ValidationMessage.ValidationMessages.ResultCategory -match "Error")
        {
            Log "Validation Failure. Rectify below issues and retry."
            Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
            $ValidationMessage.ValidationMessages
            exit
        }
        elseif($ValidationMessage.ValidationMessages.Count -gt 0)
        {
            Log "Validation warning. This migration may succeed, but issues should be resolved if possible before moving the preparation."
            Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
            $ValidationMessage.ValidationMessages
            Log "Warnings only. Prompting for bypass."
            Choice "Confirm bypass of validation warnings" "Do you want to continue script processing with the above validation warnings?" "Continue processing." "Exit script." {Log "Bypass confirmed. Continuing."} {Log "Exiting script.";exit}
        }
        else
        {
            Log "Validation successful"
        }

        if($Migrate)
        {
            #Prepare to move the network
            Log "Preparing to move network $vnet."
            Move-AzureVirtualNetwork -Prepare -VirtualNetworkName $vnet
        }
        if($Commit)
        {
            #Commit the network move.
            Log "Committing network $vnet."
            Move-AzureVirtualNetwork -Commit -VirtualNetworkName $vnetName -Confirm
        }
    }
}

#Move the offnet VMs. Machines can be migrated to an existing vnet that has been prepared or to an isolated vnet. This step should be completed after virtual network migration to migrate any stragglers over.
Function Offnet
{
    if(!$Migrate)
    {
        Log "Standalone VMs need to have a network to move to. This involves either placing them on an existing virtual network or making an isolated one. Validation will fail without a destination virtual network. This warning can be ignored if the virtual network migration has already occurred."
        Start-Sleep -Seconds 20
    }
    #Retrieve non-VNet based services
    $StandaloneServices=@()
    $Services=(Get-AzureService).ServiceName
    foreach($service in $Services)
    {
        if((Get-AzureDeployment -ServiceName $service).VNetName -eq $null)
        {
            $StandaloneServices+= $service
        }
    }
    if($StandaloneServices.Count -eq 0)
    {
        Log "No standalone VMs."
        return
    }
    #Retrieve existing Azure RM virtual networks. These may not exist yet if it is the first run. Populate needed variables.
    $RMVnets=Get-AzureRmVirtualNetwork

    
    if($RMVnets.count -eq 1)
    {
        $DestinationVnet = $RMVnets.Name
        $DestinationRG = $RMVnets.ResourceGroupName
        $RMVnets | Get-AzureRmVirtualNetworkSubnetConfig | ft name,addressprefix; ""
        $DestinationSubnet = Read-Host -Prompt "Enter subnet name"
    }
    elseif($RMVnets.count -gt 1)
    {
        Log "More than 1 virtual network associated. Input virtual network name manually."
        $rmvnets | ft Name, ResourceGroupName, Location; ""
        $DestinationVnet = Read-Host -Prompt "Enter virtual network name"
        $DestinationRG = Read-Host -Prompt "Enter resource group name"
        Get-AzureRmVirtualNetwork -Name $DestinationVnet -ResourceGroupName $DestinationRG | Get-AzureRmVirtualNetworkSubnetConfig | ft name,addressprefix; ""
        $DestinationSubnet = Read-Host -Prompt "Enter subnet name"
    }
    elseif($RMVnets.count -eq 0)
    {
        Log "No Azure RM model virtual networks. A destination network is needed for standalone VMs. A new standalone network can be created if desired. If you have virtual networks that you would like to migrate into, complete the vnet migrations before running the standalone vm migration"
        Start-Sleep 10
        
    }
    foreach($service in $StandaloneServices)
    {
        Choice "Make standalone virtual network?" "This will create a virtual network for only this VM. Choosing no will use the above network." "Create the virtual network." "Do not create the virtual network and use identified network above" {Log "Creating virtual network for VM $service";$script:Isolated=$true} {Log "Using above noted network";$script:Isolated=$false}
        $deployment = Get-AzureDeployment -ServiceName $service
        if($Isolated)
        {
            $ValidationMessage = Move-AzureService -Validate -ServiceName $service -DeploymentName $deployment.DeploymentName -CreateNewVirtualNetwork
            if($ValidationMessage.ValidationMessages.Count -gt 0 -and $ValidationMessage.ValidationMessages.ResultCategory -match "Error")
            {
                Log "Validation Failure. Rectify below issues and retry."
                Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
                $ValidationMessage.ValidationMessages
                exit
            }
            elseif($ValidationMessage.ValidationMessages.Count -gt 0)
            {
                Log "Validation warning. This migration may succeed, but issues should be resolved if possible before moving the preparation."
                Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
                $ValidationMessage.ValidationMessages
                Log "Warnings only. Prompting for bypass."
                Choice "Confirm bypass of validation warnings" "Do you want to continue script processing with the above validation warnings?" "Continue processing." "Exit script." {Log "Bypass confirmed. Continuing."} {Log "Exiting script.";exit}
            }
            else
            {
                Log "Validation successful"
            }
            
            if($Migrate)
            {
                   Log "Preparing $service.ServiceName with an isolated virtual network."
                   Move-AzureService -Prepare -ServiceName $service `-DeploymentName $deployment.DeploymentName -CreateNewVirtualNetwork
            }
            if($Commit)
            {
                   Log "Committing $service.ServiceName."
                   Move-AzureService -Commit -ServiceName $service `-DeploymentName $deployment.DeploymentName
            }
            if($Abort)
            {
                Log "Aborting migration of $service.ServiceName."
                Move-AzureService -Abort -ServiceName $service `-DeploymentName $deployment.DeploymentName
            }
        }
        else
        {
            $ValidationMessage = Move-AzureService -Validate -ServiceName $service `-DeploymentName $deployment.DeploymentName -UseExistingVirtualNetwork -VirtualNetworkResourceGroupName $DestinationRG -VirtualNetworkName $DestinationVnet -SubnetName $DestinationSubnet
            if($ValidationMessage.ValidationMessages.Count -gt 0 -and $ValidationMessage.ValidationMessages.ResultCategory -match "Error")
            {
                Log "Validation Failure. Rectify below issues and retry."
                Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
                $ValidationMessage.ValidationMessages
                exit
            }
            elseif($ValidationMessage.ValidationMessages.Count -gt 0)
            {
                Log "Validation warning. This migration may succeed, but issues should be resolved if possible before moving the preparation."
                Log ($ValidationMessage.ValidationMessages.Count.ToString() + " issue(s).")
                $ValidationMessage.ValidationMessages
                Log "Warnings only. Prompting for bypass."
                Choice "Confirm bypass of validation warnings" "Do you want to continue script processing with the above validation warnings?" "Continue processing." "Exit script." {Log "Bypass confirmed. Continuing."} {Log "Exiting script.";exit}
            }
            else
            {
                Log "Validation successful"
            }
            if($Migrate)
            {
                   Log "Preparing $service with an isolated virtual network."
                   Move-AzureService -Prepare -ServiceName $service `-DeploymentName $deployment.DeploymentName -UseExistingVirtualNetwork -VirtualNetworkResourceGroupName $DestinationRG -VirtualNetworkName $DestinationVnet -SubnetName $DestinationSubnet
            }
            if($Commit)
            {
                   Log "Committing $service."
                   Move-AzureService -Commit -ServiceName $service `-DeploymentName $deployment.DeploymentName
            }
            if($Abort)
            {
                Log "Aborting migration of $service."
                Move-AzureService -Abort -ServiceName $service `-DeploymentName $deployment.DeploymentName
            }
        }
    }
}


Function StorageAccounts
{
    #Move the storage accounts
    Log "Identify all storage accounts."
    $StorageAccounts = Get-AzureStorageAccount
    if($StorageAccounts.Count -eq 0)
    {
        Log "No storage accounts to migrate."
        break
    }
    if($Migrate)
    {
        #Prepare the storage accounts.
        Foreach($account in $StorageAccounts)
        {
            Log "Preparing to move storage account $account.StorageAccountName."
            Move-AzureStorageAccount -Prepare -StorageAccountName $account.StorageAccountName
        }
    }
    if($Commit)
    {    
        #Commit the storage accounts
        Foreach($account in $StorageAccounts)
        {
            Log "Committing storage account $account.StorageAccountName."
            Move-AzureStorageAccount -Commit -StorageAccountName $account.StorageAccountName
        }
    }
    if($Abort)
    {    
        #Commit the storage accounts
        Foreach($account in $StorageAccounts)
        {
            Log "Aborting migration of storage account $account.StorageAccountName."
            Move-AzureStorageAccount -Abort -StorageAccountName $account.StorageAccountName
        }
    }
}

#Main Script body

LoginToAzure
Vnet
Offnet
StorageAccounts