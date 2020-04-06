Param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $NSGName,
    [String] $ResourceGroupName,
    [switch] $UpdateAllResourceGroup,
    [String] $GeoURI ="http://ipinfo.io/json"
)

Import-Module -Name Az.Compute

$res = get-module "Az.*" -ErrorAction SilentlyContinue
if ( ! $res )
{
    Write-Host "Az Powershell Modules are missing, installation is on going !"    
    Install-Module -Name Az -AllowClobber -Scope AllUsers -Force -confirm:$false
    Write-Host "ReRun the script !!!!" 
    sleep 10   
    exit 0
}

$Connected = Get-AzSubscription -ErrorAction Continue -OutVariable null 
if ( $Connected ) {
    "Already connected to the subscription"
}
else {
    Connect-AzAccount
}

$NSGRuleName="WFH-Rule"

if ( ! $UpdateAllResourceGroup)
{
    # Checking ResourceGroupName is existing and getting the Az locaiton from it
    $AzResourceGroupNames = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

    if ( ! ( $AzResourceGroupNames ) )
    {
        $list = Get-AzResourceGroup | select-object ResourceGroupName,Location
        Write-Host "See existing resource group"
        $list | ft
        throw "$ResourceGroupName does not exist on your subscription. Please create it First."
    }
    else
    {
        $LocationName = $AzResourceGroupNames.Location
    }
}
else
{
    Write-Host -ForegroundColor Yellow "Going to update $NSGRuleName for all ResourceGroup"
    $AzResourceGroupNames = Get-AzResourceGroup -ErrorAction SilentlyContinue
}

foreach( $AzResourceGroupName in $AzResourceGroupNames )
{
    $ResourceGroupName = $AzResourceGroupName.ResourceGroupName

    if ( $NSGName )
    {   
        $AzNetworkSecurityGroups = Get-AzNetworkSecurityGroup -ResourceName $NSGName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    }
    else
    {
        $AzNetworkSecurityGroups = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    }

    if ( ! $AzNetworkSecurityGroups )
    {
        $NSGName="NGS-Default"
        Write-Host -ForegroundColor Yellow "$NSGName does not exist so creation one called $NSGName."
        $AzNetworkSecurityGroups = New-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $ResourceGroupName `
                                    -Location $LocationName
    }

    #$MyPublicIp = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
    $IpInfo = (Invoke-WebRequest -uri $GeoURI) | convertfrom-json 
    $MyPublicIp = $IpInfo.IP

    #just a simple validation (could ge better)
    if ( ! ($MyPublicIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') ) 
    {
        throw "IP $MyPublicIp is not in a good format... Check if $GeoURI is not responding!"
    }

    $MyPublicIp+="/32"
    Write-Host -ForegroundColor Yellow  "Going to update Azure NSG with following IP $MyPublicIp "

    #Checking Network security rules
    ## Adding RCP + WMI
    foreach ( $AzNetworkSecurityGroup in $AzNetworkSecurityGroups)
    {
        if ( !( $AzNetworkSecurityGroup.SecurityRules | ? Name -eq $NSGRuleName)  ) 
        {
            Write-Host -foregroundcolor Green "Creating RG:$ResourceGroupName NSG:$($AzNetworkSecurityGroup.name) Rule:$NSGRuleName IP:$MyPublicIp"
            $AzNetworkSecurityGroup | Add-AzNetworkSecurityRuleConfig -Name $NSGRuleName -Description "Allow WFH IP address" -Access "Allow" `
                -Protocol "*" -Direction "Inbound" -Priority 110 -SourceAddressPrefix $MyPublicIp -SourcePortRange "*" `
                -DestinationAddressPrefix "*" -DestinationPortRange "*" | Set-AzNetworkSecurityGroup | Out-Null 
        }
        else
        {
            $NSGRule = ($AzNetworkSecurityGroup.SecurityRules | ? Name -eq $NSGRuleName).Name

            Write-Host -foregroundcolor Green "Updating RG:$ResourceGroupName NSG:$($AzNetworkSecurityGroup.name) Rule:$NSGRule IP:$MyPublicIp"
            Remove-AzNetworkSecurityRuleConfig -Name $NSGRule -NetworkSecurityGroup $AzNetworkSecurityGroup | Out-Null
            $AzNetworkSecurityGroup | Add-AzNetworkSecurityRuleConfig -Name $NSGRuleName -Description "Allow WFH IP address" -Access "Allow" `
                -Protocol "*" -Direction "Inbound" -Priority 110 -SourceAddressPrefix $MyPublicIp -SourcePortRange "*" `
                -DestinationAddressPrefix "*" -DestinationPortRange "*" | Set-AzNetworkSecurityGroup | Out-Null 
        }
    }
}