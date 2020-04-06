# Update-MyIPAzNSG

A small Azure PS script which allows to add/update your Public IP address to your Azure Network Security Group (see attached).

To update all NSG on all your Azure’s resource group:

.\Update-MyIPAzNSG.ps1 -AllResourceGroup

To update all NSG on a specific Azure’s resource group:

.\Update-MyIPAzNSG.ps1 -ResourceGroupName “MyResourceGroup”

To update a specific NSG in a specific Azure’s resource group:

.\Update-MyIPAzNSG.ps1 -ResourceGroupName “MyResourceGroupName” -NSGName “MyNSGName”
