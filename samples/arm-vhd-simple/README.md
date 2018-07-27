# ARM VHD and Scripts

## Dependency

This sample uses the [AOSConfigs PowerShell Module](/aosconfigs/) to manage the configuration of the AOS on the VHD.

## Known Limitations

Currently the scripts only configure the AOS to run correctly. There is no support yet for SSRS, MR, Retail, DIXF or any other non-AOS components on the VM.

## How To Start Using This Sample

### 1. Configure your AAD
Since the VM will be using a custom URL/Domain, AAD will refuse the login because the AOS application ID was not setup to allow logins against this URL. To avoid this problem, a new application will have to be registered in the tenant's AAD with the expected URLs. Then the AOS has to be reconfigured to use this new application ID - which the scripts will take care of.<br/>
Open the [Azure Portal](https://portal.azure.com) as an admin for the tenant. Navigate to the **Azure Active Directory** blade from the left-hand list. Click on **App Registrations**. Add a new application registration of type **Web app / API**. Give it a name, and the sign on URL should reflect the expected URL that will be used to sign on. If using wildcards please use security best practices such as being as specific as possible. You can explicitly add, edit and remove multiple reply-URLs from the **Settings** after the application registration has been created. When finished, note the **Application ID** as you will need it later for the AOS configuration.<br/>
For more information, see [Integrating applications with Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications) for more information on how to setup an application registration.

### 2. Prepare a VHD
To use the ARM template and scripts, you will need a generalized (sysprep) VHD file. To begin, download the VHD of one or more versions of Dynamics 365 for F&O from the [Lifecycle Services website](https://lcs.dynamics.com) and perform the following steps:
1. Azure requires a fixed-size VHD. The VHD downloaded from LCS is a dynamically expanding VHD, so it has to be converted first. If you have access to a Hyper-V client this can be done through the inspect disk feature. Alternatively, there are [PowerShell cmdlets](https://docs.microsoft.com/en-us/powershell/module/hyper-v/convert-vhd?view=win10-ps) you can use as well.
2. Create and start a new VM using the fixed-size VHD.
3. Optionally turn off any services you deem unnecessary to be running for your purpose of these samples. For example, turning off Financial Reporting (Managemetn Reporter service) by changing its startup type to manual. Potentially install any available Windows updates.
4. Finally, generalize (sysprep) the VM. The generalize options should be set for OOBE (out of box experience). See [the documentation on sysprep](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation) for more information.
5. Upload the final VHD to blob storage in Azure to be used with ARM. More information in the next steps.

### 3. Deploy the ARM Template
The ARM template itself requires a few parameters as listed below. Note that any ARM template can be used and this is just a basic sample which is not specific to Dynamics 365 F&O.
- Storage URL to the generalized (sysprep) Dynamics 365 F&O VHD (used as the [blobUri parameter to create an image](https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/images#imageosdisk-object))
- VM Size (in the format listed [ described here](https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines#hardwareprofile-object))
- VM Name which will be used as the actual computer name ([see documentation](https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines#osprofile-object))
- DNS Label prefix for the URL, which could be the same as the VM Name but as it's used for a public URL needs to be unique across the Azure region.
- Admin user name on the VM itself, in case RDP is needed ([see documentation](https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines#osprofile-object))
- Admin password for the VM itself ([see documentation](https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines#osprofile-object))
- IP Whitelist to allow only certain IPs through for RDP, used in the network security group ([see documentation](https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups#securityrulepropertiesformat-object))

Also note that the ARM template has an output that returns the public FQDN (URL) for the VM created. This will be in a format like: DNSLabelPrefix.datacenter.cloudapp.azure.com

### 4. Run the SetupVM.ps1
SetupVM.ps1 along with the [AOSConfigs PowerShell Module](/aosconfigs/) can be executed on the VM, to finalize the AOS configuration to work with its new name, passwords, URL, etc. The script will generate new self-signed certificates for SSL and encryption on the VM. ARM templates have features to supply certificates to be installed automatically during VM deployment, which is a great option to consider.<br />
The SetupVM.ps1 expects the following parameters:
- adminEmail is the AAD email of the user to make the admin in the AOS instance. The domain of this email will also be used to find the AAD tenant to tie this environment to.
- FQDN is the new URL used by the VM. This ties into the DNS Label prefix documentation from above. (the output parameter of the ARM)
- appID is the new application ID registered in the AAD Tenant, as described in the first step of this documentation.
- databasePassword is a new SQL database password to be used for the AOS login 'axdbadmin'
- configsPath can be omitted and left to its default C:\AOSService\webroot
- packagesFolder can be omitted and left to its default C:\AOSService\PackagesLocalDirectory

### Final Words
This is a sample template and script, and VMs can be deployed in many ways with many features. For example, consider using custom DNS URLs, and supplying certificates through KeyVault instead of self-signed certificates generated by the script.

## Contributing
See [the readme](/README.md) at the root of this repository about contributing to this repository.


<br />
<br />
Copyright (c) 2018 Microsoft Corp. All rights reserved.