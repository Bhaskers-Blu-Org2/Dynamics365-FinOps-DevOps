# ARM VHD and Scripts

## Known Limitations

The scripts are samples only, and do not manage exceptions and error conditions well.

## How To Start Using This Sample

### DevInstallPackages.ps1
This script can "devinstall" a deployable package or set of packages. By default it will then also run DB Sync and deploy reports
when all the packages are installed. The following arguments are accepted:<br />
<br />
- packagesToInstallPath is the path to a folder contain all the zipped packages to install
- tempFolder is an optional path to unzip the packages to and run the axupdateinstaller from (defaults to C:\Temp)
- packagesFolder is an optional path to the packages folder for the AOS, and defaults to "C:\AosService\PackagesLocalDirectory"
- skipDBSync is a switch to indicate you do not wish to sync the database after all the packages are devinstall'ed
- skipReportDeploy is a switch to indicate you do not wish to deploy the reports after all the packages are devinstall'ed
<br />
Consider the advantages and disadvantages of the 'devinstall' feature before using this automated feature.

### RunBookInstallUpdate.ps1
This script can take any deployable package, including binary updates, and install them on "onebox" topologies (tier1 or VHD).<br />
- packagePath specifies the path to the deployable package ZIP file
- tempFolder is an optional path to unzip the packages to and run the axupdateinstaller from (defaults to C:\Temp)
- dontSkipBackup is a switch that disables the default behavior of this script that disables the backup steps of the runbook installer


### Final Words
These are sample scripts for development purposes, but they can be adapted and used in many ways. For example, consider using VSTS to automate deploying new VMs using
the ARM-VHD-Simple sample and deploying custom code or platform updates for testing purposes.<br />

## Contributing
See [the readme](/README.md) at the root of this repository about contributing to this repository.

<br />
<br />
Copyright (c) 2018 Microsoft Corp. All rights reserved.