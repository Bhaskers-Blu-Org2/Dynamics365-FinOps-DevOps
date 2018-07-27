# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
Param(
    [string]$packagesToInstallPath,
    [string]$tempFolder = "C:\Temp",
    [string]$packagesFolder = "C:\AosService\PackagesLocalDirectory",
    [switch]$skipDBSync,
    [switch]$skipReportDeploy
)
$ErrorActionPreference = 'Stop'

# Find all runtime packages in a given path
$packages = Get-ChildItem -Path $packagesToInstallPath -Filter AXDeployableRuntime*.zip
ForEach($package in $packages)
{
    [string]$packageTempDirectory = Join-Path -Path $tempFolder -ChildPath ($package.Basename)
    if (!(Test-Path -Path $packageTempDirectory)) # If the folder doesn't exist, it's a new package to install!
    {
        Write-Verbose "Starting extraction of $($package.FullName)"
        & C:\DynamicsTools\7za.exe x $package.FullName -o"$($packageTempDirectory)" -r
        cd $packageTempDirectory

        # If the server is in some intermediate state, wait for it to finish
        $batch = Get-Service DynamicsAXBatch
        while (([string]$batch.Status).Contains("Pending"))
        {
            Write-Verbose "Waiting for batch..."
            Start-Sleep -Seconds 5
            $batch = Get-Service DynamicsAXBatch
        }

        Write-Verbose "Starting dev install of $($package.Basename)"
        & .\AxUpdateInstaller.exe devinstall
    }
    else # If the ZIP file already has a folder with the same name, we assume it was from a previous run...
    {
        Write-Verbose "Removing old $($package.Basename)"
        Remove-Item -Path $package.FullName -Force
        Remove-Item -Path $packageTempDirectory -Recurse -Force
    }
}

if (!$skipDBSync)
{
    $syncEngine = Join-Path -Path $packagesFolder -ChildPath "bin\SyncEngine.exe"
    & $syncEngine ("-syncmode=fullall") ("-metadatabinaries=$packagesFolder") ("-connect=`"Data Source=localhost;Initial Catalog=AxDB;Integrated Security=True;Enlist=True;Application Name=SyncEngine`"") ("-fallbacktonative=False") #-raiseDataEntityViewSyncNotification
}

if (!$skipReportDeploy)
{
    $deployScript = Join-Path -Path $packagesFolder -ChildPath "Plugins\AxReportVmRoleStartupTask\DeployAllReportsToSsrs.ps1"
    # TODO Re-enable once SSRS can run on the image
    #& $deployScript -PackageInstallLocation ($packagesFolder)
}