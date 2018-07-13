# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
Param(
    [string]$packagePath,
    [string]$tempFolder = "C:\Temp",
    [switch]$dontSkipBackup
)
$ErrorActionPreference = 'Stop'

$package = Get-ChildItem -Path $packagePath
[string]$packageTempDirectory = Join-Path -Path $tempFolder -ChildPath ($package.Basename)
if (Test-Path -Path $packageTempDirectory) # If the folder already exists, clean it up
{
    Write-Verbose "Removing old $($package.Basename)"
    Remove-Item -Path $packageTempDirectory -Recurse -Force
}

Write-Verbose "Starting extraction of $($package.FullName)"
& C:\DynamicsTools\7za.exe x $package.FullName -o"$($packageTempDirectory)" -r
cd $packageTempDirectory


# Grab the default topology and update it
[xml]$topology = Get-Content (Join-Path -Path $packageTempDirectory -ChildPath "DefaultTopologyData.xml")
$services = .\AXUpdateInstaller.exe list | select-string "Version: " | % { [string]$line = $_; "<string>$($line.Split("`t")[0])</string>" }
$topology.TopologyData.MachineList.Machine.ServiceModelList.InnerXml = [System.String]::Join("`n", $services)
$topology.Save("$packageTempDirectory\CurrentTopology.xml")


# If the server is in some intermediate state, wait for it to finish
$batch = Get-Service DynamicsAXBatch
while (([string]$batch.Status).Contains("Pending"))
{
    Write-Verbose "Waiting for batch..."
    Start-Sleep -Seconds 5
    $batch = Get-Service DynamicsAXBatch
}

Write-Verbose "Starting dev install of $($package.Basename)"

# Generate a runbook for our current topology
$runbookName = "UPDATE$(New-Guid)"
.\AXUpdateInstaller.exe generate -runbookid="$runbookName" -topologyfile="$packageTempDirectory\CurrentTopology.xml" -servicemodelfile="$packageTempDirectory\DefaultServiceModelData.xml" -runbookfile="$packageTempDirectory\$runbookName.xml"

# Import the new runbook into the update installer
.\AXUpdateInstaller.exe import -runbookfile="$packageTempDirectory\$runbookName.xml"

# Execute the runbook
if (!$dontSkipBackup)
{
    .\AXUpdateInstaller.exe execute -runbookid="$runbookName" -backup="False"
}
else
{
    .\AXUpdateInstaller.exe execute -runbookid="$runbookName"
}

# Export the result
.\AxUpdateInstaller.exe export -runbookid="$runbookName" -runbookfile="$packageTempDirectory\$runbookName.xml"

[xml]$runbook = Get-Content "$packageTempDirectory\$runbookName.xml"
$notCompletedStep = $runbook.SelectNodes("/RunbookData/RunbookStepList/Step[not(StepState='Completed')][1]")

if ($notCompletedStep -and ($notCompletedStep.StepState -eq "Failed"))
{
    throw "Not completed step $($notCompletedStep.ID) ($($notCompletedStep.Description)) is in state $($notCompletedStep.StepState)"
}