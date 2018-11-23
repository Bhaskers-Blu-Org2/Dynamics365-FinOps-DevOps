# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
Param(
    [string]$adminEmail,
    [string]$FQDN,
    [string]$appId,
    [string]$databasePassword,
    [string]$configsPath = "C:\AOSService\Webroot",
    [string]$packagesFolder = "C:\AosService\PackagesLocalDirectory",
    [string]$AOSConfigModulePath = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

Import-Module (Join-Path -Path $AOSConfigModulePath -ChildPath "AOSConfigs.psm1")

Stop-Service DynamicsAXBatch

# Backup and read config files
$webconfigPath = Join-Path -Path $configsPath "web.config"
Copy-Item $webconfigPath "$webconfigPath.bak"
[xml]$webconfig = Get-Content $webconfigPath

$wifservicesconfigPath = Join-Path -Path $configsPath "wif.services.config"
Copy-Item $wifservicesconfigPath "$wifservicesconfigPath.bak"
[xml]$wifservicesconfig = Get-Content $wifservicesconfigPath

$wifconfigPath = Join-Path -Path $configsPath "wif.config"
Copy-Item $wifconfigPath "$wifconfigPath.bak"
[xml]$wifconfig = Get-Content $wifconfigPath


# Fix SQL for Machine Rename
Invoke-Sqlcmd -Query "USE [master]; DECLARE @server varchar(30); SELECT @server = name from sys.servers; EXEC sp_dropserver @server; EXEC sp_addserver '$($env:COMPUTERNAME)', local;"
Restart-Service MSSQLSERVER
if ($databasePassword)
{
    Invoke-Sqlcmd -Query "ALTER LOGIN axdbadmin WITH PASSWORD = '$databasePassword';"
}

# *** TENANT and ADMIN
Set-AOSTenant -WebConfig $webconfig -WifServicesConfig $wifservicesconfig -AdminPrincipal $adminEmail

# *** DATABASE ACCESS
Set-AOSDatabaseConnection -WebConfig $webconfig -DatabasePassword ($DatabasePassword | ConvertTo-SecureString -AsPlainText -Force)

# *** URL and HostName
Set-AOSHostName -WebConfig $webconfig -HostName $env:COMPUTERNAME
Set-AOSURL -WebConfig $webconfig -WifServicesConfig $wifservicesconfig -URL $FQDN
$cert = New-Cert -CertName $FQDN
$certHash = $cert.GetCertHash()
$SSLThumbprint = $cert.Thumbprint
Set-AOSSSLCert -WebConfig $webconfig -WifConfig $wifconfig -SSLThumbprint ($SSLThumbprint.ToString())
Set-IISBinding -FQDN $FQDN -CertHash $certHash

# *** APPID for AAD
Set-AOSAppId -WebConfig $webconfig -WifServicesConfig $wifservicesconfig -WifConfig $wifconfig -AppID $appId

# *** CERTIFICATES
[string]$sessionAuth = (New-Cert -CertName "SessionAuthentication").Thumbprint
[string]$dataEncryption = (New-Cert -CertName "DataEncryption").Thumbprint
[string]$dataSigning = (New-Cert -CertName "DataSigning").Thumbprint
Set-AOSSessionAuthCert -WebConfig $webconfig -WifConfig $wifconfig -WifServicesConfig $wifservicesconfig -SessionAuthThumbprint $sessionAuth
Set-AOSDataEncryptionCert -WebConfig $webconfig -WifConfig $wifconfig -DataEncryptionThumbprint $dataEncryption
Set-AOSDataSigningCert -WebConfig $webconfig -WifConfig $wifconfig -DataSigningThumbprint $dataSigning

# *** Save all the config changes
$webconfig.Save($webconfigPath)
$wifservicesconfig.Save($wifservicesconfigPath)
$wifconfig.Save($wifconfigPath)

# *** Run the admin provisioning
Start-Process -FilePath (Join-Path -Path $packagesFolder "bin\AdminUserProvisioning.exe") -ArgumentList "-networkalias $adminEmail" -WorkingDirectory "$packagesFolder\bin" -Wait


Restart-Service W3SVC
Start-Service DynamicsAXBatch