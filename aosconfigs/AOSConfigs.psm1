# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Set-ConfigKeyValue([xml]$xml, [string]$key, [string]$value, [bool]$create = $True)
{
    Write-Verbose ("Updating $key with $value")
    try
    {
        $node = $xml.configuration.appSettings.SelectSingleNode("add[@key='$key']")
        $node.value = $value
    }
    catch
    {
        if ($create)
        {
            Write-Verbose ("- Created $key")
            $node = $xml.CreateElement("add")
            $attr = $xml.CreateAttribute("key")
            $attr.Value = $key
            $node.Attributes.Append($attr) | Out-Null
            $attr = $xml.CreateAttribute("value")
            $attr.Value = $value
            $node.Attributes.Append($attr) | Out-Null
            $xml.configuration.appSettings.AppendChild($node) | Out-Null
        }
        else
        {
            Write-Verbose ("- Couldn't find $key")
        }
    }
}

function Get-ConfigKeyValue([xml]$xml, [string]$key)
{
    $node = $xml.configuration.appSettings.SelectSingleNode("add[@key='$key']")
    if ($node)
    {
        return $node.value
    }

    return ""
}

function Add-ConfigKeyValue([xml]$xml, [string]$key, [string]$value, [bool]$create = $True, [string]$replaceValue = "")
{
    [string]$existingValue = Get-ConfigKeyValue $xml $key
    if ($existingValue -and !($existingValue -like "*placeholder*"))
    {
        if ($existingValue -like "*$replaceValue*")
        {
            $value = $existingValue.Replace($replaceValue, $value)
            Set-ConfigKeyValue $xml $key $value $create
        }
        elseif (!($existingValue -like "*$value*"))
        {
            $value = "$value;$existingvalue"
            Set-ConfigKeyValue $xml $key $value $create
        }
    }
    else
    {
        Set-ConfigKeyValue $xml $key $value $create
    }
}

function Get-AuthorityKeys([xml]$wifconfig)
{
    $authorityKeys = $wifconfig.SelectSingleNode("//authority[@name = 'https://fakeacs.accesscontrol.windows.net/']/child::keys")
    if (!$authorityKeys)
    {
        $authoritynode = $wifconfig.CreateElement("authority")
        $authorityKeys = $wifconfig.CreateElement("keys")
        $authoritynode.AppendChild($authorityKeys) | Out-Null
        $validIssuers = $wifconfig.CreateElement("validIssuers")
        $authoritynode.AppendChild($validIssuers) | Out-Null
        $add = $wifconfig.CreateElement("add")
        $attr = $wifconfig.CreateAttribute("name")
        $attr.Value = "https://fakeacs.accesscontrol.windows.net/"
        $add.Attributes.Append($attr) | Out-Null
        $validIssuers.AppendChild($add) | Out-Null
        $attr = $wifconfig.CreateAttribute("name")
        $attr.Value = "https://fakeacs.accesscontrol.windows.net/"
        $authoritynode.Attributes.Append($attr) | Out-Null
        $wifconfig.'system.identityModel'.identityConfiguration.securityTokenHandlers.securityTokenHandlerConfiguration.issuerNameRegistry.AppendChild($authoritynode)
    }

    return $authorityKeys
}

<#
 .Synopsis
  Adds a certificate thumbprint to the trusted thumbprints.

 .Description
  Adds or replaces a thumbprint in the listed of trusted certificates in web.config and wif.config.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifConfig
  An XML object representing the wif.config.

 .Parameter NewThumbprint
  The thumbprint of the certificate to add to the trusted list.

 .Parameter OriginalThumbprint
  Optional parameter to indicate the certificate thumbprint that should be replaced.
#>
function Set-TrustedThumbprints([xml]$WebConfig, [xml]$WifConfig, [string]$NewThumbprint, [string]$OriginalThumbprint = "")
{
    Add-ConfigKeyValue $WebConfig "Infrastructure.InternalServiceCertificateThumbprints" $NewThumbprint -replaceValue $OriginalThumbprint
    Add-ConfigKeyValue $WebConfig "Infrastructure.TrustedCertificates" $NewThumbprint -replaceValue $OriginalThumbprint

    $authoritykeys = Get-AuthorityKeys $WifConfig
    if ($OriginalThumbprint)
    {
        $thumbprintNode = $authoritykeys.SelectNodes("//add[@thumbprint = '$OriginalThumbprint']")
    }
    if ($thumbprintNode -and ($thumbprintNode.Count -gt 0))
    {
        foreach($node in $thumbprintNode)
        {
            $node.Attributes["thumbprint"].'#text' = $NewThumbprint
        }
    }
    else
    {
        $thumbprintNode = $authoritykeys.SelectNodes("//add[@thumbprint = '$NewThumbprint']")
        if ($thumbprintNode.Count -eq 0)
        {
            $key = $WifConfig.CreateElement("add")
            $attr = $WifConfig.CreateAttribute("thumbprint")
            $attr.Value = $NewThumbprint.ToString()
            $key.Attributes.Append($attr) | Out-Null
            $authoritykeys.AppendChild($key) | Out-Null
        }
    }
}

<#
 .Synopsis
  Changes the tenant of the AOS based on an AAD email.

 .Description
  Looks up the AAD tenant information based on the email, and changes the tenant
  and admin principal settings of the AOS.
  Note that this does not set the admin for the AOS in the database.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifServicesConfig
  An XML object representing the wif.services.config.

 .Parameter AdminPrincipal
  An email address representing the admin principal and tenant.

 .Example
  Set-AOSTenant -WebConfig $webconfigXML -WifServicesConfig $wifservicesconfigXML -AdminPrincipal joe@contoso.com
#>
function Set-AOSTenant
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.services.config file of the AOS")]
        [xml]$WifServicesConfig,

        [Parameter(Mandatory=$True, HelpMessage="The email address of the user to make admin principal, using the domain to use as the tenant")]
        [string]$AdminPrincipal
    )

    $tenantDomain = $AdminPrincipal.Split("@")[1]

    Write-Verbose ("Setting new tenant and admin info: $tenantDomain ($AdminPrincipal)")

    [xml]$tenant = (Invoke-WebRequest -UseBasicParsing "https://login.windows.net/$tenantDomain/federationmetadata/2007-06/federationmetadata.xml").content.Substring(1)
    [string]$tenantGuid = $tenant.EntityDescriptor.entityID.Substring(24)
    if ($tenantGuid.Substring($tenantGuid.Length-1) -eq "/")
    {
        $tenantGuid = $tenantGuid.Substring(0, $tenantGuid.Length-1)
    }

    Set-ConfigKeyValue $WebConfig "Aad.AADTenantId" $tenantDomain
    Set-ConfigKeyValue $WebConfig "Aad.TenantDomainGUID" $tenantGuid
    Set-ConfigKeyValue $WebConfig "Provisioning.AdminPrincipalName" $AdminPrincipal
    $WifServicesConfig.'system.identityModel.services'.federationConfiguration.wsFederation.Attributes["issuer"].'#text' = "https://login.windows.net/$tenantDomain/wsfed"
    Set-ConfigKeyValue $WebConfig "Provisioning.AdminIdentityProvider" "https://sts.windows.net/"
    Set-ConfigKeyValue $WebConfig "Aad.AADMetadataLocationFormat" "https://login.windows.net/{0}/FederationMetadata/2007-06/FederationMetadata.xml"
    Set-ConfigKeyValue $WebConfig "Aad.AADLoginWsfedEndpointFormat" "https://login.windows.net/{0}/wsfed"
    Set-ConfigKeyValue $WebConfig "Aad.AADIssuerNameFormat" "https://sts.windows.net/{0}/"
    Set-ConfigKeyValue $WebConfig "FederationMetadataLocation" "https://login.windows.net/common/FederationMetadata/2007-06/FederationMetadata.xml"
    Set-ConfigKeyValue $WebConfig "Aad.ACSServiceEndpoint" "https://accounts.accesscontrol.windows.net/tokens/OAuth/2"
}

<#
 .Synopsis
  Sets the path to the packages and metadata locations.

 .Description
  Changes the web.config settings for packages, metadata and binary folders.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter PackagesFolder
  The absolute path to the Packages folder.
#>
function Set-AOSPackagePaths
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="The absolute path to the Packages folder")]
        [string]$PackagesFolder
    )

    Write-Verbose ("Setting new packages folder: $PackagesFolder")
    Set-ConfigKeyValue $WebConfig "Aos.MetadataDirectory" $PackagesFolder
    Set-ConfigKeyValue $WebConfig "Aos.PackageDirectory" $PackagesFolder
    Set-ConfigKeyValue $WebConfig "bindir" $PackagesFolder
    Set-ConfigKeyValue $WebConfig "Common.BinDir" $PackagesFolder
    Set-ConfigKeyValue $WebConfig "Common.DevToolsBinDir" "$PackagesFolder\bin"
    Set-ConfigKeyValue $WebConfig "Microsoft.Dynamics.AX.AosConfig.AzureConfig.bindir" $PackagesFolder
}

<#
 .Synopsis
  Sets the path to the webroot.

 .Description
  Changes the web.config settings for webroot and flighting if available.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WebRoot
  The absolute path to the webroot.
#>
function Set-AOSWebrootPath
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="The absolute path to the webroot folder")]
        [string]$WebRoot
    )

    Write-Verbose ("Setting new tenant and admin info: $WebRoot")

    Set-ConfigKeyValue $WebConfig "DataAccess.FlightingCachePath" "$WebRoot\CarbonRuntimeBackup" $False
    Set-ConfigKeyValue $WebConfig "Aos.AppRoot" $WebRoot
    Set-ConfigKeyValue $WebConfig "Infrastructure.WebRoot" $WebRoot
}

<#
 .Synopsis
  Sets the database connection configurations.

 .Description
  Changes the web.config settings for database server, database name and username and password.
  Note that only each setting is optional, and only specified settings will be updated in the config.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter DatabaseName
  The name of the business database on the server.

 .Parameter DatabaseServer
  The name of the server or the FQDN for the server to connect to.

 .Parameter DatabaseUser
  The username to connect to the server.

 .Parameter DatabasePassword
  A securestring object containing the password for the username to connect to the server.
#>
function Set-AOSDatabaseConnection
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$False, HelpMessage="The name of the database")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$False, HelpMessage="The name of the database server (or FQDN)")]
        [string]$DatabaseServer,

        [Parameter(Mandatory=$False, HelpMessage="The username for the database")]
        [string]$DatabaseUser,

        [Parameter(Mandatory=$False, HelpMessage="The password for the database user")]
        [SecureString]$DatabasePassword
    )

    if ($DatabaseName)
    {
        Write-Verbose ("Setting new database: $DatabaseName")
        Set-ConfigKeyValue $WebConfig "DataAccess.Database" $DatabaseName
    }
    if ($DatabaseServer)
    {
        Write-Verbose ("Setting new database server: $DatabaseServer")
        Set-ConfigKeyValue $WebConfig "DataAccess.DbServer" $DatabaseServer
        Set-ConfigKeyValue $WebConfig "DataAccess.ReadOnlySecondaryDbServers" $DatabaseServer
    }
    if ($DatabasePassword)
    {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DatabasePassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        Write-Verbose ("Setting new database password")
        Set-ConfigKeyValue $WebConfig "DataAccess.SqlPwd" $password
        Set-ConfigKeyValue $WebConfig "DataAccess.AxAdminSqlPwd" $password
    }
    if ($DatabaseUser)
    {
        Write-Verbose ("Setting new database user: $DatabaseUser")
        Set-ConfigKeyValue $WebConfig "DataAccess.SqlUser" $DatabaseUser
        Set-ConfigKeyValue $WebConfig "DataAccess.AxAdminSqlUser" $DatabaseUser
    }
    # Set-ConfigKeyValue $webconfig "BiReporting.DW" ""
    # Set-ConfigKeyValue $webconfig "BiReporting.DWPwd" ""
    # Set-ConfigKeyValue $webconfig "BiReporting.DWRuntimePwd" ""
    # Set-ConfigKeyValue $webconfig "BiReporting.DWRuntimeUser" ""
    # Set-ConfigKeyValue $webconfig "BiReporting.DWServer" ""
    # Set-ConfigKeyValue $webconfig "BiReporting.DWUser" ""
}

<#
 .Synopsis
  Sets the hostname.

 .Description
  Changes the web.config settings for hostname and persistent machine address.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter HostName
  The name of the business database on the server.

 .Example
  Set-AOSHostName -WebConfig webconfigXML -HostName $env:COMPUTERNAME
#>
function Set-AOSHostName
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="The hostname of the AOS instance")]
        [string]$HostName
    )

    Write-Verbose ("Setting new host name: $HostName")

    Set-ConfigKeyValue $WebConfig "Infrastructure.HostedServiceName" $HostName
    Set-ConfigKeyValue $WebConfig "Infrastructure.PersistentVirtualMachineIPAddress" $HostName
    Set-ConfigKeyValue $WebConfig "PersistentVirtualMachineIPAddress" $HostName
}

<#
 .Synopsis
  Sets the AOS URL.

 .Description
  Changes the web.config and wif.services.config settings indicating the URL for the AOS.
  Note that this does not update IIS settings, which should be updated using the Set-IISBinding cmdlet.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifServicesConfig
  An XML object representing the wif.services.config.

 .Parameter URL
  The URL for the instance.

 .Parameter SoapURL
  An optional separate URL for SOAP.

 .Example
  Set-AOSURL -WebConfig webconfigXML -WifServicesConfig wifservicesconfigXML -URL myaos.centralus.cloudapp.azure.com
#>
function Set-AOSURL
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.services.config file of the AOS")]
        [xml]$WifServicesConfig,

        [Parameter(Mandatory=$True, HelpMessage="The full URL for the AOS, as the fully-qualified domain name that will be used")]
        [string]$URL,

        [Parameter(Mandatory=$False, HelpMessage="The SOAP URL for the AOS, if different from URL.")]
        [string]$SoapURL
    )

    Write-Verbose ("Setting new URL: $URL")

    $fqdn = $URL.Replace("https://","")
    $fqdn = $URL.Replace("http://","")
    $toplevelDomain = $fqdn.SubString($fqdn.SubString(0, $fqdn.LastIndexOf(".")).LastIndexOf(".") + 1)

    if ($SoapURL)
    {
        $soapfqdn = $SoapURL.Replace("https://","")
        $soapfqdn = $SoapURL.Replace("http://","")
    }
    else
    {
        $soapfqdn = $fqdn
    }
    
    Set-ConfigKeyValue $WebConfig "Infrastructure.EnvironmentDomainName" $toplevelDomain
    Set-ConfigKeyValue $WebConfig "Infrastructure.FullyQualifiedDomainName" $fqdn
    Set-ConfigKeyValue $WebConfig "Infrastructure.HostName" $fqdn
    Set-ConfigKeyValue $WebConfig "Infrastructure.HostUrl" "https://$fqdn/"
    Set-ConfigKeyValue $WebConfig "Infrastructure.SoapServicesUrl" "https://$soapfqdn/"
    
    #Set-ConfigKeyValue $WebConfig "SecurityTokenValidatedRedirectOverride" "https://$fqdn"
    $WifServicesConfig.'system.identityModel.services'.federationConfiguration.wsFederation.Attributes["reply"].'#text' = "https://$fqdn/"
    $WifServicesConfig.'system.identityModel.services'.federationConfiguration.cookieHandler.Attributes["domain"].'#text' = $fqdn
}

<#
 .Synopsis
  Sets the App ID to be used for the AOS.

 .Description
  Changes the web.config, wif.config and wif.services.config settings to use a different App ID for authentication.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifServicesConfig
  An XML object representing the wif.services.config.

 .Parameter WifConfig
  An XML object representing the wif.config. 

 .Parameter AppID
  The App ID GUID to be used for the AOS.
#>
function Set-AOSAppId
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.services.config file of the AOS")]
        [xml]$WifServicesConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.config file of the AOS")]
        [xml]$WifConfig,

        [Parameter(Mandatory=$True, HelpMessage="The GUID of the registered Application ID in Azure Active Directory to use for the AOS")]
        [GUID]$AppID
    )

    Write-Verbose ("Setting new app ID: $($AppID.ToString())")

    $appIDSPN = "spn:$($AppID.ToString())"
    $WifConfig.'system.identityModel'.identityConfiguration.securityTokenHandlers.securityTokenHandlerConfiguration.audienceUris.add.Attributes['value'].'#text' = $appIDSPN
    $WifServicesConfig.'system.identityModel.services'.federationConfiguration.wsFederation.Attributes['realm'].'#text' = $appIDSPN
    Set-ConfigKeyValue $WebConfig "Aad.Realm" $appIDSPN
}

<#
 .Synopsis
  Sets the certificate to be used for the AOS session authentication.

 .Description
  Changes the web.config, wif.config and wif.services.config settings to use a different certificate for session authentication.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifServicesConfig
  An XML object representing the wif.services.config.

 .Parameter WifConfig
  An XML object representing the wif.config. 

 .Parameter SessionAuthThumbprint
  The thumbprint of the certificate to be used.
#>
function Set-AOSSessionAuthCert
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.services.config file of the AOS")]
        [xml]$WifServicesConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.config file of the AOS")]
        [xml]$WifConfig,

        [Parameter(Mandatory=$True, HelpMessage="The thumbprint of the Session Authentication Certificate to be used by the AOS")]
        [string]$SessionAuthThumbprint
    )

    Write-Verbose ("Setting new session authorization key: $SessionAuthThumbprint")

    $originalThumbprint = Get-ConfigKeyValue $WebConfig "Infrastructure.SessionAuthenticationCertificateThumbprint"
    Set-ConfigKeyValue $WebConfig "Infrastructure.SessionAuthenticationCertificateThumbprint" $SessionAuthThumbprint
    $WifServicesConfig.'system.identityModel.services'.federationConfiguration.serviceCertificate.certificateReference.Attributes["findValue"].'#text' = $SessionAuthThumbprint
    $nodes = $WebConfig.configuration.SelectNodes("location/system.serviceModel/behaviors/serviceBehaviors/behavior/serviceCredentials/serviceCertificate")
    foreach($node in $nodes)
    {
        $node.Attributes["findValue"].'#text' = $SessionAuthThumbprint
    }

    Set-TrustedThumbprints $WebConfig $WifConfig $SessionAuthThumbprint $originalThumbprint
}

<#
 .Synopsis
  Sets the certificate to be used for the AOS data encryption.

 .Description
  Changes the web.config and wif.config settings to use a different certificate for data encryption.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifConfig
  An XML object representing the wif.config. 

 .Parameter DataEncryptionThumbprint
  The thumbprint of the certificate to be used.
#>
function Set-AOSDataEncryptionCert
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.config file of the AOS")]
        [xml]$WifConfig,

        [Parameter(Mandatory=$True, HelpMessage="The thumbprint of the Data Encryption Certificate to be used by the AOS")]
        [string]$DataEncryptionThumbprint
    )

    Write-Verbose ("Setting new data encryption key: $DataEncryptionThumbprint")

    $originalThumbprint = Get-ConfigKeyValue $WebConfig "DataAccess.DataEncryptionCertificateThumbprint"
    Set-ConfigKeyValue $WebConfig "DataAccess.DataEncryptionCertificateThumbprint" $DataEncryptionThumbprint
    Set-ConfigKeyValue $WebConfig "DataAccess.DataEncryptionCertificateThumbprintLegacy" $DataEncryptionThumbprint

    Set-TrustedThumbprints $WebConfig $WifConfig $DataEncryptionThumbprint $originalThumbprint
}

<#
 .Synopsis
  Sets the certificate to be used for the AOS data signing.

 .Description
  Changes the web.config and wif.config settings to use a different certificate for data signing.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifConfig
  An XML object representing the wif.config. 

 .Parameter DataSigningThumbprint
  The thumbprint of the certificate to be used.
#>
function Set-AOSDataSigningCert
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.config file of the AOS")]
        [xml]$WifConfig,

        [Parameter(Mandatory=$True, HelpMessage="The thumbprint of the Data Signing Certificate to be used by the AOS")]
        [string]$DataSigningThumbprint
    )

    Write-Verbose ("Setting new data signing key: $DataSigningThumbprint")

    $originalThumbprint = Get-ConfigKeyValue $WebConfig "DataAccess.DataSigningCertificateThumbprint"
    Set-ConfigKeyValue $WebConfig "DataAccess.DataSigningCertificateThumbprint" $DataSigningThumbprint
    Set-ConfigKeyValue $WebConfig "DataAccess.DataSigningCertificateThumbprintLegacy" $DataSigningThumbprint

    Set-TrustedThumbprints $WebConfig $WifConfig $DataSigningThumbprint $originalThumbprint
}

<#
 .Synopsis
  Sets the certificate to be used for SSL.

 .Description
  Changes the web.config and wif.config settings to use a different certificate for SSL.
  Note that this not change the IIS binding. Use the Set-IISBinding cmdlet.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter WifConfig
  An XML object representing the wif.config. 

 .Parameter SSLThumbprint
  The thumbprint of the certificate to be used.
#>
function Set-AOSSSLCert
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the wif.config file of the AOS")]
        [xml]$WifConfig,

        [Parameter(Mandatory=$True, HelpMessage="The thumbprint of the SSL Certificate to be used by the AOS")]
        [string]$SSLThumbprint
    )

    Write-Verbose ("Setting new SSL key: $SSLThumbprint")

    $originalThumbprint = Get-ConfigKeyValue $WebConfig "Infrastructure.CsuClientCertThumbprint"
    $wifconfig.'system.identityModel'.identityConfiguration.securityTokenHandlers.securityTokenHandlerConfiguration.issuerNameRegistry.authority[0].keys.add.Attributes['thumbprint'].'#text' = $SSLThumbprint
    Set-ConfigKeyValue $WebConfig "Infrastructure.CsuClientCertThumbprint" $SSLThumbprint

    Set-TrustedThumbprints $WebConfig $WifConfig $SSLThumbprint $originalThumbprint
}

<#
 .Synopsis
  Creates a new self-signed certificate and grants access.

 .Description
  Creates a new self-signed certificate using RSA/AES with a key length of 2048, and gives the specified
  user group or user access to the certificate.
  The cmdlet returns the actual certificate object.

 .Parameter UserOrGroup
  The name of a user group or user to grant access to the new cert.

 .Parameter CertName
  A new DNS name for the cert. 
#>
function New-Cert
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="The name of a user or user group to grant access to the new certificate")]
        [string]$UserOrGroup = "NETWORK SERVICE",

        [Parameter(Mandatory=$True, HelpMessage="The 'dns name' to give to the new certificate")]
        [string]$CertName
    )

    Write-Verbose ("Creating new certificate: $CertName")

    $permission = @($UserOrGroup,"Read,FullControl","Allow")
    $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission

    $cert = New-SelfSignedCertificate -CertStoreLocation "cert:\LocalMachine\My"  -DnsName $CertName -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -KeyLength 2048
    $keyFullPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\" + $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $acl = Get-Acl -Path $keyFullPath
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $keyFullPath -AclObject $acl

    return $cert
}

<#
 .Synopsis
  Updates or create an IIS binding.

 .Description
  Updates or creates an IIS binding for a given URL and port, and assigns the cert hash to be used for SSL.

 .Parameter FQDN
  The URL to set the binding for.

 .Parameter CertHash
  The hash of the certificate to be used on the binding. 

 .Parameter SiteName
  Optional name of the IIS site the binding should be set on. Default is "AOSService"

 .Parameter Port
  Optional port number to be used. Default is "443"

 .Example
  Set-IISBinding -FQDN myaos.centralus.cloudapp.azure.com -CertHash ((New-Cert -CertName "myaos.centralus.cloudapp.azure.com").GetCertHash())
#>
function Set-IISBinding
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="The fully qualified domain name for the IIS binding")]
        [string]$FQDN,

        [Parameter(Mandatory=$True, HelpMessage="The object containing the certificate hash to use for SSL")]
        $CertHash,

        [Parameter(Mandatory=$False, HelpMessage="The name of the IIS site to add/update the binding for")]
        [string]$SiteName = "AOSService",

        [Parameter(Mandatory=$False, HelpMessage="The port number to use for the URL")]
        [string]$Port = "443"
    )

    $FQDN = $FQDN.Replace("https://","")
    $FQDN = $FQDN.Replace("http://","")
    $bindingURL = "*:$($Port):$FQDN"

    Write-Verbose ("Setting new IIS binding: $bindingURL")

    Start-IISCommitDelay
    $site = Get-IISSite -Name $SiteName
    $binding = $site.Bindings | Where-Object { $_.bindingInformation -eq $bindingURL }
    if ($binding.Count -eq 0)
    {
        $site.Bindings.Add($bindingURL, $CertHash, "My", "0")
    }
    else
    {
        $binding.CertificateHash = $CertHash
    }
    Stop-IISCommitDelay -Commit $True
}

<#
 .Synopsis
  Sets the SSRS URL to use.

 .Description
  Changes the web.config settings to use a different SSRS URL.

 .Parameter WebConfig
  An XML object representing the web.config.

 .Parameter ServerURL
  The URL, IP or computername for SSRS. 
#>
function Set-SSRSServer
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="An XML object representing the web.config file of the AOS")]
        [xml]$WebConfig,

        [Parameter(Mandatory=$True, HelpMessage="The FQDN, IP or ComputerName of the SSRS Server")]
        [string]$ServerURL
    )

    Write-Verbose ("Setting new SSRS serverURL: $ServerURL")

    Set-ConfigKeyValue $webconfig "PersistentVirtualMachineIPAddressSSRS" $ServerURL
    Set-ConfigKeyValue $webconfig "BiReporting.PersistentVirtualMachineIPAddressSSRS" $ServerURL
}

Export-ModuleMember -Function Set-AOSTenant, Set-AOSPackagePaths, Set-AOSWebrootPath, Set-AOSDatabaseConnection, Set-AOSHostName, Set-AOSURL, Set-AOSAppId, Set-AOSSessionAuthCert, Set-AOSDataEncryptionCert, Set-AOSDataSigningCert, Set-AOSSSLCert, New-Cert, Set-IISBinding