# Create Asure Stack Development Kit in a Hyper-V VM
<#
.Synopsis
   Script to Create ASDK Hyper-V VM
   Copyright 2018 by Carsten Rachfahl Rachfahl IT-Solutions GmbH & Co.KG
   Version 1.8
   1.0 06.04.2018 cr First draft
   1.1 08.04.2018 cr Added DNSServerIP, NTPServerIP and IPSubnetMask parameter
   1.2 20.04.2018 cr Added VMGWIP parameter
   1.3 03.05.2018 bf Mask Password
   1.4 17.05.2018 cr Add Installation of PowerShell for Azure Stack & Download ConfigASDK.ps1
   1.5 23.05.2018 cr Automatic start of ConfigASDK.ps1
   1.6 20.10.2018 cr Creation of Drive D
   1.7 23.10.2018 cr Added Azure Subscription ID to process
   1.8 02.11.2018 cr Added Windows 10 Hyper-V suport (less Memory, Checkpoint setings)

.DESCRIPTION
   Script creates a Hyper-V VM that is capable to host an Azure Stack Development Kit Installation
.EXAMPLE
   Create-ASDKVM.ps1 -VMName "AST1804-02" -VMPath "\\DellSOFS\Share1" -VMIP 172.16.0.2 -BGPNatIP 172.16.0.3 -VMGWIP 172.16.0.1 -IPSubnetMask 24 -DNSServerIP 192.168.57.3 -NTPServerIP 192.168.57.254 -CloudBuilderDisk "C:\ClusterStorage\COLLECT\Azure Stack Dev Kit\CloudBuilder.vhdx" -LocalAdminPassword Password! -$AzureTenantAdminName admin@RITSASTPoC.onmicrosoft.com -$AzureTenantAdminPassord Password! -MemoryinGB 128 -Cores 12
.EXAMPLE
#>

#region Parameter
[CmdletBinding()]
Param
(
    # VMName
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [String]$VMName,

    # VMPath
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=1)]
    [String]$VMPath,

    # VMIP
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=2)]
    [String]$VMIP,

    # BGPNatIP
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=3)]
    [String]$BGPNatIP,

    # VMGWIP
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=4)]
    [String]$VMGWIP,

    # IPSubnetMask
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=5)]
               [ValidateRange(8,32)]
    [int]$IPSubnetMask,    

    # DNSServerIP
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=6)]
    [String]$DNSServerIP,

    # NTPServerIP
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=7)]
    [String]$NTPServerIP,

    # CloudBuilderDisk
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=8)]
    [String]$CloudBuilderDisk,

    # LocalAdminPassword
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=9)]
    [String]$LocalAdminPassword,

    # AzureTenantAdminName
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=10)]
    [String]$AzureTenantAdminName,

    # AzureTenantAdminPassword
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=11)]
    [String]$AzureTenantAdminPassword,

    #$AzureTenantSubcriptionID
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=12)]
    [String]$AzureTenantSubcriptionID,

    # $MemoryinGB
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=13)]
    [ValidateRange(96,512)]
    [int]$MemoryinGB = 115,

    # Cores
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=14)]
    [ValidateRange(12,32)]
    [int]$Cores = 12
)
#endregion

Get-Date

#Calculate IP Address
function Calc-IPAddress {
  param
  (
    [string]
    $IPAddrStr,

    [string]
    $IP
  )

  $NewIPAddrStr = $IPAddrStr.Split('.')[0]
  $NewIPAddrStr = $NewIPAddrStr + '.' + $IPAddrStr.Split('.')[1]
  $NewIPAddrStr = $NewIPAddrStr + '.' + $IPAddrStr.Split('.')[2]
  $LastOctet = [int]$IPAddrStr.Split('.')[3]
  $NewIP = $LastOctet + [int]$IP
  $NewIPAddrStr = $NewIPAddrStr + '.' + [String]$NewIP
  return $NewIPAddrStr
}
#endregion

#region Variables
$localAdmin = 'Administrator'
$localAdminPWord = ConvertTo-SecureString –String "$LocalAdminPassword" –AsPlainText -Force
$localAdminCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $localAdmin, $LocalAdminPWord

# Path
$ConfigDirName = 'AdditionalSoftware'
#$AditionalSoftwareDir = 'C:\ClusterStorage\COLLECT\AzureStack DevKit\' + $ConfigDirName
$AditionalSoftwareDir = 'C:\Projekte\Azure Stack Dev Kit\' + $ConfigDirName
$DDriveName = 'DDrive'
$DDriveSize = 50GB

#VM releated
$HVSWitch = 'NATSwitch'
$IPSubNetNAT = $($VMIP.Substring(0,$VMIP.LastIndexOf('.')+1)+'0/'+[String]$IPSubnetMask)
$DefaultGatewayIP = $VMGWIP
$VMGeneration = 2
$VMMemory = $MemoryinGB * 1GB
$vmProcCount  = $Cores
$VDiskNumber = 4
$CloudBuilderDiskSize = 200GB
$VDiskSize = 200GB
#endregion

#region Unattend.xml Handling
$ComputerName = '*'
$Organization = 'PowerKurs'
$Owner = 'PowerKurs'
$Timezone = 'Pacific Standard Time'
$InputLocale = 'en-US'
$SystemLocale = 'en-US'
$UserLocale = 'en-US'
$adminPassword = "$LocalAdminPassword"
$WindowsKey = 'CB7KF-BWN84-R7R2Y-793K2-8XDDG'


#Operation System
$OSType = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name InstallationType).InstallationType
$OSBuild = [environment]::OSVersion.Version.Build
if($OSType -eq "Server") {
    if(($OSBuild -ge 17763)) {
        Write-Verbose "Running on Windows Server 2019"
        $OSString = "Server2019"
    } elseif ($OSBuild -ge 14393) {
        Write-Verbose "Running on Windows Server 2016"
        $OSString = "Server2016"        
    } else {
        Write-Error "Script needs at least Windows Server 2016 to execute"
        break 
    }
} elseif ($OSType -eq "Client") {
    if(($OSBuild -ge 14393)) {
        Write-Verbose "Running on Windows 10"
        $OSString = "Client10"  
    } else {
        Write-Verbose "Running not on Windows 10"
        Write-Error "Script needs at least Windows 10 to execute"
        break 
    }
} 

### Sysprep unattend XML
$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <ProductKey>Key</ProductKey> 
            <RegisteredOrganization>Organization</RegisteredOrganization>
            <RegisteredOwner>Owner</RegisteredOwner>
            <TimeZone>TZ</TimeZone>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>password</Value>
                    <PlainText>True</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-us</InputLocale>
            <SystemLocale>en-us</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>en-us</UserLocale>
        </component>
    </settings>
</unattend>
"@
#endregion


#region Helper function for no error file cleanup

#Cleanup File
function cleanupFile
{
  param
  (
    [string] $file
  )
    
  if (Test-Path $file) 
  {
    Remove-Item $file -Recurse > $null;
  }
}

#Modify Unattend File
function GetUnattendChunk 
{
  param
  (
    [string] $pass, 
    [string] $component, 
    [xml] $unattend
  ); 
    
  # Helper function that returns one component chunk from the Unattend XML data structure
  return $Unattend.unattend.settings | ? pass -eq $pass `
  | select -ExpandProperty component `
  | ? name -eq $component;
}

#Write Unaattendend File
function makeUnattendFile 
{
  param
  (
    [string] $filePath
  ); 

  # Composes unattend file and writes it to the specified filepath
     
  # Reload template - clone is necessary as PowerShell thinks this is a "complex" object
  $unattend = $unattendSource.Clone();
     
  # Customize unattend XML
  GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.ComputerName = $ComputerName};
  GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.RegisteredOrganization = $Organization};
  GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.RegisteredOwner = $Owner};
  GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.TimeZone = $Timezone};
  GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.UserAccounts.AdministratorPassword.Value = $adminPassword};
  GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | %{$_.ProductKey = $WindowsKey};
  GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | %{$_.InputLocale = $InputLocale};
  GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | %{$_.SystemLocale = $SystemLocale};
  GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | %{$_.UserLocale = $UserLocale};
    
  # Write it out to disk
  cleanupFile $filePath; $Unattend.Save($filePath);
}
#endregion


function Wait-ForPSDirect([string]$VMName, $cred){
  while ((Invoke-Command -VMName $VMName -Credential $cred {'Test'} -ea SilentlyContinue) -ne 'Test') {Start-Sleep -Seconds 1}
}

####

#region Create VM 
$VmDirectory = "$VMPath\$VMName"
$VHDDirectory = $VmDirectory+'\Virtual Hard Disks'

#create Unattended.xml File
$DiskPath = $CloudBuilderDisk.Substring(0,$CloudBuilderDisk.LastIndexOf('\'))
$TempDir = $DiskPath.Substring(0,$DiskPath.LastIndexOf('\'))+'\Temp'
New-Item -Path $TempDir -Type Directory -ErrorAction SilentlyContinue
$UnattendFile = $TempDir+'\'+$VMName+'-Unattend.xml'
$ComputerName = $VMName
makeUnattendFile $UnattendFile

#Create VM 
New-Item -Path $VHDDirectory -ItemType Directory
New-VM -Name $VMName -MemoryStartupBytes $VMMemory -NoVHD -Path $VMPath -Generation $VMGeneration -SwitchName $HVSWitch | Set-VM -ProcessorCount $vmProcCount 
Copy-Item $CloudBuilderDisk -Destination $VHDDirectory -Verbose
$OSVHDName = $CloudBuilderDisk.Substring($CloudBuilderDisk.LastIndexOf('\')+1)
$CloudBuilderVHDXPath = $($VHDDirectory+'\'+$OSVHDName)
Resize-VHD -Path $CloudBuilderVHDXPath -SizeBytes $CloudBuilderDiskSize
$VHD = Mount-VHD -Path $CloudBuilderVHDXPath –PassThru
$OSVolumes = $VHD | Get-Disk | Get-Partition | Get-Volume
$DriveLetterAssigned = $false
foreach($Drive in $OSVolumes) {
    if(($Drive.DriveLetter -ne '') -and ($Drive.DriveLetter -ne $Null)) {
        $IsOSDrive = Test-Path -Path $($Drive.DriveLetter + ':\Windows')
        if($IsOSDrive) {
            $DriveLetterAssigned = $true
            $DriveLetter = $Drive.DriveLetter
            Copy-Item $UnattendFile -Destination $($DriveLetter + ':\Unattend.xml')  
        }
    }    
}
if($DriveLetterAssigned -ne $true) {
    $DriveLetter = 'O'
    $OSPartition = ($VHD | Get-Disk | Get-Partition | where Size  -gt 5GB | Set-Partition -NewDriveLetter $DriveLetter)
    Copy-Item $UnattendFile -Destination $($DriveLetter + ':\Unattend.xml')
    $DriveLetterAssigned = $true
}      

# Coppy aditional Software into VHDX
$ConfigDirPath = $($DriveLetter + ':\' + $ConfigDirName)
New-Item -Path $ConfigDirPath -ItemType Directory
Copy-Item -Path $($AditionalSoftwareDir + '\*') -Destination $($ConfigDirPath) -Confirm:$false -Recurse 

#dismount VHDX
Dismount-VHD -Path $($VHDDirectory+'\'+$OSVHDName)
Add-VMHardDiskDrive -VMName $VMName -Path $($VHDDirectory+'\'+$OSVHDName)

#Set firtst Boot Device to CloudBuilder VHDX
$BootVHDX = Get-VMHardDiskDrive -VMName $VMName -ControllerNumber 0
Set-VMFirmware -VMName $VMName -FirstBootDevice $BootVHDX


#create DDrive
$DiskPath = $("$VHDDirectory\$DDriveName"+'.vhdx')
New-VHD -Path $DiskPath -SizeBytes $DDriveSize -Dynamic
Add-VMHardDiskDrive -VMName $VMName -Path $DiskPath

#Set Shutdown behavior to Shutdown
Set-VM -VMName $VMName -AutomaticStopAction Shutdown

#Enable Nested Virtualization
Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true

#Disable Dynamic Memory
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false

#Disable Time Synchronisation
Disable-VMIntegrationService -VMName $VMName -Name "Time Synchronization"

#Enable MacAddress Spoofing
Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing on

#if Host is not Windows Server turn of atomatic Checkpoints
if($OSString -like "Client*") {
    Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
}
#endregion


#region create $VDiskNumber VHDX disks of $DiskSize for each S2D node
for ($i = 1; $i -le $VDiskNumber; $i++)
{ 
    $DiskPath = "$VHDDirectory\Data$i.vhdx"
    New-VHD -Path $DiskPath -SizeBytes $VDiskSize -Dynamic
    Add-VMHardDiskDrive -VMName $VMName -Path $DiskPath
}


#Start VM
Start-VM -VMName $VMName
Wait-ForPSDirect $VMName $localAdminCredential

start-sleep 60

Stop-VM -VMName $VMName -Force
Start-VM -VMName $VMName
Wait-ForPSDirect $VMName $localAdminCredential
#endregion


#region prepare ASDK VM
$PSSession = New-PSSession -VMName $VMName -Credential $LocalAdminCredential
Invoke-Command -Session $PSSession -ArgumentList $VMIP, $IPSubNetMask, $BGPNatIP, $DNSServerIP, $DefaultGatewayIP, $NTPServerIP, $LocalAdminPassword, $AzureTenantAdminName, $AzureTenantAdminPassword, $AzureTenantSubcriptionID, $ConfigDirName, $DDriveName -ScriptBlock {
    param(
        $IP,
        $IPSubNetMask,
        $BGPNatIP,
        $DNSServerIP,
        $DefaultGatewayIP,
        $NTPServerIP,
        $LocalAdminPassword,
        $AzureTenantAdminName,
        $AzureTenantAdminPassword,
        $AzureTenantSubcriptionID,
        $ConfigDirName,
        $DDriveName
    )

    
    #Variables
    $ConfigDir = 'C:\' + $ConfigDirName
    $InstallASDKScript = "$ConfigDir\Install-AzureStackPoC.ps1"
    $ConfigASKScript = "$ConfigDir\Configure-AzureStackPoC.ps1"
    $InstallTaskScript = "$ConfigDir\InstallTask.ps1"
    $AzureTenenantName = $AzureTenantAdminName.Substring($AzureTenantAdminName.LastIndexOf('@')+1)
    $SubnetwithMask = $($IP.Substring(0,$IP.LastIndexOf('.'))+'.0/'+$IPSubNetMask)
    $localAdminPWord = ConvertTo-SecureString –String "$LocalAdminPassword" –AsPlainText -Force
    $AADTenantAdminPWord = ConvertTo-SecureString –String "$AzureTenantAdminPassword" –AsPlainText -Force
    $AADCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AzureTenantAdminName, $AADTenantAdminPWord
 

    #rezize CloudBuilder Partition
    $size = (Get-PartitionSupportedSize –DiskNumber 0 –PartitionNumber 2)
    Resize-Partition -DiskNumber 0 –PartitionNumber 2 -Size $size.SizeMax

    #Bring Online D Disk
    $DriveFound = $false
    $Disk = Get-Disk | where Number -eq 1 
    Set-Disk -Number $Disk.DiskNumber -IsOffline $false
    Initialize-Disk $Disk.DiskNumber
    $partition = New-Partition -DriveLetter D -UseMaximumSize -DiskNumber $Disk.DiskNumber
    $volume = Format-Volume -FileSystem NTFS -NewFileSystemLabel $DDriveName -Confirm:$false -Force -Partition $partition


    # set IP Config
    $NetAdapter = Get-NetAdapter
    Set-NetIPInterface -InterfaceAlias $NetAdapter.Name -dhcp Disabled -verbose
    if(($DefaultGatewayIP.Length -eq 0) -or ($DefaultGatewayIP -eq '')) {
        New-NetIPAddress -AddressFamily IPv4 -PrefixLength $IPSubNetMask -InterfaceAlias $NetAdapter.Name -IPAddress $IP -verbose
    } else {
        New-NetIPAddress -AddressFamily IPv4 -PrefixLength $IPSubNetMask -InterfaceAlias $NetAdapter.Name -IPAddress $IP -DefaultGateway $DefaultGatewayIP -verbose
    }
    Set-DnsClientServerAddress -InterfaceAlias $NetAdapter.Name -ServerAddresses $DNSServerIP

    # Configure IE Security
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0


    #Find Windows Server ISO in ConfigDir
    $WindowsServerISOName = (Get-Item -Path $($ConfigDir + '\*') -Include "*_SERVER_*.iso").FullName

    #create Azure Stack Installation Script
    "# Script to start Azure Stack Development Kit Installation" | Out-File -FilePath $InstallASDKScript
    " "  | Out-File -FilePath $InstallASDKScript -Append
    "#Variable"  | Out-File -FilePath $InstallASDKScript -Append
    $OutPutString = '$localAdminPWord = ConvertTo-SecureString –String ' + """$LocalAdminPassword"" –AsPlainText -Force" 
    $OutPutString | Out-File -FilePath $InstallASDKScript -Append
    
    $OutPutString = '$AADTenantAdminPWord = ConvertTo-SecureString –String ' + """$AzureTenantAdminPassword"" –AsPlainText -Force" 
    $OutPutString | Out-File -FilePath $InstallASDKScript -Append

    $OutPutString = '$AADCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList ' + """$AzureTenantAdminName"", " +'$AADTenantAdminPWord'
    $OutPutString | Out-File -FilePath $InstallASDKScript -Append

    " "  | Out-File -FilePath $InstallASDKScript -Append
    "# Script to configure Azure Stack Development Kit"  | Out-File -FilePath $InstallASDKScript -Append
    "Set-Location C:\CloudDeployment\Setup" | Out-File -FilePath $InstallASDKScript -Append
    $OutPutString = './InstallAzureStackPOC.ps1 -AdminPassword $LocalAdminPWord -InfraAzureDirectoryTenantName "' + "$AzureTenenantName" +'" -InfraAzureDirectoryTenantAdminCredential $AADCredential -NATIPv4Subnet ' + "$SubnetwithMask -NATIPv4Address $BGPNatIP -NATIPv4DefaultGateway $DefaultGatewayIP -TimeServer $NTPServerIP -Verbose"
    $OutPutString |  Out-File -FilePath $InstallASDKScript -Append
 

    #create Azure Stack Configuration Script
    "# Script to Configure Azure Stack Development Kit" | Out-File -FilePath $ConfigASKScript
    " "  | Out-File -FilePath $ConfigASKScript -Append
 
    "#Change into Download Dir "  | Out-File -FilePath $ConfigASKScript -Append
    $OutPutString = 'Set-Location "' + "$ConfigDir" + '"'
    $OutPutString |  Out-File -FilePath $ConfigASKScript -Append
    
    " "  | Out-File -FilePath $ConfigASKScript -Append
    "# Download the ConfigASDK Script."  | Out-File -FilePath $ConfigASKScript -Append
    $OutPutString = '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12'
    $OutPutString |  Out-File -FilePath $ConfigASKScript -Append
    $OutPutString = 'Invoke-Webrequest http://bit.ly/configasdk -UseBasicParsing -OutFile ConfigASDK.ps1'
    $OutPutString |  Out-File -FilePath $ConfigASKScript -Append

    " "  | Out-File -FilePath $ConfigASKScript -Append
    "# Start the Azure Stack Configuration "  | Out-File -FilePath $ConfigASKScript -Append
    #$OutPutString = '.\ConfigASDK.ps1 -azureDirectoryTenantName "' + $AzureTenenantName + '" -authenticationType AzureAD -registerASDK -useAzureCredsForRegistration -downloadPath "' + $ConfigDir + '" -ISOPath "' + $WindowsServerISOName + '" -azureStackAdminPwd "' + $LocalAdminPassword + '" -VMpwd "' + $LocalAdminPassword + '" -azureAdUsername "' + $AzureTenantAdminName +'" -azureAdPwd "' + $AzureTenantAdminPassword + '"'
    $OutPutString = '.\ConfigASDK.ps1 -azureDirectoryTenantName "' + $AzureTenenantName + '" -authenticationType AzureAD -registerASDK -useAzureCredsForRegistration -azureRegSubId "' + $AzureTenantSubcriptionID + '" -downloadPath "' + $ConfigDir + '" -ISOPath "' + $WindowsServerISOName + '" -azureStackAdminPwd "' + $LocalAdminPassword + '" -VMpwd "' + $LocalAdminPassword + '" -azureAdUsername "' + $AzureTenantAdminName +'" -azureAdPwd "' + $AzureTenantAdminPassword + '"'
    $OutPutString |  Out-File -FilePath $ConfigASKScript -Append

}
#endregion

Get-Date
