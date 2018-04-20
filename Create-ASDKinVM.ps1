# Create Asure Stack Development Kit in a Hyper-V VM
<#
.Synopsis
   Script to Create ASDK Hyper-V VM
   Copyright 2018 by Carsten Rachfahl Rachfahl IT-Solutions GmbH & Co.KG
   Version 1.0
   1.0 6.4.2018 cr First draft
.DESCRIPTION
   Script creates a Hyper-V VM that is capable to host an Azure Stack Development Kit Installation
.EXAMPLE
   Create-ASDKVM.ps1 -VMName "AST1804-02" -VMPath "\\DellSOFS\Share1" -VMIP 172.16.0.2 -GBPNatIP 172.16.0.3 -CloudBuilderDisk "C:\ClusterStorage\COLLECT\Azure Stack Dev Kit\CloudBuilder.vhdx" -LocalAdminPassword Password! -$AzureTenantAdminName @admin@RITSASTPoC.onmicrosoft.com -$AzureTenantAdminPassord Password! -MemoryinGB 128 -Cores 12
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

    # CloudBuilderDisk
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=4)]
    [String]$CloudBuilderDisk,

    # LocalAdminPassword
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=5)]
    [String]$LocalAdminPassword,

    # AzureTenantAdminName
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=6)]
    [String]$AzureTenantAdminName,


    # AzureTenantAdminPassword
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=7)]
    [String]$AzureTenantAdminPassword,

    # $MemoryinGB
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=8)]
    [ValidateRange(96,512)]
    [int]$MemoryinGB = 200,

    # Cores
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=9)]
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

#VM releated
$HVSWitch = 'NATSwitch'
$IPSubNetNAT = '172.16.0.0/24'
$IPSubNetMask = $IPSubNetNAT.Substring($IPSubNetNAT.LastIndexOf('/')+1)
$DNSServerIP = '192.168.209.2'
$DefaultGatewayIP = '172.16.0.1'
$NTPServerIP = '192.168.209.2'
$VMGeneration = 2
$VMMemory = $MemoryinGB * 1GB
$vmProcCount  = $Cores
$VDiskNumber = 4
$CloudBuilderDiskSize = 200GB
$VDiskSize = 200GB
#endregion

#region Unattend.xml Handling
#$UnattendFile = $DiskPath+'\Temp\'+$VMName+'-Unattend.xml'
$ComputerName = '*'
$Organization = 'PowerKurs'
$Owner = 'PowerKurs'
$Timezone = 'Pacific Standard Time'
$InputLocale = 'en-US'
$SystemLocale = 'en-US'
$UserLocale = 'en-US'
$adminPassword = "$LocalAdminPassword"
$WindowsKey = 'CB7KF-BWN84-R7R2Y-793K2-8XDDG'



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
        $DriveLetterAssigned = $true
        Copy-Item $UnattendFile -Destination $($Drive.DriveLetter + ':\Unattend.xml')  
    }    
}
if($DriveLetterAssigned -ne $true) {
    $OSPartition = ($VHD | Get-Disk | Get-Partition | where Size  -gt 5GB | Set-Partition -NewDriveLetter O)
    Copy-Item $UnattendFile -Destination 'O:\Unattend.xml'
    $DriveLetterAssigned = $true
}      
Dismount-VHD -Path $($VHDDirectory+'\'+$OSVHDName)
Add-VMHardDiskDrive -VMName $VMName -Path $($VHDDirectory+'\'+$OSVHDName)

#Set firtst Boot Device to CloudBuilder VHDX
$BootVHDX = Get-VMHardDiskDrive -VMName $VMName -ControllerNumber 0
Set-VMFirmware -VMName $VMName -FirstBootDevice $BootVHDX

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
Invoke-Command -Session $PSSession -ArgumentList $VMIP, $IPSubNetMask, $BGPNatIP, $DNSServerIP, $DefaultGatewayIP, $NTPServerIP, $LocalAdminPassword, $AzureTenantAdminName, $AzureTenantAdminPassword -ScriptBlock {
    param(
        $IP,
        $IPSubNetMask,
        $BGPNatIP,
        $DNSServerIP,
        $DefaultGatewayIP,
        $NTPServerIP,
        $LocalAdminPassword,
        $AzureTenantAdminName,
        $AzureTenantAdminPassword 
    )
    
    #Variables
    $InstallFile = "C:\Install-AzureStackPoC.ps1"
    $AzureTenenantName = $AzureTenantAdminName.Substring($AzureTenantAdminName.LastIndexOf('@')+1)
    $SubnetwithMask = $($IP.Substring(0,$IP.LastIndexOf('.'))+'.0/'+$IPSubNetMask)
    $localAdminPWord = ConvertTo-SecureString –String "$LocalAdminPassword" –AsPlainText -Force
    $AADTenantAdminPWord = ConvertTo-SecureString –String "$AzureTenantAdminPassword" –AsPlainText -Force
    $AADCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AzureTenantAdminName, $AADTenantAdminPWord
  

    #rezize CloudBuilder Partition
    $size = (Get-PartitionSupportedSize –DiskNumber 0 –PartitionNumber 2)
    Resize-Partition -DiskNumber 0 –PartitionNumber 2 -Size $size.SizeMax

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

    #create Azure Stack Installation File
    "# Script to start Azure Stack Development Kit Installation" | Out-File -FilePath $InstallFile
    " "  | Out-File -FilePath $InstallFile -Append
    "#Variable"  | Out-File -FilePath $InstallFile -Append
    $String1 = '$localAdminPWord = ConvertTo-SecureString –String ' + "$LocalAdminPassword –AsPlainText -Force" 
    $String1 | Out-File -FilePath $InstallFile -Append
    
    $String2 = '$AADTenantAdminPWord = ConvertTo-SecureString –String ' + "$AzureTenantAdminPassword –AsPlainText -Force" 
    $String2 | Out-File -FilePath $InstallFile -Append

    $String3 = '$AADCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList ' + "$AzureTenantAdminName, " +'$AADTenantAdminPWord'
    $String3 | Out-File -FilePath $InstallFile -Append

    " "  | Out-File -FilePath $InstallFile -Append
    "Set-Location C:\CloudDeployment\Setup" | Out-File -FilePath $InstallFile -Append
    $String4 = './InstallAzureStackPOC.ps1 -AdminPassword $LocalAdminPWord -InfraAzureDirectoryTenantName "' + "$AzureTenenantName" +'" -InfraAzureDirectoryTenantAdminCredential $AADCredential -NATIPv4Subnet ' + "$SubnetwithMask -NATIPv4Address $BGPNatIP -NATIPv4DefaultGateway $DefaultGatewayIP -TimeServer $NTPServerIP -Verbose"
    $String4 |  Out-File -FilePath $InstallFile -Append

    #start PowerShell to Execute Script
    start-process powershell -ArgumentList $InstallFile -RedirectStandardOutput "C:\Install-AzureStackPoC-out.txt" -RedirectStandardError "C:\Install-AzureStackPoC-err.txt"

}
#endregion

Get-Date