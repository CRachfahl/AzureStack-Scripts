# Create Asure Stack Development Kit in a Hyper-V VM
<#
.Synopsis
   Script to Modify ASDK CloudBuilderDisk for use in a Hyper-V VM
   Copyright 2018-2019 by Carsten Rachfahl Rachfahl IT-Solutions GmbH & Co.KG
   Version 1.0
   1.0 10.03.2019 cr First draft
   
.DESCRIPTION
   Script modifies ASDK CloudBuilderDisk that it can be Deployed in a Hyper-V VM
.EXAMPLE
   Modify-CloudBuilderDisk.ps1 -CloudBuilderDisk "C:\ClusterStorage\COLLECT\Azure Stack Dev Kit\CloudBuilder.vhdx"
.EXAMPLE
#>

#region Parameter
[CmdletBinding()]
Param
(
    # CloudBuilderDisk
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=1)]
    [String]$CloudBuilderDisk
)
#endregion

#region test the Variables
if(($CloudBuilderDisk[0] -eq '"') -and ($CloudBuilderDisk[$CloudBuilderDisk.Length-1] -eq '"')) {
    $CloudBuilderDisk = $CloudBuilderDisk.Substring(1, $CloudBuilderDisk.Length-2)
}
if(!(Test-Path $CloudBuilderDisk)) {
    Write-Error "$CloudBuilderDisk does not Exists!" 
    break
}
#endregion

#region Constants
$TempDirName = 'Temp'
$NuGetPackagePath = "\CloudDeployment\NuGetStore\"
$NuGetArchivePattern = "Microsoft.AzureStack.Solution.Deploy.CloudDeployment.*.nupkg"
$BarMetalTestPatern = "\content\Roles\PhysicalMachines\Tests\BareMetal.Tests.ps1"
$ZipExtractionPath = 'C:\Temp\NuGetZIP'
Get-Date

#Extract Path
$CloudBuilderPath = $CloudBuilderDisk.Substring(0,$CloudBuilderDisk.LastIndexOf('\')+1)
$CloudBuilderSavePath = $CloudBuilderPath+$TempDirName
$CloudBuilderDiskName = $CloudBuilderDisk.Substring($CloudBuilderDisk.LastIndexOf('\')+1)

#Save Cloudbuilder VHDX 
New-Item -Path $CloudBuilderSavePath -ItemType Directory
Copy-Item $CloudBuilderDisk -Destination $CloudBuilderSavePath  -Verbose
$VHD = Mount-VHD -Path $CloudBuilderDisk –PassThru
$OSVolumes = $VHD | Get-Disk | Get-Partition | Get-Volume
$DriveLetterAssigned = $false
foreach($Drive in $OSVolumes) {
    if(($Drive.DriveLetter -ne '') -and ($Drive.DriveLetter -ne $Null)) {
        $IsOSDrive = Test-Path -Path $($Drive.DriveLetter + ':\Windows')
        if($IsOSDrive) {
            $DriveLetterAssigned = $true
            $DriveLetter = $Drive.DriveLetter
        }
    }    
}
if($DriveLetterAssigned -ne $true) {
    $DriveLetter = 'O'
    $OSPartition = ($VHD | Get-Disk | Get-Partition | where Size  -gt 5GB | Set-Partition -NewDriveLetter $DriveLetter)
    $DriveLetterAssigned = $true
}      

#Copy NuPKG to TempDir 
$NuGetFileName = "$DriveLetter"+':'+$NuGetPackagePath+$NuGetArchivePattern
$NuGetArchiveObj = Get-Item -Path $NuGetFileName
Copy-Item -Path $NuGetArchiveObj.FullName -Destination $CloudBuilderSavePath
$NuGetArchiveTempObj = Get-Item $($CloudBuilderSavePath+'\'+$NuGetArchiveObj.Name)

#Rename NuPkg to ZIP
$NuGetZipFilename = $($NuGetArchiveTempObj.BaseName+'.zip')
Rename-Item -Path $NuGetArchiveTempObj.FullName -NewName $NuGetZipFilename
$NuGetZipObj = Get-Item $($CloudBuilderSavePath+'\'+$NuGetZipFilename)

#Expand Archive
New-Item $ZipExtractionPath -ItemType Directory
Expand-Archive $NuGetZipObj.FullName -DestinationPath $ZipExtractionPath -Force -Verbose

#Replace Strings
$BareMetalTestPSName = $($ZipExtractionPath+$BarMetalTestPatern)
$BareMetalTestPs1NewName = $BareMetalTestPSName+'.txt'
Rename-Item -Path $BareMetalTestPSName -NewName $BareMetalTestPs1NewName
$BareMetalTestScriptObj = Get-Item -LiteralPath $BareMetalTestPs1NewName
(Get-Content -LiteralPath $BareMetalTestPs1NewName) | foreach {$_ -Replace '-not \$isVirtualizedDeployment', '$isVirtualizedDeployment'} | Set-Content -LiteralPath $BareMetalTestPSName -Encoding String
remove-item -LiteralPath $BareMetalTestPs1NewName

#Copy File in Archive again
$ArchiveEntryName = 'content/Roles/PhysicalMachines/Tests/'+(Split-Path $BareMetalTestPSName -Leaf)
$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
$zip = [System.IO.Compression.ZipFile]::Open($NuGetZipObj.FullName, 'update')
$ArchiveEntryObj = $zip.GetEntry($ArchiveEntryName)
$ArchiveEntryObj.Delete()
[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $BareMetalTestPSName, $ArchiveEntryName, $compressionLevel)
$zip.Dispose()

#Rename to NuPkg 
Rename-Item -Path $NuGetZipObj.FullName -NewName $NuGetArchiveTempObj.FullName

#Copy back to Mounted VHDX
Copy-Item -Path $NuGetArchiveTempObj.FullName -Destination $NuGetArchiveObj.FullName


#dismount VHDX
Dismount-VHD -Path $CloudBuilderDisk

# Delete Temp Directory
remove-item -LiteralPath $ZipExtractionPath -Recurse

Get-Date