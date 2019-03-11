<#
	Author: Tyler Wright
	Git Repo: https://github.com/tylwright/Get-MACVendor

	.Synopsis
	Shows the vendor who owns a MAC address prefix
	or
	Shows the MAC addresses that are registered to a vendor

	.Parameter MAC
	MAC address you wish to lookup the vendor of

	.Parameter Vendor
	Vendor you wish to lookup the MACs of

	.Parameter Action
	An action you wish to perform
	Available Actions:
		Update: Updates MAC vendor list

	.Example
	# Update MAC vendor list
	Get-MACVendor -Action Update

	.Example
	# Display the vendor who owns a certain MAC address prefix
	Get-MACVendor -MAC 001223
	or
	Get-MACVendor -MAC 00:12:23
	or
	Get-MACVendor -MAC 00-12-23

	.Example
	# Display the MAC addresses registered to a certain vendor
	Get-MACVendor -Vendor Dell
#>

function Get-MACVendor 
{
	#region Script Arguments
	[CmdletBinding(DefaultParameterSetName='MACProvided')]
	param
	(
		[Parameter(Mandatory = $true,
				ParameterSetName = 'MACProvided',
				HelpMessage = 'MAC Address in any format')]
		[ValidateNotNullOrEmpty()]
		[string]$MAC,
		[Parameter(Mandatory = $true,
				ParameterSetName = 'VendorProvided',
				HelpMessage = 'Vendor/manufacturer')]
		[ValidateNotNullOrEmpty()]
		[string]$vendor,
		[Parameter(Mandatory = $true,
				ParameterSetName = 'UpdateRequested',
				HelpMessage = 'Actions available: Update')]
		[ValidateSet('update', IgnoreCase = $true)]
		[string]$action
	)
	#endregion

	#region Variables
	# Default location for vendor list
	$vendorList = "$pwd/vendor.txt"
	#endregion

	#region Functions
	<#
		.SYNOPSIS
			Updates vendor/MAC list
		
		.DESCRIPTION
			Retrieves a list of vendors and their assigned MAC addresses from  standards-oui.ieee.org/oui.txt.
	#>
	function Update-VendorList
	{
		Try
		{
			# If a vendor list already exists, rename it as "old"
			if (Test-Path $vendorList)
			{
				# In the event that an old copy of the OUI list was not deleted, delete it now before a new backup is made
				if (Test-Path "$vendorList.old")
				{
					Remove-Item -Path "$vendorList.old"
				}
				Rename-Item -Path $vendorList "$vendorList.old"
			}
			# Download vendor list
			Write-Host "Attempting to download a new OUI list..."
			$webclient = New-Object System.Net.WebClient
			$url = "http://standards-oui.ieee.org/oui.txt"
			$webclient.DownloadFile($url, $vendorList)
			# If vendor list downloaded successfully, delete the "old" copy
			if (Test-Path $vendorList)
			{
				Write-Host "Vendor list has been updated - deleting older version."
				Remove-Item -Path "$vendorList.old"
			}
		}
		Catch
		{
			Write-Host "Unable to download the latest OUI list from http://standards-oui.ieee.org"
			Write-Host "Reverting to previous OUI list..."
			# Rename the "old" copy back to the default name.
			# We want to be able to use this script even if our update function fails.
			Rename-Item "$vendorList.old" $vendorList
		}
	}

	<#
		.SYNOPSIS
			Makes sure that the given MAC is formatted correctly
		
		.DESCRIPTION
			First, the function removes any ":" or "-" characters from the MAC address.
			Second, the function limits the number of characters down to the first eight characters (vendors are only assigned the first three sections in a MAC address).
		
		.PARAMETER MAC
			Provide a MAC address in string format
	#>
	function Clean-MAC
	{
		param
		(
			[Parameter(Mandatory = $true,
					HelpMessage = 'Provide a MAC address in string format')]
			[ValidateNotNullOrEmpty()]
			[string]$MAC
		)
		
		# Change : to -
		$MAC = $MAC -replace ":", "-"

		if ($MAC -notlike '*-*')
		{
			$MAC = ($MAC -replace '(..)','$1-').trim('-')
		}
		
		# Only use the first 00:00:00 character
		if ($MAC.length -gt 7)
		{
			$MAC = $MAC.Substring(0, 8)
		}
		
		return $MAC
	}

	<#
		.SYNOPSIS
			Finds the vendor of a given MAC address
		
		.DESCRIPTION
			Searches for the given MAC address in the OUI list and returns the name of the vendor
		
		.PARAMETER MAC
			Provide a MAC address that has undergone the Clean-MAC function
	#>
	function Get-Vendor
	{
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					HelpMessage = 'Provide a MAC address that has undergone the Clean-MAC function')]
			[ValidateLength(8, 8)]
			[ValidateNotNullOrEmpty()]
			[string]$MAC
		)
		
		Process
		{
			Try
			{
				$output = Select-String -Path $vendorList -pattern $MAC
				$output = $output -replace ".*(hex)"
				$output = $output.Substring(3)
				return $output
			}
			Catch
			{
				Write-Warning "MAC address was not found"
				return false
			}
		}
	}

<#
		.SYNOPSIS
			Finds the MAC addresses registered to the given vendor
		
		.DESCRIPTION
			Searches for the given vendor in the OUI list and returns the MAC(s) associated with it
		
		.PARAMETER vendor
			Provide a vendor's name
	#>
	function Get-MACs
	{
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					HelpMessage = 'Provide a vendor/manufacturer')]
			[ValidateNotNullOrEmpty()]
			[string]$vendor
		)
		
		Process
		{
			Try
			{
				$output = Select-String -Path $vendorList -pattern $vendor | Select-String -pattern "(hex)" | Select-Object line -ExpandProperty line
				$num_results = $output | Measure-Object
				$num_results = $num_results.count
				if ($num_results -eq 1)
				{
					$term = "result"
				}
				else
				{
					$term = "results"
				}
				$array_of_objects = @()
				$num = @("$num_results $term")

				foreach ($line in $output)
				{
					$prefix,$vendor = $line.split('(hex)')
					$vendor = $vendor.replace('(hex)','')
					$object = New-Object PSObject
					Add-Member -InputObject $object -MemberType NoteProperty -Name "MAC Prefix" -Value $prefix
					Add-Member -InputObject $object -MemberType NoteProperty -Name Vendor -Value $vendor.trim()
					$array_of_objects += $object
				}
				
				return $array_of_objects,$num
			}
			Catch
			{
				Write-Warning "Vendor/manufacturer was not found"
			}
		}
	}
	#endregion

	#region Main Program
	# If the user wants to update the vendor list, direct them away from the vendor search
	if ($action.ToLower() -eq "update")
	{
		Update-VendorList
	}
	elseif ($MAC)
	{
		# Clean and format the given MAC address
		$cleanedMAC = Clean-MAC -MAC $MAC
		
		# Get the vendor of the MAC address
		$returnedVendor = Get-Vendor -MAC $cleanedMAC
		
		# If there is a vendor, output the name
		if ($returnedVendor)
		{
			Write-Output $returnedVendor
		}
		else
		{
			Write-Output "Unable to find the vendor of $MAC."
		}
	}
	elseif ($vendor)
	{		
			# Get the MAC address(es) pertaining to a vendor
			$addresses,$num = Get-MACs -Vendor $vendor
			
			# If there are MACs, output them
			if ($addresses)
			{
				$addresses | Sort-Object -Property Vendor | Format-Table -Property "MAC Prefix", Vendor -AutoSize -GroupBy Vendor
				Write-Output $num
			}
			else
			{
				Write-Output "Unable to find any MACs registered to $vendor."
			}
	}
	#endregion
	Export-ModuleMember -Function Get-MACVendor
}
