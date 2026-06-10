<#
Azure Tag Scan Script
Outputs CSV with resource tag evaluation across subscriptions.

Features:
- Parameterised output path (no hard-coded local paths)
- Parameterised required tags (defaults set to org keys)


Usage:
# .\Scan-AzureTags.ps1 -OutputPath .\outputs\azuretag-prodscan.csv

#>

param(
	[string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "outputs\azuretag-prodscan.csv"),
	[string[]]$RequiredTags = @(
		"Environment",
		"Owner",
		"CostCentre",
		"Application",
		"Product",
		"ServiceOffering"
	),
	[switch]$UseAzCli = $true
)

if ($UseAzCli -ne $true) {
	throw "Only az CLI mode is supported by this script. Set UseAzCli switch or call the Az module variant."
}

# Ensure output directory exists
$outDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

Write-Host "Starting Azure tag scan. Output: $OutputPath" -ForegroundColor Yellow

# Ensure az is authenticated
try {
	$account = az account show --only-show-errors -o json 2>$null | ConvertFrom-Json
} catch {
	$account = $null
}

if (-not $account) {
	Write-Host "Not authenticated to Azure CLI, attempting az login..." -ForegroundColor Yellow
	az login --only-show-errors | Out-Null
}

$output = @()

# Get subscriptions
$subscriptions = az account list --query "[].{Name:name, Id:id}" -o json | ConvertFrom-Json

foreach ($sub in $subscriptions) {
	Write-Host "Scanning subscription: $($sub.Name)" -ForegroundColor Cyan
	az account set --subscription $sub.Id --only-show-errors | Out-Null

	# Cache resource group tags
	$rgTagsCache = @{}
	$resourceGroups = az group list -o json | ConvertFrom-Json
	foreach ($rg in $resourceGroups) {
		# Tags can be $null
		$rgTagsCache[$rg.name] = $rg.tags
	}

	# Get resources
	$resources = az resource list -o json | ConvertFrom-Json

	foreach ($resource in $resources) {
		$resourceTags = $resource.tags
		$rgTags = $rgTagsCache[$resource.resourceGroup]

		# Merge RG + Resource tags (resource overrides RG)
		$mergedTags = @{}
		if ($rgTags) {
			$rgTags.PSObject.Properties | ForEach-Object { $mergedTags[$_.Name] = $_.Value }
		}
		if ($resourceTags) {
			$resourceTags.PSObject.Properties | ForEach-Object { $mergedTags[$_.Name] = $_.Value }
		}

		foreach ($tag in $RequiredTags) {
			$tagValue = $null
			if ($mergedTags.ContainsKey($tag)) { $tagValue = $mergedTags[$tag] }

			$output += [PSCustomObject]@{
				SubscriptionName = $sub.Name
				SubscriptionId   = $sub.Id
				ResourceGroup    = $resource.resourceGroup
				ResourceName     = $resource.name
				ResourceType     = $resource.type
				Location         = $resource.location
				RequiredTag      = $tag
				TagValue         = $tagValue
				TagStatus        = if ([string]::IsNullOrWhiteSpace($tagValue)) { "Missing" } else { "Present" }
			}
		}
	}
}

# Export output
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Tag scan complete. Output written to $OutputPath" -ForegroundColor Green
