<#
PowerShell script to search org repositories for .csproj PackageReference entries

Usage examples:
# Local run writing to local file (token from env):
# $env:GITHUB_TOKEN = 'ghp_...'; .\Get-GitHubReposCsprojDetails.ps1 -OrgName SkillsFundingAgency -OutputPath .\outputs\packages.csv

# Run and upload using connection string:
# $env:GITHUB_TOKEN='ghp_...'; $env:AZURE_STORAGE_CONNECTION_STRING='DefaultEndpointsProtocol=...'; .\Get-GitHubReposCsprojDetails.ps1 -OrgName SkillsFundingAgency -ContainerName csv-outputs -BlobPrefix myjob

# Run using managed identity (when running in Azure with a managed identity that has Blob Data Contributor):
# $env:GITHUB_TOKEN='ghp_...'; .\Get-GitHubReposCsprojDetails.ps1 -OrgName SkillsFundingAgency -StorageAccountName mystorageacct -ContainerName csv-outputs -UseManagedIdentity
#>

param(
	[Parameter(Mandatory=$true)]
	[string]$OrgName,

	[string]$GitHubToken = $env:GITHUB_TOKEN,

	[string]$OutputPath = $env:OUTPUT_PATH,

	[string]$StorageAccountName = $env:AZURE_STORAGE_ACCOUNT_NAME,

	[string]$ContainerName = $env:AZURE_STORAGE_CONTAINER,

	[string]$BlobPrefix = $env:BLOB_PREFIX,

	[switch]$UseManagedIdentity
)

if (-not $GitHubToken) { throw "Missing GitHub token. Provide via -GitHubToken or set the GITHUB_TOKEN environment variable." }

if (-not $OutputPath) { $OutputPath = Join-Path -Path (Get-Location) -ChildPath "outputs\packages.csv" }
if (-not $ContainerName) { $ContainerName = "csv-outputs" }
if (-not $BlobPrefix) { $BlobPrefix = "" }

$perPage = 100
$headers = @{ "Authorization" = "Bearer $GitHubToken"; "User-Agent" = "Get-GitHubReposCsprojDetailsScript" }

$packageList = New-Object 'System.Collections.Generic.List[object]'

function Get-Repos {
	param([string]$org)
	$page = 1
	$repos = @()
	do {
		$uri = "https://api.github.com/orgs/$org/repos?type=all&per_page=$perPage&page=$page"
		try {
			$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
			if (-not $response) { break }
			if ($response.count -eq 0) { break }
			$repos += $response
			$page++
		} catch {
			Write-Warning "Failed to list repositories: $_"
			break
		}
	} while ($true)
	return $repos
}

function Search-CsprojFilesInRepo {
	param([string]$org, [string]$repoName)
	$page = 1
	do {
		$searchQuery = "extension:csproj in:path repo:$org/$repoName"
		$uri = "https://api.github.com/search/code?q=$searchQuery&per_page=$perPage&page=$page"
		try {
			$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
			if (-not $response) { break }
			if ($response.total_count -eq 0) { break }

			foreach ($item in $response.items) {
				$filePath = $item.path
				$filePathEncoded = [Uri]::EscapeDataString($filePath)
				$contentUri = "https://api.github.com/repos/$($item.repository.full_name)/contents/$filePathEncoded"
				try {
					$fileContentResponse = Invoke-RestMethod -Uri $contentUri -Headers $headers -Method Get
					if ($fileContentResponse -and $fileContentResponse.content) {
						$fileContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($fileContentResponse.content))

						$packagePattern = '<PackageReference Include="([^\"]+)" Version="([^\"]+)"\s*/>'
						$packageMatches = [regex]::Matches($fileContent, $packagePattern)
						foreach ($match in $packageMatches) {
							$packageName = $match.Groups[1].Value
							$packageVersion = $match.Groups[2].Value
							$packageList.Add([PSCustomObject]@{
								RepositoryName = $repoName
								FilePath = $filePath
								PackageName = $packageName
								PackageVersion = $packageVersion
							})
						}
					}
				} catch {
					Write-Warning "Failed to retrieve content for file $filePath in repository $repoName: $_"
				}
			}

			if ($response.total_count -le $perPage * $page) { break }
			$page++
		} catch {
			Write-Warning "Failed to search for csproj files in repository $repoName: $_"
			break
		}
	} while ($true)
}

# Main
$repos = Get-Repos -org $OrgName
if (-not $repos -or $repos.Count -eq 0) { Write-Host "No repositories found for org $OrgName"; return }

foreach ($repo in $repos) {
	$repoName = $repo.name
	if (-not $repoName.StartsWith("das-", [System.StringComparison]::OrdinalIgnoreCase)) { continue }

	Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Searching repository $repoName"
	Start-Sleep -Seconds 1
	Search-CsprojFilesInRepo -org $OrgName -repoName $repoName
}

# Ensure local folder exists
$localDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $localDir)) { New-Item -ItemType Directory -Path $localDir -Force | Out-Null }

$tempFile = $OutputPath
$packageList | Export-Csv -Path $tempFile -NoTypeInformation -Encoding UTF8
Write-Host "Package reference export completed. Results saved to $tempFile"

# Upload to Azure Blob Storage if requested
if ($env:AZURE_STORAGE_CONNECTION_STRING -or $StorageAccountName) {
	try {
		Import-Module Az.Storage -ErrorAction Stop

		if ($env:AZURE_STORAGE_CONNECTION_STRING) {
			$ctx = New-AzStorageContext -ConnectionString $env:AZURE_STORAGE_CONNECTION_STRING
		} elseif ($UseManagedIdentity -or $StorageAccountName) {
			if ($UseManagedIdentity) { Connect-AzAccount -Identity | Out-Null }
			$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
		}

		# Ensure container exists
		$container = Get-AzStorageContainer -Name $ContainerName -Context $ctx -ErrorAction SilentlyContinue
		if (-not $container) { New-AzStorageContainer -Name $ContainerName -Context $ctx | Out-Null }

		$blobName = if ($BlobPrefix) { "$BlobPrefix/$(Split-Path -Path $tempFile -Leaf)" } else { Split-Path -Path $tempFile -Leaf }
		Set-AzStorageBlobContent -File $tempFile -Container $ContainerName -Blob $blobName -Context $ctx -Force | Out-Null
		Write-Host "Uploaded $tempFile to container '$ContainerName' as blob '$blobName'"
	} catch {
		Write-Warning "Failed to upload to Azure Blob Storage: $_"
	}
} else {
	Write-Host "No Azure storage configuration found. Skipping upload. To enable upload set AZURE_STORAGE_CONNECTION_STRING or provide -StorageAccountName and -UseManagedIdentity." 
}
