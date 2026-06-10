<#
Lookup GitHub Advisory Database for NuGet package vulnerabilities based on an input CSV of package references

This script exposes a function Get-GitHubPackageVulnerabilities and can executed directly

Usage examples:
# Dot-source and call from a PowerShell session (token from env):
# $env:GITHUB_TOKEN = 'ghp_...'
# .\Get-GitHubPackageVulnerabilities.ps1
# Get-GitHubPackageVulnerabilities -InputCsvPath .\outputs\GitHubPackageReferences.csv -OutputCsvPath .\outputs\GitHubPackageVulnerabilities.csv



#>

function Get-GitHubPackageVulnerabilities {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$InputCsvPath,

		[Parameter(Mandatory = $true)]
		[string]$OutputCsvPath,

		[Parameter(Mandatory = $false)]
		[string]$GitHubToken = $env:GITHUB_TOKEN,

		[Parameter(Mandatory = $false)]
		[int]$DelayMilliseconds = 250
	)

	if (-not (Test-Path $InputCsvPath)) {
		throw "Input CSV not found: $InputCsvPath"
	}

	if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
		throw "GitHub token is missing. Set GITHUB_TOKEN or pass -GitHubToken."
	}

	$headers = @{
		Authorization          = "Bearer $GitHubToken"
		Accept                 = "application/vnd.github+json"
		"X-GitHub-Api-Version" = "2022-11-28"
		"User-Agent"           = "PowerShell-TRM-Vulnerability-Exporter"
	}

	$packageRows = Import-Csv -Path $InputCsvPath
	$results = New-Object 'System.Collections.Generic.List[object]'

	function Get-SafeValue {
		param([object]$Value)

		if ($null -eq $Value) { return $null }

		$text = [string]$Value
		if ([string]::IsNullOrWhiteSpace($text)) { return $null }

		return $text.Trim()
	}

	function Normalize-PackageVersion {
		param([string]$Version)

		if ([string]::IsNullOrWhiteSpace($Version)) { return $null }

		$v = $Version.Trim()

		# Strip common wrappers sometimes found in version expressions
		$v = $v.Trim('[',']','(',')')

		return $v
	}

	function Get-LookupStatus {
		param(
			[string]$PackageVersion,
			[string]$PackageVersionRaw,
			[string]$PackageVersionSource
		)

		if ([string]::IsNullOrWhiteSpace($PackageVersionRaw) -and [string]::IsNullOrWhiteSpace($PackageVersion)) {
			return "NoVersion"
		}

		if ($PackageVersionSource -eq "PropertyReference") {
			return "UnresolvedProperty"
		}

		if ($PackageVersionSource -eq "CentralPackageManagementCandidate") {
			return "CentralPackageManagement"
		}

		if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
			return "UnresolvedVersion"
		}

		return "Ready"
	}

	function Invoke-GitHubGlobalAdvisoriesLookup {
		param(
			[string]$PackageName,
			[string]$PackageVersion
		)

		$affects = "$PackageName@$PackageVersion"
		$encodedAffects = [uri]::EscapeDataString($affects)
		$uri = "https://api.github.com/advisories?ecosystem=nuget&affects=$encodedAffects&per_page=100"

		$allItems = @()
		$nextUrl = $uri

		do {
			$response = Invoke-WebRequest -Uri $nextUrl -Headers $headers -Method Get

			$content = $response.Content | ConvertFrom-Json
			if ($content) {
				$allItems += $content
			}

			$linkHeader = $response.Headers["Link"]
			$nextUrl = $null

			if ($linkHeader) {
				$links = $linkHeader -split ','
				foreach ($link in $links) {
					if ($link -match '<([^>]+)>;\s*rel="next"') {
						$nextUrl = $matches[1]
						break
					}
				}
			}

			if ($DelayMilliseconds -gt 0) {
				Start-Sleep -Milliseconds $DelayMilliseconds
			}
		} while ($nextUrl)

		return $allItems
	}

	function Expand-VulnerabilityRows {
		param(
			[pscustomobject]$PackageRow,
			[object[]]$Advisories
		)

		$repositoryName         = Get-SafeValue $PackageRow.RepositoryName
		$repositoryUrl          = Get-SafeValue $PackageRow.RepositoryUrl
		$filePath               = Get-SafeValue $PackageRow.FilePath
		$projectName            = Get-SafeValue $PackageRow.ProjectName
		$projectKey             = Get-SafeValue $PackageRow.ProjectKey
		$technology             = Get-SafeValue $PackageRow.Technology
		$frameworkName          = Get-SafeValue $PackageRow.FrameworkName
		$frameworkFamily        = Get-SafeValue $PackageRow.FrameworkFamily
		$packageName            = Get-SafeValue $PackageRow.PackageName
		$packageVersion         = Get-SafeValue $PackageRow.PackageVersion
		$packageVersionRaw      = Get-SafeValue $PackageRow.PackageVersionRaw
		$packageVersionSource   = Get-SafeValue $PackageRow.PackageVersionSource
		$isVersionPropertyRef   = Get-SafeValue $PackageRow.IsVersionPropertyReference
		$isVersionMissing       = Get-SafeValue $PackageRow.IsVersionMissing
		$packageKey             = Get-SafeValue $PackageRow.PackageKey
		$repoPackageKey         = Get-SafeValue $PackageRow.RepoPackageKey
		$scanDate               = (Get-Date).ToString("yyyy-MM-dd")

		if (-not $Advisories -or $Advisories.Count -eq 0) {
			return @(
				[PSCustomObject]@{
					RepositoryName             = $repositoryName
					RepositoryUrl              = $repositoryUrl
					FilePath                   = $filePath
					ProjectName                = $projectName
					ProjectKey                 = $projectKey
					Technology                 = $technology
					FrameworkName              = $frameworkName
					FrameworkFamily            = $frameworkFamily
					PackageName                = $packageName
					PackageVersion             = $packageVersion
					PackageVersionRaw          = $packageVersionRaw
					PackageVersionSource       = $packageVersionSource
					IsVersionPropertyReference = $isVersionPropertyRef
					IsVersionMissing           = $isVersionMissing
					PackageKey                 = $packageKey
					RepoPackageKey             = $repoPackageKey
					VulnerabilityId            = $null
					GhsaId                     = $null
					CveId                      = $null
					AdvisorySource             = "GitHub Advisory Database"
					Severity                   = $null
					CvssScore                  = $null
					CvssVector                 = $null
					EpssPercentage             = $null
					AffectedPackage            = $packageName
					AffectedEcosystem          = "nuget"
					AffectedRange              = $null
					FirstPatchedVersion        = $null
					PublishedDate              = $null
					UpdatedDate                = $null
					WithdrawnDate              = $null
					IsWithdrawn                = $false
					Summary                    = $null
					Description                = $null
					ReferenceUrl               = $null
					LookupStatus               = "NoMatch"
					ScanDate                   = $scanDate
				}
			)
		}

		$expanded = @()

		foreach ($advisory in $Advisories) {
			$ghsaId = $null
			$cveId = $null
			$severity = $null
			$cvssScore = $null
			$cvssVector = $null
			$epssPercentage = $null
			$publishedDate = $null
			$updatedDate = $null
			$withdrawnDate = $null
			$isWithdrawn = $false
			$summary = $null
			$description = $null
			$referenceUrl = $null

			if ($advisory.ghsa_id) { $ghsaId = [string]$advisory.ghsa_id }
			if ($advisory.cve_id) { $cveId = [string]$advisory.cve_id }
			if ($advisory.severity) { $severity = [string]$advisory.severity }
			if ($advisory.summary) { $summary = [string]$advisory.summary }
			if ($advisory.description) { $description = [string]$advisory.description }
			if ($advisory.html_url) { $referenceUrl = [string]$advisory.html_url }
			if ($advisory.published_at) { $publishedDate = [string]$advisory.published_at }
			if ($advisory.updated_at) { $updatedDate = [string]$advisory.updated_at }
			if ($advisory.withdrawn_at) {
				$withdrawnDate = [string]$advisory.withdrawn_at
				$isWithdrawn = $true
			}

			if ($advisory.cvss) {
				if ($advisory.cvss.score) { $cvssScore = [string]$advisory.cvss.score }
				if ($advisory.cvss.vector_string) { $cvssVector = [string]$advisory.cvss.vector_string }
			}

			if ($advisory.epss -and $advisory.epss.percentage) {
				$epssPercentage = [string]$advisory.epss.percentage
			}

			$vulnerabilityId = $ghsaId
			if (-not $vulnerabilityId -and $cveId) {
				$vulnerabilityId = $cveId
			}

			if ($advisory.vulnerabilities) {
				foreach ($v in $advisory.vulnerabilities) {
					$affectedPackage = $null
					$affectedEcosystem = $null
					$affectedRange = $null
					$firstPatchedVersion = $null

					if ($v.package -and $v.package.name) {
						$affectedPackage = [string]$v.package.name
					}
					if ($v.package -and $v.package.ecosystem) {
						$affectedEcosystem = [string]$v.package.ecosystem
					}
					if ($v.vulnerable_version_range) {
						$affectedRange = [string]$v.vulnerable_version_range
					}
					if ($v.first_patched_version -and $v.first_patched_version.identifier) {
						$firstPatchedVersion = [string]$v.first_patched_version.identifier
					}

					if (-not $affectedPackage) {
						$affectedPackage = $packageName
					}

					$expanded += [PSCustomObject]@{
						RepositoryName             = $repositoryName
						RepositoryUrl              = $repositoryUrl
						FilePath                   = $filePath
						ProjectName                = $projectName
						ProjectKey                 = $projectKey
						Technology                 = $technology
						FrameworkName              = $frameworkName
						FrameworkFamily            = $frameworkFamily
						PackageName                = $packageName
						PackageVersion             = $packageVersion
						PackageVersionRaw          = $packageVersionRaw
						PackageVersionSource       = $packageVersionSource
						IsVersionPropertyReference = $isVersionPropertyRef
						IsVersionMissing           = $isVersionMissing
						PackageKey                 = $packageKey
						RepoPackageKey             = $repoPackageKey
						VulnerabilityId            = $vulnerabilityId
						GhsaId                     = $ghsaId
						CveId                      = $cveId
						AdvisorySource             = "GitHub Advisory Database"
						Severity                   = $severity
						CvssScore                  = $cvssScore
						CvssVector                 = $cvssVector
						EpssPercentage             = $epssPercentage
						AffectedPackage            = $affectedPackage
						AffectedEcosystem          = $affectedEcosystem
						AffectedRange              = $affectedRange
						FirstPatchedVersion        = $firstPatchedVersion
						PublishedDate              = $publishedDate
						UpdatedDate                = $updatedDate
						WithdrawnDate              = $withdrawnDate
						IsWithdrawn                = $isWithdrawn
						Summary                    = $summary
						Description                = $description
						ReferenceUrl               = $referenceUrl
						LookupStatus               = "Matched"
						ScanDate                   = $scanDate
					}
				}
			}
			else {
				$expanded += [PSCustomObject]@{
					RepositoryName             = $repositoryName
					RepositoryUrl              = $repositoryUrl
					FilePath                   = $filePath
					ProjectName                = $projectName
					ProjectKey                 = $projectKey
					Technology                 = $technology
					FrameworkName              = $frameworkName
					FrameworkFamily            = $frameworkFamily
					PackageName                = $packageName
					PackageVersion             = $packageVersion
					PackageVersionRaw          = $packageVersionRaw
					PackageVersionSource       = $packageVersionSource
					IsVersionPropertyReference = $isVersionPropertyRef
					IsVersionMissing           = $isVersionMissing
					PackageKey                 = $packageKey
					RepoPackageKey             = $repoPackageKey
					VulnerabilityId            = $vulnerabilityId
					GhsaId                     = $ghsaId
					CveId                      = $cveId
					AdvisorySource             = "GitHub Advisory Database"
					Severity                   = $severity
					CvssScore                  = $cvssScore
					CvssVector                 = $cvssVector
					EpssPercentage             = $epssPercentage
					AffectedPackage            = $packageName
					AffectedEcosystem          = "nuget"
					AffectedRange              = $null
					FirstPatchedVersion        = $null
					PublishedDate              = $publishedDate
					UpdatedDate                = $updatedDate
					WithdrawnDate              = $withdrawnDate
					IsWithdrawn                = $isWithdrawn
					Summary                    = $summary
					Description                = $description
					ReferenceUrl               = $referenceUrl
					LookupStatus               = "Matched"
					ScanDate                   = $scanDate
				}
			}
		}

		return $expanded
	}

	$seen = @{}

	foreach ($row in $packageRows) {
		$packageName = Get-SafeValue $row.PackageName
		$packageVersionRaw = Get-SafeValue $row.PackageVersionRaw
		$packageVersionSource = Get-SafeValue $row.PackageVersionSource

		$packageVersion = Get-SafeValue $row.PackageVersion
		if (-not $packageVersion) {
			$packageVersion = Normalize-PackageVersion -Version $packageVersionRaw
		}
		else {
			$packageVersion = Normalize-PackageVersion -Version $packageVersion
		}

		$lookupStatus = Get-LookupStatus -PackageVersion $packageVersion -PackageVersionRaw $packageVersionRaw -PackageVersionSource $packageVersionSource

		if ([string]::IsNullOrWhiteSpace($packageName)) {
			continue
		}

		# Ensure join keys exist even if source CSV did not have them
		if (-not $row.ProjectKey) {
			$row | Add-Member -NotePropertyName ProjectKey -NotePropertyValue ("{0}|{1}" -f $row.RepositoryName, $row.FilePath) -Force
		}

		if (-not $row.PackageKey) {
			$row | Add-Member -NotePropertyName PackageKey -NotePropertyValue ("{0}|{1}" -f $packageName, $packageVersion) -Force
		}

		if (-not $row.RepoPackageKey) {
			$row | Add-Member -NotePropertyName RepoPackageKey -NotePropertyValue ("{0}|{1}|{2}|{3}" -f $row.RepositoryName, $row.FilePath, $packageName, $packageVersionRaw) -Force
		}

		if ($lookupStatus -ne "Ready") {
			$results.Add([PSCustomObject]@{
				RepositoryName             = Get-SafeValue $row.RepositoryName
				RepositoryUrl              = Get-SafeValue $row.RepositoryUrl
				FilePath                   = Get-SafeValue $row.FilePath
				ProjectName                = Get-SafeValue $row.ProjectName
				ProjectKey                 = Get-SafeValue $row.ProjectKey
				Technology                 = Get-SafeValue $row.Technology
				FrameworkName              = Get-SafeValue $row.FrameworkName
				FrameworkFamily            = Get-SafeValue $row.FrameworkFamily
				PackageName                = $packageName
				PackageVersion             = $packageVersion
				PackageVersionRaw          = $packageVersionRaw
				PackageVersionSource       = $packageVersionSource
				IsVersionPropertyReference = Get-SafeValue $row.IsVersionPropertyReference
				IsVersionMissing           = Get-SafeValue $row.IsVersionMissing
				PackageKey                 = Get-SafeValue $row.PackageKey
				RepoPackageKey             = Get-SafeValue $row.RepoPackageKey
				VulnerabilityId            = $null
				GhsaId                     = $null
				CveId                      = $null
				AdvisorySource             = "GitHub Advisory Database"
				Severity                   = $null
				CvssScore                  = $null
				CvssVector                 = $null
				EpssPercentage             = $null
				AffectedPackage            = $packageName
				AffectedEcosystem          = "nuget"
				AffectedRange              = $null
				FirstPatchedVersion        = $null
				PublishedDate              = $null
				UpdatedDate                = $null
				WithdrawnDate              = $null
				IsWithdrawn                = $false
				Summary                    = $null
				Description                = $null
				ReferenceUrl               = $null
				LookupStatus               = $lookupStatus
				ScanDate                   = (Get-Date).ToString("yyyy-MM-dd")
			})
			continue
		}

		$cacheKey = "{0}|{1}" -f $packageName.ToLowerInvariant(), $packageVersion.ToLowerInvariant()

		if (-not $seen.ContainsKey($cacheKey)) {
			Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Looking up $packageName $packageVersion"

			try {
				$advisories = Invoke-GitHubGlobalAdvisoriesLookup -PackageName $packageName -PackageVersion $packageVersion
				$seen[$cacheKey] = $advisories
			}
			catch {
				Write-Warning "Lookup failed for $packageName $packageVersion : $_"
				$seen[$cacheKey] = "__LOOKUP_ERROR__"
			}
		}

		if ($seen[$cacheKey] -eq "__LOOKUP_ERROR__") {
			$results.Add([PSCustomObject]@{
				RepositoryName             = Get-SafeValue $row.RepositoryName
				RepositoryUrl              = Get-SafeValue $row.RepositoryUrl
				FilePath                   = Get-SafeValue $row.FilePath
				ProjectName                = Get-SafeValue $row.ProjectName
				ProjectKey                 = Get-SafeValue $row.ProjectKey
				Technology                 = Get-SafeValue $row.Technology
				FrameworkName              = Get-SafeValue $row.FrameworkName
				FrameworkFamily            = Get-SafeValue $row.FrameworkFamily
				PackageName                = $packageName
				PackageVersion             = $packageVersion
				PackageVersionRaw          = $packageVersionRaw
				PackageVersionSource       = $packageVersionSource
				IsVersionPropertyReference = Get-SafeValue $row.IsVersionPropertyReference
				IsVersionMissing           = Get-SafeValue $row.IsVersionMissing
				PackageKey                 = Get-SafeValue $row.PackageKey
				RepoPackageKey             = Get-SafeValue $row.RepoPackageKey
				VulnerabilityId            = $null
				GhsaId                     = $null
				CveId                      = $null
				AdvisorySource             = "GitHub Advisory Database"
				Severity                   = $null
				CvssScore                  = $null
				CvssVector                 = $null
				EpssPercentage             = $null
				AffectedPackage            = $packageName
				AffectedEcosystem          = "nuget"
				AffectedRange              = $null
				FirstPatchedVersion        = $null
				PublishedDate              = $null
				UpdatedDate                = $null
				WithdrawnDate              = $null
				IsWithdrawn                = $false
				Summary                    = $null
				Description                = $null
				ReferenceUrl               = $null
				LookupStatus               = "LookupError"
				ScanDate                   = (Get-Date).ToString("yyyy-MM-dd")
			})
			continue
		}

		$expandedRows = Expand-VulnerabilityRows -PackageRow $row -Advisories $seen[$cacheKey]
		foreach ($expanded in $expandedRows) {
			$results.Add($expanded)
		}
	}

	$results |
		Sort-Object RepositoryName, ProjectName, PackageName, PackageVersion, Severity, VulnerabilityId |
		Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8

	Write-Host "Vulnerability export completed. Results saved to $OutputCsvPath"
}


