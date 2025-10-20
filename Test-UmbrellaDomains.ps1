<#
.SYNOPSIS
    Tests whether domains are allowed, blocked, or not found when resolved through Cisco Umbrella/OpenDNS.

.DESCRIPTION
    Reads a CSV file that contains a column of domain names (defaults to a column named "Url").
    Each domain is resolved using the Cisco Umbrella/OpenDNS resolver (default 208.67.222.222) and
    is classified as Allowed, Blocked, or NotFound based on the response. Results are displayed in a
    colorized table. Output can be filtered with the -Allowed, -Blocked, or -NotFound switches. Domains
    can also be supplied directly via the -Domains parameter for quick one-off tests.

.PARAMETER InputCsv
    Path to the CSV file that contains domains to test. The file must contain at least one column.

.PARAMETER DomainColumn
    Name of the CSV column that contains the domain values. Defaults to "Url". If the column is not
    present, the first column in the file is used.

.PARAMETER Domains
    One or more domains to test directly without using a CSV input file. This is useful for quickly
    validating a handful of URLs from the command line.

.PARAMETER Allowed
    When supplied, only outputs entries that resolved to an allowed destination.

.PARAMETER Blocked
    When supplied, only outputs entries that were blocked by Umbrella/OpenDNS.

.PARAMETER NotFound
    When supplied, only outputs entries that could not be resolved (NXDOMAIN).

.PARAMETER DnsServer
    Umbrella/OpenDNS resolver to query. Defaults to 208.67.222.222.

.EXAMPLE
    PS> .\Test-UmbrellaDomains.ps1 -InputCsv .\domains.csv

    Tests each domain in domains.csv and outputs the full table of results.

.EXAMPLE
    PS> .\Test-UmbrellaDomains.ps1 -InputCsv .\domains.csv -Blocked -Allowed

    Outputs only the domains that were either blocked or allowed, excluding any that could not be found.

.EXAMPLE
    PS> .\Test-UmbrellaDomains.ps1 -Domains 'google.com','example.com'

    Quickly checks the supplied domains without creating a CSV file.
#>

[CmdletBinding(DefaultParameterSetName = 'FromCsv')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'FromCsv')]
    [string]$InputCsv,

    [Parameter(ParameterSetName = 'FromCsv')]
    [string]$DomainColumn = 'Url',

    [Parameter(Mandatory = $true, ParameterSetName = 'FromList')]
    [string[]]$Domains,

    [Parameter()]
    [switch]$Allowed,

    [Parameter()]
    [switch]$Blocked,

    [Parameter()]
    [switch]$NotFound,

    [Parameter()]
    [string]$DnsServer = '208.67.222.222'
)

$blockAddresses = @(
    '146.112.61.104',
    '146.112.61.105',
    '146.112.61.106',
    '146.112.61.107',
    '146.112.61.108',
    '146.112.61.109',
    '146.112.61.110',
    '146.112.61.111',
    '146.112.61.112'
)

function Get-DomainClassification {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $cleanDomain = $Domain.Trim()
    $cleanDomain = $cleanDomain -replace '^(https?://)', ''
    $cleanDomain = $cleanDomain -replace '/.*$', ''

    if ([string]::IsNullOrWhiteSpace($cleanDomain)) {
        return $null
    }

    try {
        $resolution = Resolve-DnsName -Name $cleanDomain -Server $DnsServer -Type A -ErrorAction Stop
        $records = @($resolution)

        $aRecords = $records | Where-Object { $_.Type -eq 'A' }
        $cnameRecords = $records | Where-Object { $_.Type -eq 'CNAME' }

        $blocked = $false

        if ($aRecords) {
            $blockedAddresses = $aRecords | Where-Object { $blockAddresses -contains $_.IPAddress }
            if ($blockedAddresses) {
                $blocked = $true
            }
        }

        if (-not $blocked -and $cnameRecords) {
            $blockedCnames = $cnameRecords | Where-Object { $_.NameHost -match 'hit-block\.opendns\.com' }
            if ($blockedCnames) {
                $blocked = $true
            }
        }

        if ($blocked) {
            return [PSCustomObject]@{
                Url    = $cleanDomain
                Status = 'Blocked'
            }
        } else {
            return [PSCustomObject]@{
                Url    = $cleanDomain
                Status = 'Allowed'
            }
        }
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'DNS name does not exist' -or $message -match 'NXDOMAIN') {
            return [PSCustomObject]@{
                Url    = $cleanDomain
                Status = 'NotFound'
            }
        }

        return [PSCustomObject]@{
            Url    = $cleanDomain
            Status = 'Error'
            Detail = $message
        }
    }
}

$results = $null
switch ($PSCmdlet.ParameterSetName) {
    'FromCsv' {
        if (-not (Test-Path -LiteralPath $InputCsv)) {
            throw "Input CSV '$InputCsv' was not found."
        }

        try {
            $csvData = Import-Csv -LiteralPath $InputCsv
        } catch {
            throw "Failed to import CSV '$InputCsv': $($_.Exception.Message)"
        }

        if (-not $csvData) {
            Write-Warning "No data found in '$InputCsv'."
            return
        }

        $availableColumns = $csvData[0].PSObject.Properties.Name
        $selectedColumn = $DomainColumn

        if (-not ($availableColumns -contains $DomainColumn)) {
            $selectedColumn = $availableColumns | Select-Object -First 1
            if (-not $selectedColumn) {
                throw "The CSV file does not contain any columns to process."
            }
            if ($DomainColumn -ne $selectedColumn) {
                Write-Warning "Column '$DomainColumn' was not found. Using first column '$selectedColumn'."
            }
        }

        $results = foreach ($row in $csvData) {
            $rawDomain = $row.$selectedColumn
            if ([string]::IsNullOrWhiteSpace($rawDomain)) {
                continue
            }

            Get-DomainClassification -Domain $rawDomain
        }
    }
    'FromList' {
        $results = foreach ($domain in $Domains) {
            if ([string]::IsNullOrWhiteSpace($domain)) {
                continue
            }

            Get-DomainClassification -Domain $domain
        }
    }
    default {
        throw 'Unsupported parameter set.'
    }
}

if (-not $results) {
    Write-Warning 'No valid domains were processed.'
    return
}

$desiredStatuses = @()
if ($Allowed) { $desiredStatuses += 'Allowed' }
if ($Blocked) { $desiredStatuses += 'Blocked' }
if ($NotFound) { $desiredStatuses += 'NotFound' }

if ($desiredStatuses.Count -gt 0) {
    $results = $results | Where-Object { $desiredStatuses -contains $_.Status }
}

if (-not $results) {
    Write-Warning 'No results matched the selected status filters.'
    return
}

$maxUrlLength = ($results | Measure-Object -Property Url -Maximum).Maximum
if (-not $maxUrlLength) { $maxUrlLength = 3 }

$headerUrl = 'URL'
$headerStatus = 'Status'
$formatString = "{0,-$maxUrlLength}  {1}"
$dividerLength = [Math]::Max($headerUrl.Length, $maxUrlLength)
$divider = ('-' * $dividerLength) + '  ' + ('-' * $headerStatus.Length)

Write-Host ($formatString -f $headerUrl, $headerStatus) -ForegroundColor White
Write-Host $divider -ForegroundColor White

foreach ($item in $results) {
    $color = switch ($item.Status) {
        'Allowed'  { 'Green' }
        'Blocked'  { 'Red' }
        'NotFound' { 'Blue' }
        default    { 'Yellow' }
    }

    Write-Host ($formatString -f $item.Url, $item.Status) -ForegroundColor $color
}
