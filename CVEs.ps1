# Read in the file path from the command line
param (
    [Parameter(Mandatory=$true)][string]$FilePath
)

# Read in CPE strings from txt file in same directory
$FileContents = Get-Content -Path $FilePath
 
# declare variables to be used during loop
$i = 0
$data = @{};

# Read the file line by line FOR Cpe Name strings
ForEach ($Line in $FileContents) {

    # Create the necessary URL
    $URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$Line&isVulnerable"

    # Use the stored CPE strings to retrieve any vulnerabilities
    $AllRetrievedCVEs = Invoke-RestMethod -Uri $URL
    
    # grab the desired information from the vulenrability object
    foreach ($item in $AllRetrievedCVEs.vulnerabilities) {
        $cve = $item.cve
        $data[$cve.id] = @($cve.id, $cve.published)
        
        if ($cve.metrics.cvssMetricV31)
        {
            $data[$cve.id] += @($cve.metrics.cvssMetricV31[0].cvssData.baseScore, $cve.metrics.cvssMetricV31[0].cvssData.vectorString)
        }
        elseif ($cve.metrics.cvssMetricV30)
        {
            $data[$cve.id] += @($cve.metrics.cvssMetricV30[0].cvssData.baseScore, $cve.metrics.cvssMetricV30[0].cvssData.vectorString)
        }
        else {
            $data[$cve.id] += @($cve.metrics.cvssMetricV2[0].cvssData.baseScore, $cve.metrics.cvssMetricV2[0].cvssData.vectorString)
        }
    }
    
    # fetch the EPSS score based on the CVE-ID

    # increment i for next loop and sleep program as requested by the NVD API
    if ($i -gt 0) 
    {
        Start-Sleep -Seconds 6
    }
    $i++
}

$data | Format-Table