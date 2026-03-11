# Read in the file path from the command line
param (
    [Parameter(Mandatory=$true)][string]$FilePath
)

# Read in CPE strings from txt file in same directory
$FileContents = Get-Content -Path $FilePath
 
# declare variables to be used during loop
$i = 0
$MaxData = [ordered]@{}
$CpeToCveLookup = @{}
$arr = @()

# Read the file line by line FOR Cpe Name strings
ForEach ($Line in $FileContents) {
    $max = 0
    # Create the necessary URL
    $URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$Line&isVulnerable"

    # Use the stored CPE strings to retrieve any vulnerabilities
    try {
        $AllRetrievedCVEs = Invoke-RestMethod -Uri $URL
    } catch {
        Write-Host "Status Code:" $_.Exception.Response.StatusCode.value__
        Write-Host "CPE Name: " $Line 
    }
    
    # grab the desired information from the vulenrability object
    if (@(AllRetrievedCVEs.vulnerabilities).Count -gt 0) {
        foreach ($item in $AllRetrievedCVEs.vulnerabilities) {
            $cve = $item.cve
            if ($cve.metrics.cvssMetricV31)
            {
                if ($cve.metrics.cvssMetricV31[0].cvssData.baseScore -gt $max) {
                    $max = $cve.metrics.cvssMetricV31[0].cvssData.baseScore
                    $arr = @($cve.id, $cve.metrics.cvssMetricV31[0].cvssData.baseScore, $cve.metrics.cvssMetricV31[0].cvssData.vectorString)
                    $MaxData[$Line] = $arr
                    $CpeToCveLookup[$cve.id] = $Line
                }
                
            }
            elseif ($cve.metrics.cvssMetricV31)
            {
                if ($cve.metrics.cvssMetricV31[0].cvssData.baseScore -gt $max) {
                    $max = $cve.metrics.cvssMetricV31[0].cvssData.baseScore
                    $arr = @($cve.id, $cve.metrics.cvssMetricV31[0].cvssData.baseScore, $cve.metrics.cvssMetricV31[0].cvssData.vectorString)
                    $MaxData[$Line] = $arr
                    $CpeToCveLookup[$cve.id] = $Line
                }
                
            }
            elseif ($cve.metrics.cvssMetricV30)
            {

                if ($cve.metrics.cvssMetricV30[0].cvssData.baseScore -gt $max) {
                    $max = $cve.metrics.cvssMetricV30[0].cvssData.baseScore
                    $arr = @($cve.id, $cve.metrics.cvssMetricV30[0].cvssData.baseScore, $cve.metrics.cvssMetricV30[0].cvssData.vectorString)
                    $MaxData[$Line] = $arr
                    $CpeToCveLookup[$cve.id] = $Line
                }
            }
            else {
                if ($cve.metrics.cvssMetricV2[0].cvssData.baseScore -gt $max) {
                    $max = $cve.metrics.cvssMetricV2[0].cvssData.baseScore
                    $arr = @($cve.id, $cve.metrics.cvssMetricV2[0].cvssData.baseScore, $cve.metrics.cvssMetricV2[0].cvssData.vectorString)
                    $MaxData[$Line] = $arr
                    $CpeToCveLookup[$cve.id] = $Line
                }
            }
        } # end of inner for loop
    } # end of if statements to check for found CVEs

    # increment i for next loop and sleep program as requested by the NVD API
    if ($i -gt 0) {
        Start-Sleep -Seconds 6
    }
    $i++
}
    
# build the URL for the EPSS scores
$EpssUrl = "https://api.first.org/data/v1/epss?cve="
$tracker = 1
foreach($key in $MaxData.Keys) {
    switch ($MaxData.Count) {
        {$_ -eq 1} {
            $EpssUrl += $MaxData[$key][0]
            break
        }
        {$_ -gt $tracker} {
            $EpssUrl += $MaxData[$key][0] + ","
            break
        }
        {$_ -eq $tracker} {
            $EpssUrl += $MaxData[$key][0]
            break
        }
    }
    $tracker++
}

# fetch the EPSS score based on the CVE-ID
try {
    $EpssScores = Invoke-RestMethod -Uri $EpssUrl
} catch {
    Write-Host "Status Code: " $_.Exception.Response.StatusCode.value__
}

# loop through the returned API data and store them in the data hashmap
foreach ($item in $EpssScores.data) {
    $MaxData[$CpeToCveLookup[$item.cve]] += $item.epss
}

# output the final results
foreach ($key in $MaxData.Keys) {
    Write-Host $key ": " $MaxData[$key]
}

