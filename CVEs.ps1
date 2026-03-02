# Read in the file path from the command line
param (
    [Parameter(Mandatory=$true)][string]$FilePath
)

# Read in CPE strings from txt file in same directory
$FileContents = Get-Content -Path $FilePath
 
$i = 1
# Read the file line by line FOR Cpe Name strings
ForEach ($Line in $FileContents) {
    # Process each line here
    Write-Host "Line# $i :" $Line

    # Create the necessary URL
    $URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$Line&isVulnerable"

    # Use the stored CPE strings to retrieve any vulnerabilities
    $AllRetrievedCVEs = Invoke-RestMethod -Uri $URL
    
    # grab the desired information from the vulenrability object
    foreach ($item in $AllRetrievedCVEs.vulnerabilities) {
        $cve = $item.cve
        Write-Host $cve.id
    }

    # increment i for next loop and sleep program as requested by the NVD API
    $i++
    Start-Sleep -Seconds 6
}