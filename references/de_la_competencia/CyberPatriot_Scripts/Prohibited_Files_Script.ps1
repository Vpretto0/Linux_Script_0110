# Define file types to search and keywords
$prohibitedExtensions = @("*.mp3", "*.mp4")
$prohibitedKeywords = @("hacker", "tool")
$reportPath = "C:\ProhibitedFilesReport.txt"

# Start logging
"Prohibited Files Report - Generated on $(Get-Date)" | Out-File -FilePath $reportPath
Add-Content -Path $reportPath -Value "==================================================="

# Function to delete files and log the action
function DeleteFile {
    param (
        [string]$filePath
    )
    try {
        # Delete the file
        Remove-Item -Path $filePath -Force
        Write-Host "Deleted: $filePath"
        
        # Log the action
        Add-Content -Path $reportPath -Value "Deleted: $filePath"
    } catch {
        Write-Host "Failed to delete: $filePath"
        Add-Content -Path $reportPath -Value "Failed to delete: $filePath. Error: $_"
    }
}

# Search and delete prohibited extensions
Write-Host "Searching for prohibited file extensions..."
foreach ($ext in $prohibitedExtensions) {
    Add-Content -Path $reportPath -Value "`nSearching for $ext files:"
    Get-ChildItem -Path C:\ -Recurse -Include $ext -ErrorAction SilentlyContinue |
        ForEach-Object {
            DeleteFile -filePath $_.FullName
        }
}

# Search and delete files containing prohibited keywords
Write-Host "Searching for prohibited keywords..."
foreach ($keyword in $prohibitedKeywords) {
    Add-Content -Path $reportPath -Value "`nSearching for files containing keyword: $keyword"
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
        Select-String -Pattern $keyword -SimpleMatch |
        ForEach-Object {
            DeleteFile -filePath $_.Path
        }
}

# Search and delete hidden files
Write-Host "Searching for hidden files..."
Add-Content -Path $reportPath -Value "`nSearching for hidden files:"
Get-ChildItem -Path C:\ -Recurse -Attributes Hidden -ErrorAction SilentlyContinue |
    ForEach-Object {
        DeleteFile -filePath $_.FullName
    }

# Search and delete system files
Write-Host "Searching for system files..."
Add-Content -Path $reportPath -Value "`nSearching for system files:"
Get-ChildItem -Path C:\ -Recurse -Attributes System -ErrorAction SilentlyContinue |
    ForEach-Object {
        DeleteFile -filePath $_.FullName
    }

# Finalize
Write-Host "Search and delete process complete. Report saved to $reportPath"
Add-Content -Path $reportPath -Value "`nProcess complete."