<#
.SYNOPSIS
    This script is designed to be run during the Windows Setup OOBE (Out-of-Box Experience).
    It captures the device's hardware hash and uploads it to Microsoft Intune for Windows Autopilot registration.

.DESCRIPTION
    This script is built to be robust and work in minimal PowerShell environments like WinRE.
    1.  Forces the use of TLS 1.2 to ensure compatibility with modern web APIs.
    2.  Installs required PowerShell modules (Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement.Administration).
    3.  Installs the official 'Get-WindowsAutopilotInfo' script.
    4.  Connects to Microsoft Graph using an Azure AD App Registration (Service Principal).
    5.  Runs the 'Get-WindowsAutopilotInfo' script to generate the hardware hash CSV file.
    6.  Imports the hardware hash from the CSV into your Intune tenant.
    7.  Provides console output for each step and cleans up temporary files.

.PREREQUISITES
    - An active internet connection in the Windows PE/OOBE environment.
    - An Azure AD App Registration with the 'DeviceManagementServiceConfig.ReadWrite.All' Application permission granted.

.NOTES
    Author: Gemini
    Version: 1.1 (Added TLS 1.2 enforcement for compatibility with older PowerShell versions)
#>

#region Configuration - PASTE YOUR AZURE APP DETAILS HERE
# ------------------------------------------------------------------------------------
# IMPORTANT: Replace the placeholder values below with the details from the
# Azure AD App Registration you created in Step 1.
# ------------------------------------------------------------------------------------
$tenantID = "6b1311e5-123f-49db-acdf-8847c2d00bed"         # Paste your Directory (tenant) ID here
$appID    = "b432e847-4103-4c64-af21-8f5a71af6da5"    # Paste your Application (client) ID here
$appSecret = "V7i8Q~VbZEl5o4mlJ4sD5lX5djze0OrIfhHMEbDJ"    # Paste your Client Secret Value here
#endregion

#region Script Body (Do not edit below this line)

# --- Function to Write Colored Output ---
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

# --- Main Execution Block ---
try {
    Write-Log "Script starting. Ensuring PowerShell environment is ready." -Color Cyan

    # --- Step 1: Force TLS 1.2 Security Protocol ---
    # This is critical for older PowerShell versions to connect to PowerShell Gallery and Microsoft Graph.
    Write-Log "Forcing session to use TLS 1.2 for modern API compatibility."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # --- Step 2: Set Execution Policy and Install Modules ---
    Write-Log "Setting Execution Policy for this session."
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    Write-Log "Installing required PowerShell Package Provider (NuGet)."
    # Install the NuGet package provider without prompting for confirmation.
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue

    # --- Install required Microsoft Graph Modules ---
    $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement.Administration")
    foreach ($module in $requiredModules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Log "Module '$module' is already available."
        } else {
            Write-Log "Installing module '$module'..." -Color Yellow
            Install-Module $module -Force -Confirm:$false -AllowClobber -Scope CurrentUser
            Write-Log "Module '$module' installed successfully." -Color Green
        }
    }

    # --- Step 3: Connect to Microsoft Graph ---
    Write-Log "Authenticating to Microsoft Graph..." -Color Yellow
    # Convert the plain text secret to a secure string for the credential object
    $secureAppSecret = ConvertTo-SecureString -String $appSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $appID, $secureAppSecret

    # Connect using the service principal credentials
    Connect-MgGraph -TenantId $tenantID -Credential $credential
    Write-Log "Successfully connected to Microsoft Graph." -Color Green

    # --- Step 4: Get the Autopilot Hardware Hash ---
    $tempDirectory = "C:\TempHWID"
    Write-Log "Creating temporary directory: $tempDirectory"
    if (-not (Test-Path -Path $tempDirectory)) {
        New-Item -Path $tempDirectory -ItemType Directory | Out-Null
    }

    Write-Log "Installing the 'Get-WindowsAutopilotInfo' script..." -Color Yellow
    # Save the current directory, change to temp, and then change back.
    Push-Location
    Set-Location $tempDirectory
    Install-Script -Name Get-WindowsAutopilotInfo -Force -Confirm:$false -AllowClobber
    Pop-Location
    Write-Log "'Get-WindowsAutopilotInfo' script installed." -Color Green

    Write-Log "Running script to extract hardware hash..." -Color Yellow
    $hashCsvPath = "$tempDirectory\autopilot-hash.csv"
    # The script installs to a path that might not be in the default $env:PSModulePath for the session
    $autopilotScriptPath = "$env:USERPROFILE\Documents\WindowsPowerShell\Scripts\Get-WindowsAutopilotInfo.ps1"
    
    if (-not (Test-Path -Path $autopilotScriptPath)) {
        throw "Failed to find the Get-WindowsAutopilotInfo.ps1 script after installation."
    }

    & $autopilotScriptPath -OutputFile $hashCsvPath -Append
    
    if (-not (Test-Path -Path $hashCsvPath)) {
        throw "Hardware hash CSV file was not created. Cannot proceed."
    }
    Write-Log "Hardware hash successfully extracted to: $hashCsvPath" -Color Green

    # --- Step 5: Import the Hash into Intune ---
    Write-Log "Reading hash file and preparing to upload to Intune..." -Color Yellow
    $devices = Import-Csv -Path $hashCsvPath
    
    foreach ($device in $devices) {
        $serialNumber = $device.'Serial Number'
        Write-Log "Importing device with Serial Number: $serialNumber"
        
        # Using the newer Import-AutopilotDeviceIdentity cmdlet from the Microsoft.Graph.DeviceManagement.Administration module
        Import-AutopilotDeviceIdentity -SerialNumber $serialNumber -HardwareIdentifier $device.'Hardware Hash' -ProductKey $device.'Product Key'
        
        Write-Log "Successfully submitted import request for device: $serialNumber" -Color Green
    }

    # --- Step 6: Cleanup ---
    Write-Log "Cleaning up temporary files and directory..."
    Remove-Item -Path $tempDirectory -Recurse -Force
    Write-Log "Cleanup complete."

    Write-Log "PROCESS COMPLETE. The device hash has been uploaded to Intune. It may take up to 15 minutes to appear in the Autopilot devices list." -Color Cyan
    Write-Log "You can now restart the machine (e.g., by typing 'shutdown /r /t 0' and pressing Enter)." -Color Cyan

} catch {
    # --- Error Handling ---
    Write-Log "AN ERROR OCCURRED:" -Color Red
    Write-Log $_.Exception.Message -Color Red
    # Pause the script so the error can be read
    Read-Host "Press Enter to exit..."
}
#endregion
