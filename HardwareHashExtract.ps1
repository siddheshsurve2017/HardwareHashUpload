<#
.SYNOPSIS
    This script is designed to be run during the Windows Setup OOBE (Out-of-Box Experience).
    It captures the device's hardware hash and uploads it to Microsoft Intune for Windows Autopilot registration.

.DESCRIPTION
    This script is built to be robust and work in minimal PowerShell environments like WinRE.
    It is secure for public hosting as it prompts for the App Secret at runtime.
    1.  Forces the use of TLS 1.2 to ensure compatibility with modern web APIs.
    2.  Prompts the user to securely enter the Client Secret (App Secret).
    3.  Installs required PowerShell modules (Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement.Administration).
    4.  Installs the official 'Get-WindowsAutopilotInfo' script.
    5.  Connects to Microsoft Graph using an Azure AD App Registration (Service Principal).
    6.  Runs the 'Get-WindowsAutopilotInfo' script to generate the hardware hash CSV file.
    7.  Imports the hardware hash from the CSV into your Intune tenant.
    8.  Provides console output for each step and cleans up temporary files.

.PREREQUISITES
    - An active internet connection in the Windows PE/OOBE environment.
    - An Azure AD App Registration with the 'DeviceManagementServiceConfig.ReadWrite.All' Application permission granted.

.NOTES
    Author: Gemini
    Version: 2.0 (Prompts for secret, secure for public hosting)
#>

#region Configuration - PASTE YOUR AZURE APP DETAILS HERE
# ------------------------------------------------------------------------------------
# IMPORTANT: Replace the placeholder values below with the details from the
# Azure AD App Registration you created. The App Secret is handled securely below.
# ------------------------------------------------------------------------------------
$tenantID = "6b1311e5-123f-49db-acdf-8847c2d00bed"         # Paste your Directory (tenant) ID here
$appID    = "b432e847-4103-4c64-af21-8f5a71af6da5"    # Paste your Application (client) ID here
# The App Secret is no longer stored here for security.
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

    # --- Step 1: Securely Prompt for the Client Secret ---
    Write-Log "Please enter the Client Secret (App Secret) for the Azure AD App." -Color Yellow
    # We need the plain text secret for the web request body, so we can't use -AsSecureString here.
    # The script is running in a temporary, non-persistent environment, making this an acceptable risk.
    $appSecret = Read-Host
    Write-Log "Secret received. Continuing with script..."

    # --- Step 2: Force TLS 1.2 Security Protocol ---
    Write-Log "Forcing session to use TLS 1.2 for modern API compatibility."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # --- Step 3: Set Execution Policy and Install Prereqs ---
    Write-Log "Setting Execution Policy for this session."
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    Write-Log "Installing required PowerShell Package Provider (NuGet)."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
    
    # --- Step 4: Get the Autopilot Hardware Hash ---
    $tempDirectory = "C:\TempHWID"
    Write-Log "Creating temporary directory: $tempDirectory"
    if (-not (Test-Path -Path $tempDirectory)) {
        New-Item -Path $tempDirectory -ItemType Directory | Out-Null
    }

    Write-Log "Installing the 'Get-WindowsAutopilotInfo' script..." -Color Yellow
    Install-Script -Name Get-WindowsAutopilotInfo -Force -Confirm:$false
    Write-Log "'Get-WindowsAutopilotInfo' script installed." -Color Green

    Write-Log "Running script to extract hardware hash..." -Color Yellow
    $hashCsvPath = "$tempDirectory\autopilot-hash.csv"
    $autopilotScriptPath = "$env:USERPROFILE\Documents\WindowsPowerShell\Scripts\Get-WindowsAutopilotInfo.ps1"
    
    if (-not (Test-Path -Path $autopilotScriptPath)) {
        $autopilotScriptPath = "$env:ProgramFiles\WindowsPowerShell\Scripts\Get-WindowsAutopilotInfo.ps1"
        if (-not (Test-Path -Path $autopilotScriptPath)){
             throw "Failed to find the Get-WindowsAutopilotInfo.ps1 script after installation."
        }
    }

    & $autopilotScriptPath -OutputFile $hashCsvPath -Append
    
    if (-not (Test-Path -Path $hashCsvPath)) {
        throw "Hardware hash CSV file was not created. Cannot proceed."
    }
    $deviceInfo = Import-Csv -Path $hashCsvPath | Select-Object -First 1
    Write-Log "Hardware hash successfully extracted for Serial Number: $($deviceInfo.'Serial Number')" -Color Green

    # --- Step 5: Authenticate to Microsoft Graph ---
    Write-Log "Authenticating to Microsoft Graph to get access token..." -Color Yellow
    $authUrl = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
    $authBody = @{
        client_id     = $appID
        client_secret = $appSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    $authResponse = Invoke-RestMethod -Method Post -Uri $authUrl -Body $authBody -ErrorAction Stop
    $accessToken = $authResponse.access_token
    Write-Log "Successfully obtained Graph API Access Token." -Color Green

    # --- Step 6: Import the Hash into Intune via REST API ---
    Write-Log "Preparing to upload hash to Intune via REST API..." -Color Yellow
    $apiUrl = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities"
    
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    $jsonBody = @{
        "@odata.type"          = "#microsoft.graph.importedWindowsAutopilotDeviceIdentity"
        "groupTag"             = ""
        "serialNumber"         = $deviceInfo.'Serial Number'
        "productKey"           = $deviceInfo.'Product Key'
        "hardwareIdentifier"   = $deviceInfo.'Hardware Hash'
        "state"                = @{
            "@odata.type" = "microsoft.graph.importedWindowsAutopilotDeviceIdentityState"
            "deviceImportStatus" = "pending"
            "deviceRegistrationId" = ""
            "deviceErrorCode" = 0
            "deviceErrorName" = ""
        }
    } | ConvertTo-Json -Depth 5

    Write-Log "Uploading device with Serial Number: $($deviceInfo.'Serial Number')"
    Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $jsonBody -ErrorAction Stop
    Write-Log "Successfully submitted import request for device: $($deviceInfo.'Serial Number')" -Color Green

    # --- Step 7: Cleanup ---
    Write-Log "Cleaning up temporary files and directory..."
    Remove-Item -Path $tempDirectory -Recurse -Force
    Write-Log "Cleanup complete."

    Write-Log "PROCESS COMPLETE. The device hash has been uploaded to Intune. It may take up to 15 minutes to appear in the Autopilot devices list." -Color Cyan
    Write-Log "You can now restart the machine (e.g., by typing 'shutdown /r /t 0' and pressing Enter)." -Color Cyan

} catch {
    # --- Error Handling ---
    Write-Log "AN ERROR OCCURRED:" -Color Red
    Write-Log $_.Exception.Message -Color Red
    if ($_.Exception.Response) {
        $errorResponse = $_.Exception.Response.GetResponseStream()
        $streamReader = New-Object System.IO.StreamReader($errorResponse)
        $errorBody = $streamReader.ReadToEnd()
        Write-Log "Error Details: $errorBody" -Color Red
    }
    Read-Host "Press Enter to exit..."
}
#endregion
