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
    $appSecret = Read-Host -AsSecureString
    Write-Log "Secret received. Continuing with script..."

    # --- Step 2: Force TLS 1.2 Security Protocol ---
    Write-Log "Forcing session to use TLS 1.2 for modern API compatibility."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # --- Step 3: Set Execution Policy and Install Modules ---
    Write-Log "Setting Execution Policy for this session."
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    Write-Log "Installing required PowerShell Package Provider (NuGet)."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue

    # --- Uninstall any existing versions to ensure a clean slate ---
    Write-Log "Uninstalling any existing Graph modules to prevent conflicts..."
    Uninstall-Module -Name Microsoft.Graph.DeviceManagement.Administration -AllVersions -Force -ErrorAction SilentlyContinue
    Uninstall-Module -Name Microsoft.Graph.Authentication -AllVersions -Force -ErrorAction SilentlyContinue

    # --- Install specific older, more compatible versions of the modules ---
    $moduleVersion = "1.9.6"
    Write-Log "Installing specific module version $moduleVersion for maximum compatibility." -Color Yellow
    Install-Module -Name Microsoft.Graph.Authentication -RequiredVersion $moduleVersion -Force -Confirm:$false -Scope CurrentUser -AcceptLicense
    Install-Module -Name Microsoft.Graph.DeviceManagement.Administration -RequiredVersion $moduleVersion -Force -Confirm:$false -Scope CurrentUser -AcceptLicense
    Write-Log "Modules installed successfully." -Color Green
    
    # --- Explicitly import modules by full path to ensure they are loaded ---
    Write-Log "Force-importing necessary modules into the session..."
    $moduleNames = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement.Administration")
    foreach ($name in $moduleNames) {
        $moduleInfo = Get-Module -ListAvailable -Name $name | Where-Object { $_.Version -eq $moduleVersion } | Select-Object -First 1
        if ($moduleInfo) {
            Write-Log "Found '$name' version $($moduleInfo.Version) at $($moduleInfo.Path). Importing..." -Color Cyan
            Import-Module -Name $moduleInfo.Path -Force
        } else {
            throw "CRITICAL: Module '$name' version $moduleVersion not found after installation."
        }
    }

    # --- Verify that the critical command is now available ---
    Write-Log "Verifying cmdlet availability..."
    if (-not (Get-Command -Name Import-AutopilotDeviceIdentity -ErrorAction SilentlyContinue)) {
        throw "CRITICAL: The 'Import-AutopilotDeviceIdentity' cmdlet is still not available after module installation and import. Cannot proceed."
    }
    Write-Log "Cmdlet verified successfully." -Color Green

    # --- Step 4: Connect to Microsoft Graph ---
    Write-Log "Authenticating to Microsoft Graph..." -Color Yellow
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $appID, $appSecret

    Connect-MgGraph -TenantId $tenantID -Credential $credential
    Write-Log "Successfully connected to Microsoft Graph." -Color Green

    # --- Step 5: Get the Autopilot Hardware Hash ---
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
    Write-Log "Hardware hash successfully extracted to: $hashCsvPath" -Color Green

    # --- Step 6: Import the Hash into Intune ---
    Write-Log "Reading hash file and preparing to upload to Intune..." -Color Yellow
    $devices = Import-Csv -Path $hashCsvPath
    
    foreach ($device in $devices) {
        $serialNumber = $device.'Serial Number'
        Write-Log "Importing device with Serial Number: $serialNumber"
        Import-AutopilotDeviceIdentity -SerialNumber $serialNumber -HardwareIdentifier $device.'Hardware Hash' -ProductKey $device.'Product Key'
        Write-Log "Successfully submitted import request for device: $serialNumber" -Color Green
    }

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
    Read-Host "Press Enter to exit..."
}
#endregion
