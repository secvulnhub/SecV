# MACPOOF - Cross-Platform MAC Address Spoofer
# PowerShell version with Windows-specific enhancements

param(
    [string]$Interface = "",
    [string]$MacAddress = "",
    [switch]$Random,
    [switch]$List,
    [switch]$Help
)

# Display banner and system information
function Show-Banner {
    Write-Host "Welcome to MACPOOF (PowerShell version) $env:USERNAME" -ForegroundColor Cyan
    Write-Host "Operating System: $($PSVersionTable.OS)" -ForegroundColor Green
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    Write-Host ""
}

# Display help information
function Show-Help {
    Write-Host @"
MACPOOF - MAC Address Spoofer

USAGE:
    .\macpoof.ps1 [-Interface <name>] [-MacAddress <mac>] [-Random] [-List] [-Help]

PARAMETERS:
    -Interface    : Network interface name to modify
    -MacAddress   : New MAC address (format: aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff)
    -Random       : Generate a random MAC address
    -List         : List all available network interfaces
    -Help         : Show this help message

EXAMPLES:
    .\macpoof.ps1 -List
    .\macpoof.ps1 -Interface "Ethernet" -MacAddress "aa:bb:cc:dd:ee:ff"
    .\macpoof.ps1 -Interface "Wi-Fi" -Random
    .\macpoof.ps1
"@ -ForegroundColor Yellow
}

# Function to validate MAC address format and normalize it
function Test-MacAddress {
    param([string]$MacAddress)
    
    # Remove whitespace and convert to lowercase
    $mac = $MacAddress.Trim().ToLower()
    
    # Define regex patterns for MAC address validation
    $colonPattern = '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    $dashPattern = '^([0-9a-f]{2}-){5}[0-9a-f]{2}$'
    
    if ($mac -match $colonPattern) {
        return @{
            IsValid = $true
            NormalizedMac = $mac
        }
    }
    elseif ($mac -match $dashPattern) {
        # Convert dash format to colon format
        $normalizedMac = $mac -replace '-', ':'
        Write-Host "Converting dash format to colon format: $normalizedMac" -ForegroundColor Yellow
        return @{
            IsValid = $true
            NormalizedMac = $normalizedMac
        }
    }
    else {
        return @{
            IsValid = $false
            NormalizedMac = $null
        }
    }
}

# Function to generate a random locally administered MAC address
function New-RandomMacAddress {
    # Generate 6 random bytes
    $macBytes = @()
    for ($i = 0; $i -lt 6; $i++) {
        $macBytes += Get-Random -Minimum 0 -Maximum 256
    }
    
    # Set the locally administered bit (bit 1 of first byte) to 1
    # and ensure it's unicast (bit 0 of first byte) by setting it to 0
    $macBytes[0] = ($macBytes[0] -bor 0x02) -band 0xFE
    
    # Format as MAC address string
    $macString = ($macBytes | ForEach-Object { "{0:x2}" -f $_ }) -join ":"
    
    return $macString
}

# Function to get all network adapters with enhanced information
function Get-NetworkAdapters {
    try {
        # Get network adapters using WMI for comprehensive information
        $adapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { 
            $_.NetEnabled -eq $true -and 
            $_.AdapterTypeId -ne $null -and
            $_.MACAddress -ne $null
        }
        
        $adapterInfo = @()
        foreach ($adapter in $adapters) {
            # Get additional configuration information
            $config = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { 
                $_.Index -eq $adapter.Index 
            }
            
            $adapterInfo += [PSCustomObject]@{
                Name = $adapter.Name
                NetConnectionID = $adapter.NetConnectionID
                MACAddress = $adapter.MACAddress
                AdapterType = $adapter.AdapterType
                Status = $adapter.NetConnectionStatus
                DeviceID = $adapter.DeviceID
                Index = $adapter.Index
                IPEnabled = $config.IPEnabled
                DHCPEnabled = $config.DHCPEnabled
            }
        }
        
        return $adapterInfo
    }
    catch {
        Write-Error "Failed to retrieve network adapters: $_"
        return @()
    }
}

# Function to display network interfaces in a user-friendly format
function Show-NetworkInterfaces {
    $adapters = Get-NetworkAdapters
    
    if ($adapters.Count -eq 0) {
        Write-Host "No network adapters found." -ForegroundColor Red
        return
    }
    
    Write-Host "Available Network Interfaces:" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Gray
    
    $index = 1
    foreach ($adapter in $adapters) {
        $status = switch ($adapter.Status) {
            2 { "Connected" }
            7 { "Disconnected" }
            default { "Unknown" }
        }
        
        Write-Host "[$index] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($adapter.NetConnectionID)" -ForegroundColor White
        Write-Host "    Name: $($adapter.Name)" -ForegroundColor Gray
        Write-Host "    MAC Address: $($adapter.MACAddress)" -ForegroundColor Green
        Write-Host "    Status: $status" -ForegroundColor $(if ($status -eq "Connected") { "Green" } else { "Red" })
        Write-Host "    Type: $($adapter.AdapterType)" -ForegroundColor Gray
        Write-Host ""
        $index++
    }
}

# Function to find network adapter by name or connection ID
function Find-NetworkAdapter {
    param([string]$InterfaceName)
    
    $adapters = Get-NetworkAdapters
    
    # Try to find by NetConnectionID first (more user-friendly)
    $adapter = $adapters | Where-Object { $_.NetConnectionID -eq $InterfaceName }
    
    # If not found, try by adapter name
    if (-not $adapter) {
        $adapter = $adapters | Where-Object { $_.Name -like "*$InterfaceName*" }
    }
    
    # If still not found, try by index if it's a number
    if (-not $adapter -and $InterfaceName -match '^\d+) {
        $adapterIndex = [int]$InterfaceName - 1
        $adaptersArray = @($adapters)
        if ($adapterIndex -ge 0 -and $adapterIndex -lt $adaptersArray.Count) {
            $adapter = $adaptersArray[$adapterIndex]
        }
    }
    
    return $adapter
}

# Function to change MAC address on Windows using registry method
function Set-MacAddressWindows {
    param(
        [string]$DeviceID,
        [string]$NewMacAddress
    )
    
    try {
        # Convert MAC address to registry format (remove colons, uppercase)
        $registryMac = $NewMacAddress -replace ':', '' -replace '-', ''
        $registryMac = $registryMac.ToUpper()
        
        # Registry path for network adapters
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        
        # Find the specific adapter's registry key
        $adapterKeys = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -match '\d{4} }
        
        foreach ($key in $adapterKeys) {
            $keyPath = $key.PSPath
            try {
                $driverDesc = Get-ItemProperty -Path $keyPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                $instanceId = Get-ItemProperty -Path $keyPath -Name "MatchingDeviceId" -ErrorAction SilentlyContinue
                
                # Check if this is our target adapter
                if ($driverDesc -and $instanceId) {
                    # Set the NetworkAddress value (this is the MAC address override)
                    Set-ItemProperty -Path $keyPath -Name "NetworkAddress" -Value $registryMac -Type String
                    Write-Host "Registry updated for adapter: $($driverDesc.DriverDesc)" -ForegroundColor Green
                    return $true
                }
            }
            catch {
                # Skip this key if we can't access it
                continue
            }
        }
        
        Write-Host "Could not find adapter in registry." -ForegroundColor Yellow
        return $false
    }
    catch {
        Write-Error "Failed to update registry: $_"
        return $false
    }
}

# Function to disable and re-enable network adapter
function Reset-NetworkAdapter {
    param([string]$NetConnectionID)
    
    try {
        Write-Host "Disabling adapter: $NetConnectionID" -ForegroundColor Yellow
        
        # Disable the adapter
        $disableResult = netsh interface set interface name="$NetConnectionID" admin=disable 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Warning: Could not disable adapter using netsh. Trying alternative method..." -ForegroundColor Yellow
            
            # Try using WMI method
            $adapter = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -eq $NetConnectionID }
            if ($adapter) {
                $adapter.Disable() | Out-Null
            }
        }
        
        Start-Sleep -Seconds 2
        
        Write-Host "Enabling adapter: $NetConnectionID" -ForegroundColor Yellow
        
        # Enable the adapter
        $enableResult = netsh interface set interface name="$NetConnectionID" admin=enable 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Warning: Could not enable adapter using netsh. Trying alternative method..." -ForegroundColor Yellow
            
            # Try using WMI method
            $adapter = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -eq $NetConnectionID }
            if ($adapter) {
                $adapter.Enable() | Out-Null
            }
        }
        
        Start-Sleep -Seconds 3
        Write-Host "Adapter reset completed." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to reset adapter: $_"
        return $false
    }
}

# Function to change MAC address using netsh (Windows 10/11 method)
function Set-MacAddressNetsh {
    param(
        [string]$InterfaceName,
        [string]$NewMacAddress
    )
    
    try {
        # Format MAC address for netsh (remove colons/dashes)
        $netshMac = $NewMacAddress -replace ':', '' -replace '-', ''
        
        # Use netsh to set the MAC address
        Write-Host "Setting MAC address using netsh..." -ForegroundColor Yellow
        $result = netsh interface ipv4 set global randomizeidentifiers=disabled 2>&1
        
        # Some systems support direct MAC address setting via netsh
        $result = cmd /c "netsh interface set interface name=`"$InterfaceName`" newname=`"$InterfaceName`"" 2>&1
        
        Write-Host "Note: Windows MAC address changing may require additional tools or registry modifications." -ForegroundColor Yellow
        return $true
    }
    catch {
        Write-Error "Failed to change MAC address with netsh: $_"
        return $false
    }
}

# Function to verify MAC address change
function Test-MacAddressChange {
    param(
        [string]$InterfaceName,
        [string]$ExpectedMac
    )
    
    Start-Sleep -Seconds 2
    
    $adapter = Find-NetworkAdapter -InterfaceName $InterfaceName
    if ($adapter) {
        $currentMac = $adapter.MACAddress -replace '-', ':'
        $expectedMac = $ExpectedMac -replace '-', ':'
        
        Write-Host "Current MAC Address: $currentMac" -ForegroundColor Cyan
        
        if ($currentMac.ToLower() -eq $expectedMac.ToLower()) {
            Write-Host "✓ MAC address successfully changed!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "⚠ Warning: MAC address may not have changed as expected." -ForegroundColor Yellow
            Write-Host "This could be due to:" -ForegroundColor Yellow
            Write-Host "  - Hardware/driver limitations" -ForegroundColor Yellow
            Write-Host "  - Windows security policies" -ForegroundColor Yellow
            Write-Host "  - Adapter not supporting MAC address modification" -ForegroundColor Yellow
            return $false
        }
    }
    
    return $false
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentUser
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Interactive mode functions
function Read-UserInput {
    param([string]$Prompt)
    
    Write-Host $Prompt -NoNewline -ForegroundColor White
    return Read-Host
}

function Confirm-Action {
    param([string]$Message)
    
    $response = Read-UserInput "$Message (y/N): "
    return $response.ToLower() -in @('y', 'yes')
}

# Main execution function
function Start-MacSpoof {
    Show-Banner
    
    # Handle command line parameters
    if ($Help) {
        Show-Help
        return
    }
    
    if ($List) {
        Show-NetworkInterfaces
        return
    }
    
    # Check for administrator privileges
    if (-not (Test-Administrator)) {
        Write-Host "Warning: This script requires administrator privileges for MAC address modification." -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator for full functionality." -ForegroundColor Red
        
        if (-not (Confirm-Action "Continue anyway?")) {
            Write-Host "Exiting..." -ForegroundColor Yellow
            return
        }
    }
    
    # Show available interfaces
    Show-NetworkInterfaces
    
    # Get interface selection
    $selectedAdapter = $null
    if ($Interface) {
        $selectedAdapter = Find-NetworkAdapter -InterfaceName $Interface
        if (-not $selectedAdapter) {
            Write-Host "Error: Interface '$Interface' not found." -ForegroundColor Red
            return
        }
    } else {
        do {
            $interfaceInput = Read-UserInput "Input INTERFACE needed to modify (name, number, or connection ID) > "
            $selectedAdapter = Find-NetworkAdapter -InterfaceName $interfaceInput
            
            if ($selectedAdapter) {
                Write-Host "Interface found: $($selectedAdapter.NetConnectionID)" -ForegroundColor Green
                Write-Host "Current MAC Address: $($selectedAdapter.MACAddress)" -ForegroundColor Cyan
            } else {
                Write-Host "Error: Interface '$interfaceInput' not found. Please try again." -ForegroundColor Red
            }
        } while (-not $selectedAdapter)
    }
    
    # Get MAC address
    $newMacAddress = ""
    if ($Random) {
        $newMacAddress = New-RandomMacAddress
        Write-Host "Generated random MAC address: $newMacAddress" -ForegroundColor Green
    } elseif ($MacAddress) {
        $macValidation = Test-MacAddress -MacAddress $MacAddress
        if (-not $macValidation.IsValid) {
            Write-Host "Error: Invalid MAC address format '$MacAddress'" -ForegroundColor Red
            Write-Host "Please use format like aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff" -ForegroundColor Yellow
            return
        }
        $newMacAddress = $macValidation.NormalizedMac
    } else {
        do {
            $macInput = Read-UserInput "Input dummy MACADDRESS preferred (or 'random' for random MAC) > "
            
            if ($macInput.ToLower() -eq 'random') {
                $newMacAddress = New-RandomMacAddress
                Write-Host "Generated random MAC address: $newMacAddress" -ForegroundColor Green
                break
            } else {
                $macValidation = Test-MacAddress -MacAddress $macInput
                if ($macValidation.IsValid) {
                    $newMacAddress = $macValidation.NormalizedMac
                    Write-Host "MAC address format is valid: $newMacAddress" -ForegroundColor Green
                } else {
                    Write-Host "Error: Invalid MAC address format." -ForegroundColor Red
                    Write-Host "Please use format like aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff" -ForegroundColor Yellow
                    Write-Host "Or type 'random' for a random MAC address." -ForegroundColor Yellow
                }
            }
        } while (-not $newMacAddress)
    }
    
    # Confirm the change
    Write-Host ""
    Write-Host "Ready to change MAC address:" -ForegroundColor Cyan
    Write-Host "  Interface: $($selectedAdapter.NetConnectionID)" -ForegroundColor White
    Write-Host "  From: $($selectedAdapter.MACAddress)" -ForegroundColor Yellow
    Write-Host "  To: $newMacAddress" -ForegroundColor Green
    Write-Host ""
    
    if (-not (Confirm-Action "Proceed with MAC address change?")) {
        Write-Host "MAC address change cancelled." -ForegroundColor Yellow
        return
    }
    
    # Perform the MAC address change
    Write-Host "Changing MAC address..." -ForegroundColor Cyan
    
    # Try registry method first (most reliable on Windows)
    $success = Set-MacAddressWindows -DeviceID $selectedAdapter.DeviceID -NewMacAddress $newMacAddress
    
    if ($success) {
        # Reset the network adapter to apply changes
        $resetSuccess = Reset-NetworkAdapter -NetConnectionID $selectedAdapter.NetConnectionID
        
        if ($resetSuccess) {
            Write-Host "MAC address change process completed!" -ForegroundColor Green
            
            # Verify the change
            Test-MacAddressChange -InterfaceName $selectedAdapter.NetConnectionID -ExpectedMac $newMacAddress
        } else {
            Write-Host "⚠ MAC address may have been set, but adapter reset failed." -ForegroundColor Yellow
            Write-Host "You may need to manually disable and re-enable the network adapter." -ForegroundColor Yellow
        }
    } else {
        Write-Host "✗ Failed to change MAC address." -ForegroundColor Red
        Write-Host "This could be due to:" -ForegroundColor Red
        Write-Host "  - Insufficient privileges (not running as Administrator)" -ForegroundColor Red
        Write-Host "  - Hardware/driver limitations" -ForegroundColor Red
        Write-Host "  - Windows security policies" -ForegroundColor Red
        Write-Host "  - Network adapter doesn't support MAC address modification" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "MACPOOF session completed." -ForegroundColor Cyan
}

# Script entry point
try {
    Start-MacSpoof
}
catch {
    Write-Error "An unexpected error occurred: $_"
    Write-Host "Please ensure you're running PowerShell as Administrator." -ForegroundColor Yellow
}

# End of script
