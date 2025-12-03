function Get-LogonEvents {
    <#
    .SYNOPSIS
        Searches Security event logs for successful logon events (Event ID 4624) for specified users.
    
    .DESCRIPTION
        Queries the Security log on a remote Domain Controller for Event ID 4624 (successful logons)
        and filters by specified usernames. Returns IP address, hostname, and other logon details.
    
    .PARAMETER TargetUsers
        Comma-separated list of usernames to search for. Can be a single user or multiple users.
    
    .PARAMETER ComputerName
        The Domain Controller to query. Defaults to the local computer.
    
    .PARAMETER Credential
        PSCredential object for authentication. If not provided, uses current user context.
    
    .PARAMETER MaxEvents
        Maximum number of events to retrieve. Defaults to 5000.
    
    .EXAMPLE
        Get-LogonEvents -TargetUsers "jsmith,mjones,aadmin" -ComputerName "DC01.contoso.com"
    
    .EXAMPLE
        $cred = Get-Credential
        Get-LogonEvents -TargetUsers "administrator" -ComputerName "DC01" -Credential $cred
    
    .EXAMPLE
        Get-LogonEvents -TargetUsers "user1,user2,user3" -ComputerName "DC01" -MaxEvents 10000
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, HelpMessage="Comma-separated usernames (e.g., 'user1,user2,user3')")]
        [string]$TargetUsers,
        
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxEvents = 5000
    )
    
    # Convert comma-separated string to array and trim whitespace
    $userArray = $TargetUsers -split ',' | ForEach-Object { $_.Trim() }
    
    Write-Host "`nSearching for logon events on $ComputerName..." -ForegroundColor Cyan
    Write-Host "Target users: $($userArray -join ', ')" -ForegroundColor Cyan
    Write-Host "Max events to retrieve: $MaxEvents`n" -ForegroundColor Cyan
    
    # Build parameters for Get-WinEvent
    $getWinEventParams = @{
        ComputerName = $ComputerName
        FilterHashtable = @{
            LogName = 'Security'
            ID = 4624
        }
        MaxEvents = $MaxEvents
        ErrorAction = 'Stop'
    }
    
    # Add credential if provided
    if ($Credential) {
        $getWinEventParams.Add('Credential', $Credential)
    }
    
    try {
        # Get Event ID 4624 (successful logon) from Security log
        Write-Host "Retrieving events from Security log..." -ForegroundColor Yellow
        $events = Get-WinEvent @getWinEventParams
        
        Write-Host "Processing $($events.Count) events...`n" -ForegroundColor Yellow
        
        # Filter and process events for the target users
        $logonEvents = $events | Where-Object {
            $xml = [xml]$_.ToXml()
            $eventData = $xml.Event.EventData.Data
            
            # Find TargetUserName
            $username = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            
            $username -in $userArray
        } | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $eventData = $xml.Event.EventData.Data
            
            # Extract relevant information
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                ComputerName = $ComputerName
                TargetUserName = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                TargetDomainName = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
                IpAddress = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                WorkstationName = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                LogonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                LogonProcessName = ($eventData | Where-Object { $_.Name -eq 'LogonProcessName' }).'#text'
                AuthenticationPackageName = ($eventData | Where-Object { $_.Name -eq 'AuthenticationPackageName' }).'#text'
            }
        }
        
        # Display results
        if ($logonEvents) {
            Write-Host "Found $($logonEvents.Count) logon event(s) for specified users`n" -ForegroundColor Green
            $logonEvents | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
            
            # Display count per user
            Write-Host "`nLogon count per user:" -ForegroundColor Cyan
            $logonEvents | Group-Object TargetUserName | 
                Select-Object Name, Count | 
                Sort-Object Count -Descending | 
                Format-Table -AutoSize
            
            # Display unique IP addresses per user
            Write-Host "Unique IP addresses per user:" -ForegroundColor Cyan
            $logonEvents | Where-Object { $_.IpAddress -and $_.IpAddress -ne '-' } |
                Group-Object TargetUserName | ForEach-Object {
                    $uniqueIPs = $_.Group | Select-Object -ExpandProperty IpAddress -Unique
                    [PSCustomObject]@{
                        User = $_.Name
                        UniqueIPs = $uniqueIPs -join ', '
                        Count = $uniqueIPs.Count
                    }
                } | Format-Table -AutoSize
            
            # Return the events for further processing if needed
            return $logonEvents
        } else {
            Write-Host "No logon events found for users: $($userArray -join ', ')" -ForegroundColor Yellow
            return $null
        }
        
    } catch {
        Write-Error "Error retrieving events from $ComputerName : $_"
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
        Write-Host "- Ensure you have administrative privileges on the target computer"
        Write-Host "- Verify the computer name is correct and reachable"
        Write-Host "- Check that Windows Remote Management (WinRM) is enabled"
        Write-Host "- Verify firewall rules allow remote event log access"
        return $null
    }
}

# Display logon type reference
function Show-LogonTypeReference {
    Write-Host "`nLogon Type Reference:" -ForegroundColor Cyan
    Write-Host "2  = Interactive (local logon)"
    Write-Host "3  = Network (e.g., file share access)"
    Write-Host "4  = Batch (scheduled task)"
    Write-Host "5  = Service (service logon)"
    Write-Host "7  = Unlock (workstation unlock)"
    Write-Host "8  = NetworkCleartext (IIS basic auth)"
    Write-Host "9  = NewCredentials (RunAs with /netonly)"
    Write-Host "10 = RemoteInteractive (RDP/Terminal Services)"
    Write-Host "11 = CachedInteractive (cached credentials)"
}

# Example usage (uncomment and modify as needed):
# $cred = Get-Credential -Message "Enter Domain Admin credentials"
# Get-LogonEvents -TargetUsers "user1,user2,user3" -ComputerName "DC01.contoso.com" -Credential $cred
# Show-LogonTypeReference

# Or without credentials (uses current user context):
# Get-LogonEvents -TargetUsers "administrator,jsmith" -ComputerName "DC01.contoso.com"
