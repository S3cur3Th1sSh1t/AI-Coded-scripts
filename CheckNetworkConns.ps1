function checkactiveconns {

param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerList
)

# Target IPs to check
$targetIPs = @("x.x.x.x", "x.x.x.x")

# Split the comma-separated list into an array
$computers = $ComputerList -split ',' | ForEach-Object { $_.Trim() }

Write-Host "Checking connections to $($targetIPs -join ' and ') on remote hosts..." -ForegroundColor Cyan
Write-Host ""

foreach ($computer in $computers) {
    Write-Host "Checking $computer..." -ForegroundColor Yellow
    
    try {
        # Test if the computer is reachable
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            
            # Get established TCP connections on the remote computer
            $connections = Invoke-Command -ComputerName $computer -ScriptBlock {
                param($ips)
                Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                    Where-Object { $_.RemoteAddress -in $ips }
            } -ArgumentList (,$targetIPs) -ErrorAction Stop
            
            if ($connections) {
                Write-Host "✓ $computer HAS ACTIVE CONNECTION(S)" -ForegroundColor Green
                foreach ($conn in $connections) {
                    Write-Host "  → Remote IP: $($conn.RemoteAddress):$($conn.RemotePort) | Local Port: $($conn.LocalPort)" -ForegroundColor White
                }
            } else {
                Write-Host "  No active connections found" -ForegroundColor Gray
            }
            
        } else {
            Write-Host "  ✗ Unable to reach $computer" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ✗ Error checking $computer : $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "Scan complete." -ForegroundColor Cyan

}
