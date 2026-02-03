# ============================================================
# MANUAL TEST PARAMETERS
# ============================================================
$WarningDays = 30
# ============================================================

Write-Output "Starting certificate expiry check across ALL subscriptions..."
Write-Output ""

# ------------------------------------------------------------
# Authenticate to Azure
# ------------------------------------------------------------
Connect-AzAccount -Identity

# ------------------------------------------------------------
# Get all subscriptions where you have access
# ------------------------------------------------------------
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Output "===== Subscription: $($sub.Name) ($($sub.Id)) ====="
    Set-AzContext -SubscriptionId $sub.Id

    # Get all VMs in subscription
    $vms = Get-AzVM

    if (-not $vms) {
        Write-Output "No VMs found in subscription: $($sub.Name)"
        continue
    }

    foreach ($vm in $vms) {
        Write-Output ""
        Write-Output "Checking VM: $($vm.Name) in RG: $($vm.ResourceGroupName)"

        # Script to run inside VM
        $vmScript = @"
`$stores = @(
    'Cert:\LocalMachine\My'
)

`$now = Get-Date
`$warningDays = $WarningDays

foreach (`$store in `$stores) {
    if (Test-Path `$store) {
        Get-ChildItem `$store -ErrorAction SilentlyContinue | ForEach-Object {
            `$daysRemaining = (`$_.NotAfter - `$now).Days

            `$status = if (`$daysRemaining -lt 0) {
                'EXPIRED'
            }
            elseif (`$daysRemaining -le `$warningDays) {
                'EXPIRING SOON'
            }
            else {
                'VALID'
            }

            Write-Output ("{0,-20} | {1,-8} | {2,-45} | {3,-12} | {4,5} days | {5}" -f `
                `$env:COMPUTERNAME,
                `$store.Replace('Cert:\LocalMachine\', ''),
                `$_.Subject.Substring(0,[Math]::Min(45, `$_.Subject.Length)),
                `$_.NotAfter.ToString('yyyy-MM-dd'),
                `$daysRemaining,
                `$status
            )
        }
    }
}
"@

        try {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name `
                -CommandId 'RunPowerShellScript' `
                -ScriptString $vmScript `
                -ErrorAction Stop

            Write-Output "===== CERTIFICATE EXPIRY REPORT ====="
            Write-Output $result.Value[0].Message
        }
        catch {
            Write-Output "Failed to run command on VM $($vm.Name): $_"
        }
    }
}
