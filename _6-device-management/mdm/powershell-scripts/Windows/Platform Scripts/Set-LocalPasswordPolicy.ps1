Function Set-LocalPasswordPolicy {
    <#
        .DESCRIPTION
        Applies a fixed local password policy (no parameters).

        .NOTES
        Author: modified for user
        Date:    2025-10-10
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    Begin {
        # Check if the current user is elevated as admin
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        If (-not $is_admin) {
            Write-Error "You must run this function as an administrator."
            return
        }

        # Define the exact policy values to apply (embedded in the script)
        $settings = @{
            "PasswordComplexity"   = 1    # $true -> 1
            "MinimumPasswordLength"= 14
            "MinimumPasswordAge"   = 1
            "MaximumPasswordAge"   = 90
            "PasswordHistorySize"  = 24
            "LockoutBadCount"      = 5
            "ResetLockoutCount"    = 15
            "LockoutDuration"      = 15
        }

        # Export the current local security policy to a temp file
        $outfile = Join-Path $Env:TEMP "secpol.cfg"
        try {
            secedit /export /cfg $outfile | Out-Null
        } catch {
            Throw "Failed to export local security policy via secedit: $($_.Exception.Message)"
        }

        # Read the secpol file as a single string for regex operations
        $sec_pol_text = Get-Content -Path $outfile -Raw -ErrorAction Stop
    } # Begin

    Process {
        if ($PSCmdlet.ShouldProcess("$Env:COMPUTERNAME","Apply local password policy")) {
            foreach ($key in $settings.Keys) {
                $value = $settings[$key]

                # Pattern: match lines like "PasswordComplexity = 0" possibly with spaces
                $pattern = "(?m)^\s*{0}\s*=\s*\d+" -f [regex]::Escape($key)

                if ($sec_pol_text -match $pattern) {
                    # Replace existing line
                    $replacement = "$key = $value"
                    $sec_pol_text = [regex]::Replace($sec_pol_text, $pattern, [regex]::Escape($replacement))
                } else {
                    # Append the setting if it doesn't exist
                    # Ensure trailing newline before appending
                    if ($sec_pol_text -notmatch "`r?`n$") { $sec_pol_text += "`r`n" }
                    $sec_pol_text += "$key = $value`r`n"
                }
            }

            # Write the updated local security policy file
            try {
                $sec_pol_text | Out-File -FilePath $outfile -Encoding ASCII -Force

                # Apply the configuration
                secedit /configure /db c:\windows\security\local.sdb /cfg $outfile /areas SECURITYPOLICY | Out-Null
            } catch {
                Throw "Failed to apply local security policy: $($_.Exception.Message)"
            } finally {
                # Remove the temporary file if present
                if (Test-Path $outfile) {
                    Remove-Item $outfile -Force -ErrorAction SilentlyContinue
                }
            }
        } # ShouldProcess
    } # Process

    End {
        return
    } # End
}

# Call the function to apply the embedded policy immediately
Set-LocalPasswordPolicy
