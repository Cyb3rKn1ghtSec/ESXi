
function ESXI-80-000005{
    Write-Host "ESXI-80-000005"
    Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3
}
function ESXI-80-000006{
    Write-Host "ESXI-80-000006"
    $banner = Get-Content -Path $PSScriptRoot\ESXI-80-000006.txt
    Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value "$($banner)"
}
function ESXI-80-000008{
    Write-Host "ESXI-80-000008"
    Write-Host "Currently not enforcing RULE: ESXI-80-000008" -ForegroundColor Yellow
}
function ESXI-80-000010{
    Write-Host "ESXI-80-000010"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value "900"
}


