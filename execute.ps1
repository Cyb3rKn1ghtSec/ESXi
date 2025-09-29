try{
    if($null -eq $global:DefaultVIServer){
        Connect-VIServer -Server esxi03
    }









    Write-Host "ESXI-80-000014"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
    $arguments.enable = $true
    $esxcli.system.security.fips140.ssh.set.Invoke($arguments)

    Write-Host "ESXI-80-000015"
    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"

    Write-Host "ESXI-80-000035"
    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"

    Write-Host "ESXI-80-000043"
    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5

    Write-Host "ESXI-80-000047"
    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false

    #ESXI-80-000049
    ###PLACEHOLDER

    Write-Host "ESXI-80-000052"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'ignorerhosts'
    $arguments.value = 'yes'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000068"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900

    Write-Host "ESXI-80-000085"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.requiresecureboot = $true
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    <#Write-Host "ESXI-80-000094"
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.Firmware = [VMware.Vim.GuestOsDescriptorFirmwareType]::efi
    $boot = New-Object VMware.Vim.VirtualMachineBootOptions
    $boot.EfiSecureBootEnabled = $true
    $spec.BootOptions = $boot
    $vm.ExtensionData.ReconfigVM($spec)#>

    Write-Host "ESXI-80-000111"
    Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900

    Write-Host "ESXI-80-000113"
    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Set-AdvancedSetting -Value 100

    #ESXI-80-000114
    ######PLACEHOLDER

    Write-Host "ESXI-80-000124"
    $NTPServers = "$($env:LOGONSERVER -replace '\\','')"
    Get-VMHost | Add-VMHostNTPServer $NTPServers
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService

    Write-Host "ESXI-80-000133"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.software.acceptance.set.CreateArgs()
    $arguments.level = "PartnerSupported"
    $esxcli.software.acceptance.set.Invoke($arguments)

    Write-Host "ESXI-80-000145"
    Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Set-VMHostHba -ChapType Required -ChapName "chapname" -ChapPassword "password" -MutualChapEnabled $true -MutualChapName "mutualchapname" -MutualChapPassword "mutualpassword"

    #ESXI-80-000160
    #######PLACEHOLDER

    Write-Host "ESXI-80-000161"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value "sslv3,tlsv1,tlsv1.1"

    Write-Host "ESXI-80-000187"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'ciphers'
    $arguments.value = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000189"
    Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root"

    Write-Host "ESXI-80-000191"
    $banner2 = Get-Content -Path $PSScriptRoot\ESXI-80-000191.txt
    Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue | Set-AdvancedSetting -Value $banner2

    Write-Host "ESXI-80-000192"
    Write-Host "Currently not enforcing RULE: ESXI-80-000192" -ForegroundColor Yellow

    Write-Host "ESXI-80-000193"
    Write-Host "Currently not enforcing RULE: ESXI-80-000193" -ForegroundColor Yellow

    Write-Host "ESXI-80-000194"
    Write-Host "Currently not enforcing RULE: ESXI-80-000194" -ForegroundColor Yellow

    Write-Host "ESXI-80-000195"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600

    Write-Host "ESXI-80-000196"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600

    #ESXI-80-000198
    ######PLACEHOLDER

    #ESXI-80-000199
    ######PLACEHOLDER

    Write-Host "ESXI-80-000201"
    Write-Host "Currently not enforcing RULE: ESXI-80-000201" -ForegroundColor Yellow

    Write-Host "ESXI-80-000202"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'hostbasedauthentication'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000204"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'permituserenvironment'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000207"
    Write-Host "Currently not enforcing RULE: ESXI-80-000201" -ForegroundColor Yellow

    Write-Host "ESXI-80-000209"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'permittunnel'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000210"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'clientalivecountmax'
    $arguments.value = '3'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000211"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'clientaliveinterval'
    $arguments.value = '200'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000212"
    Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false

    Write-Host "ESXI-80-000213"
    Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2

    Write-Host "ESXI-80-000214"
    Write-Host "Currently not enforcing RULE: ESXI-80-000214" -ForegroundColor Yellow

    Write-Host "ESXI-80-000215"
    Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1

    Write-Host "ESXI-80-000216"
    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true

    Write-Host "ESXI-80-000217"
    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true

    Write-Host "ESXI-80-000218"
    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true

    Write-Host "ESXI-80-000219"
    Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value ""

    Write-Host "ESXI-80-000220"
    Write-Host "Currently not enforcing RULE: ESXI-80-000220" -ForegroundColor Yellow

    #ESXI-80-000221
    ######PLACEHOLDER

    Write-Host "ESXI-80-000222"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 0

    Write-Host "ESXI-80-000223"
    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value 0

    Write-Host "ESXI-80-000224"
    Write-Host "Currently not enforcing RULE: ESXI-80-000224" -ForegroundColor Yellow

    Write-Host "ESXI-80-000225"
    Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value 1

    Write-Host "ESXI-80-000226"
    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Set-AdvancedSetting -Value 30

    Write-Host "ESXI-80-000227"
    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90

    Write-Host "ESXI-80-000228"
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Stop-VMHostService

    Write-Host "ESXI-80-000229"
    Write-Host "Currently not enforcing RULE: ESXI-80-000229" -ForegroundColor Yellow

    Write-Host "ESXI-80-000230"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'allowtcpforwarding'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)

    Write-Host "ESXI-80-000231"
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService

    Write-Host "ESXI-80-000232"
    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable | Set-AdvancedSetting -Value "true"

    Write-Host "ESXI-80-000233"
    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Set-AdvancedSetting -Value "true"

    Write-Host "ESXI-80-000234"
    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance | Set-AdvancedSetting -Value "true"

    Write-Host "ESXI-80-000235"
    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logLevel | Set-AdvancedSetting -Value "info"

    #ESXI-80-000236
    #####PLACEHOLDER

    #ESXI-80-000237
    #####PLACEHOLDER

    Write-Host "ESXI-80-000238"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.mode = "TPM"
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Write-Host "ESXI-80-000239"
    Write-Host "Currently not enforcing RULE: ESXI-80-000239" -ForegroundColor Yellow

    #ESXI-80-000240
    #####PLACEHOLDER

    Write-Host "ESXI-80-000241"
    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value "Domain Admins"

    Write-Host "ESXI-80-000243"
    Write-Host "Currently not enforcing RULE: ESXI-80-000243" -ForegroundColor Yellow

    Write-Host "ESXI-80-000244"
    Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value True

    Write-Host "ESXI-80-000245"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
    $arguments.setting = "disableHwrng"
    $arguments.value = "FALSE"
    $esxcli.system.settings.kernel.set.invoke($arguments)
    $arguments.setting = "entropySources"
    $arguments.value = "0"
    $esxcli.system.settings.kernel.set.invoke($arguments)

    Write-Host "ESXI-80-000246"
    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
    $arguments.logfilteringenabled = $false
    $esxcli.system.syslog.config.logfilter.set.invoke($arguments)

    exit 3010
}
catch{
    $_
}