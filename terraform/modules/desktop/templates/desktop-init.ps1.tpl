<powershell>
# ---------------------------------------------------------------------------
# Windows desktop bootstrap for the Threat Defense GenAI lab.
#
# Adapted from tech-summit-security-niosx/terraform/scripts/winrm-init.ps1.tpl,
# with three additions specific to this lab:
#   * the resolver is pointed at the NIOS-X DNS Forwarding Proxy, so every
#     lookup the participant makes is forwarded to Infoblox Threat Defense and
#     evaluated against the security policy they build in the portal;
#   * DNS-over-HTTPS is switched off in Edge and in the Windows DNS client. A
#     browser resolving over DoH goes straight to a public encrypted resolver
#     and never reaches the DFP, so Threat Defense sees no query at all: no
#     block, no Insight, and Application Discovery stays empty;
#   * desktop shortcuts are dropped for the sites the participant will test.
#
# Terraform substitutes three variables into this file: admin_password,
# dns_server_ip and portal_url. Those are the only single-dollar brace
# expressions allowed here, in comments as much as in code, because
# templatefile() evaluates them everywhere. Anything PowerShell needs to expand
# itself must use a doubled dollar.
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Continue"
Start-Transcript -Path "C:\user_data.log" -Append

Write-Host "---- Threat Defense lab desktop bootstrap ----"

Write-Host "Waiting for the network stack..."
Start-Sleep -Seconds 30

# --- Administrator password -------------------------------------------------
Write-Host "Setting Administrator password..."
try {
    $AdminPassword = ConvertTo-SecureString "${admin_password}" -AsPlainText -Force
    Set-LocalUser -Name "Administrator" -Password $AdminPassword
    Set-LocalUser -Name "Administrator" -PasswordNeverExpires $true
} catch {
    Write-Host "Failed to set admin password: $_"
}

# --- WinRM ------------------------------------------------------------------
# Basic auth over HTTP is fine here and only here: the host is a throwaway lab
# instance and port 5985 is reachable only for the duration of the track.
Write-Host "Configuring WinRM..."
try {
    winrm quickconfig -force
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
} catch {
    Write-Host "WinRM setup failed: $_"
}

# --- Firewall ---------------------------------------------------------------
Write-Host "Opening RDP and WinRM..."
$ports = @(
    @{ Name = "WinRM HTTP"; Port = 5985 },
    @{ Name = "RDP";        Port = 3389 }
)
foreach ($rule in $ports) {
    try {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $rule.Port -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Failed to create firewall rule for $($rule.Port): $_"
    }
}

# --- Point DNS at the NIOS-X DFP --------------------------------------------
# This is what puts the desktop behind Threat Defense. Everything else in the
# lab depends on it, so it is retried rather than attempted once.
Write-Host "Pointing DNS at the DFP at ${dns_server_ip}..."
for ($i = 1; $i -le 10; $i++) {
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
        if ($adapter) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("${dns_server_ip}")
            Write-Host "Resolver set on interface $($adapter.Name)"
            break
        }
        Write-Host "No adapter up yet, attempt $i..."
    } catch {
        Write-Host "DNS config attempt $i failed: $_"
    }
    Start-Sleep -Seconds 10
}

# --- Disable DNS-over-HTTPS -------------------------------------------------
# Without this the browser resolves claude.ai through Cloudflare or Google over
# 443 and never asks the DFP, so Threat Defense never sees the query and the
# policy appears not to work.
# Belt and braces: Edge policy, Edge's built-in async resolver, and the Windows
# DNS client's automatic DoH upgrade.
Write-Host "Disabling DNS-over-HTTPS..."
try {
    $edgePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    New-Item -Path $edgePolicy -Force | Out-Null
    New-ItemProperty -Path $edgePolicy -Name "DnsOverHttpsMode"       -Value "off" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $edgePolicy -Name "BuiltInDnsClientEnabled" -Value 0     -PropertyType DWord  -Force | Out-Null
    New-ItemProperty -Path $edgePolicy -Name "HideFirstRunExperience"  -Value 1     -PropertyType DWord  -Force | Out-Null

    $dnscache = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    New-Item -Path $dnscache -Force | Out-Null
    New-ItemProperty -Path $dnscache -Name "EnableAutoDoh" -Value 0 -PropertyType DWord -Force | Out-Null
} catch {
    Write-Host "Failed to disable DoH: $_"
}

# --- Make Edge usable out of the box ----------------------------------------
Write-Host "Relaxing IE Enhanced Security Configuration..."
try {
    $adminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $userKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $adminKey -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $userKey  -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
} catch {
    Write-Host "Failed to relax IE ESC: $_"
}

# --- Shortcuts for the sites the participant will test ----------------------
Write-Host "Creating desktop shortcuts..."
try {
    $shell   = New-Object -ComObject WScript.Shell
    $desktop = "C:\Users\Public\Desktop"

    $links = @(
        @{ Name = "Claude";          Url = "https://claude.ai" },
        @{ Name = "ChatGPT";         Url = "https://chatgpt.com" },
        @{ Name = "Gemini";          Url = "https://gemini.google.com" },
        @{ Name = "Copilot";         Url = "https://copilot.microsoft.com" },
        @{ Name = "Perplexity";      Url = "https://perplexity.ai" },
        @{ Name = "Infoblox Portal"; Url = "${portal_url}" }
    )

    foreach ($link in $links) {
        $shortcut = $shell.CreateShortcut("$desktop\$($link.Name).url")
        $shortcut.TargetPath = $link.Url
        $shortcut.Save()
    }
} catch {
    Write-Host "Failed to create shortcuts: $_"
}

# --- Flush so the first lookup uses the new resolver ------------------------
try {
    Clear-DnsClientCache
} catch {
    Write-Host "Failed to flush DNS cache: $_"
}

Write-Host "---- Desktop bootstrap complete ----"
Stop-Transcript
</powershell>
<persist>true</persist>
