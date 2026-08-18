**Doombot Setup**

For Windows: Run this on PowerShell:


    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -ExpandProperty IPAddress -First 1)
    $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null } | Select-Object    @{Name="name";Expression={$_.DisplayName}}, @{Name="version";Expression={$_.DisplayVersion}}


    $fwProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
    $rdpStatus = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections

    $configs = @{
    firewall_active = ($fwProfiles | Where-Object {$_.Enabled -eq $true}).Name -join ", "
    rdp_enabled = if ($rdpStatus -eq 0) { $true } else { $false }
    }


    $payload = @{
    ip_address = $ip
    os = "Windows"
    configurations = $configs
    packages = $software
    } | ConvertTo-Json -Depth 4 -Compress

    $portName = [System.IO.Ports.SerialPort]::GetPortNames()[0]; 
    if ($portName) { 
    $port = New-Object System.IO.Ports.SerialPort $portName, 115200, None, 8, one; 
    $port.Open(); 
    $port.WriteLine($payload); 
    $port.Close() 
    }

For Linux: Run this on terminal:

    stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb

    IP_ADDR=$(hostname -I | awk '{print $1}')
    SOFTWARE=$(dpkg-query -W -f='{"name":"${Package}","version":"${Version}"},' | sed '$ s/,$//')


    FW_STATUS=$(sudo ufw status | grep -o 'Status: active\|Status: inactive' | cut -d' ' -f2 || echo "unknown")
    SSH_STATUS=$(systemctl is-active ssh || echo "inactive")
    

    PAYLOAD="{\"ip_address\":\"$IP_ADDR\",\"os\":\"Linux\",\"configurations\":{\"firewall_active\":\"$FW_STATUS\",\"ssh_enabled\":\"$SSH_STATUS\"},\"packages\":[$SOFTWARE]}"

    echo "$PAYLOAD" > /dev/ttyUSB0
