**Log Collection**

For Windows: Run this command on PowerShell:

    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -ExpandProperty IPAddress -First 1)

    $regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $software = Get-ItemProperty $regPaths | 
    Where-Object { $_.DisplayName -ne $null -and $_.DisplayVersion -ne $null } | 
    Select-Object @{Name="name";Expression={$_.DisplayName}}, @{Name="version";Expression={$_.DisplayVersion}}

    $payload = @{
    ip_address = $ip
    os         = "Windows"
    packages   = $software
    } | ConvertTo-Json -Compress

    $portName = [System.IO.Ports.SerialPort]::GetPortNames()[0]
    if ($portName) {
    $port = New-Object System.IO.Ports.SerialPort $portName, 115200, None, 8, one
    $port.Open()
    $port.WriteLine($payload)
    $port.Close()
    Write-Host "[D.O.O.M.] Telemetry successfully transmitted to Doombot on $portName"
    } else {
    Write-Error "[D.O.O.M.] No active Serial/Doombot port detected."
    }

For Linux: Run this command on terminal:

    stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb
    IP_ADDR=$(hostname -I | awk '{print $1}')
    SOFTWARE=$(dpkg-query -W -f='{"name":"${Package}","version":"${Version}"},' | sed '$ s/,$//')
    cho "{\"ip_address\":\"$IP_ADDR\",\"os\":\"Linux\",\"packages\":[$SOFTWARE]}" > /dev/ttyUSB0 && echo "[D.O.O.M.] Telemetry transmitted to /dev/ttyUSB0"
