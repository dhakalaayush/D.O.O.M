**Log Collection**

For Windows: Run this command on PowerShell:
`$portName = [System.IO.Ports.SerialPort]::GetPortNames()[0]; if ($portName) { Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100 | ForEach-Object { $port = New-Object System.IO.Ports.SerialPort $portName, 115200, None, 8, one; $port.Open(); $port.WriteLine($_.Message); $port.Close() } }`

For Linux: Run this command on terminal:
`stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb && tail -f /var/log/auth.log > /dev/ttyUSB0`
