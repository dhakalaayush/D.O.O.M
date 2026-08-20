After installing doombot on the endpoint, following commands should be run:

**Windows**

    $port = New-Object System.IO.Ports.SerialPort "COM3", 115200, None, 8, one
    $port.Open()
    $sysmonLogs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message
    $payload = @{
    doombot_id = "doombot-windows-1"
    os = "Windows"
    logs = @($sysmonLogs)
    } | ConvertTo-Json -Compress
    $port.WriteLine($payload)
    $port.Close()

**Linux**

    stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb
    LOGS=$(tail -n 5 /var/log/auth.log | jq -R -s -c 'split("\n")[:-1]')
    PAYLOAD="{\"doombot_id\":\"doombot-linux-1\",\"os\":\"Linux\",\"logs\":$LOGS}"
    echo "$PAYLOAD" > /dev/ttyUSB0

Start FastAPI server:

    uvicorn main:app --reload
