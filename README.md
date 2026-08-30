# Defense Observation, Orchestration and Monitoring - D.O.O.M

### Install requirements

    pip install -r requirements.txt

### Running Agent

If ESP32 Doombot is used, configure the WiFi and server IP address the C++ program. After connecting doombot to the machine, run these commands:

**Windows**

    
    $port = New-Object System.IO.Ports.SerialPort COM3, 115200, None, 8, One
    $port.Open()
    $lastEvent = Get-WinEvent -LogName "Security" -MaxEvents 1
    $lastTime = $lastEvent.TimeCreated
    Write-Host "[*] Listening for new Windows Security events..." -ForegroundColor Green
    while ($true) {
        $ErrorActionPreference = 'SilentlyContinue'
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$lastTime}
        if ($events) {
            [array]::Reverse($events)
            foreach ($event in $events) {
                $cleanMessage = $event.Message -replace "`n|`r", " "
                $logLine = "$($event.TimeCreated) Windows Security Event $($event.Id): $cleanMessage"
                $port.WriteLine($logLine)
                Write-Host "-> Sent: Security Event $($event.Id)" -ForegroundColor Cyan
                $lastTime = $event.TimeCreated
            }
        }
        Start-Sleep -Seconds 2
    }


**Linux**

    stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb
    LOGS=$(tail -n 5 /var/log/auth.log | jq -R -s -c 'split("\n")[:-1]')
    PAYLOAD="{\"doombot_id\":\"doombot-linux-1\",\"os\":\"Linux\",\"logs\":$LOGS}"
    echo "$PAYLOAD" > /dev/ttyUSB0

If doombot is not installed, agent program can be run and following commands should be run:

**Windows**

    cd Agent
    
    python agent.py #For python agent

**Linux**

    cd Agent

    sudo python3 agent.py

### Running backend or FastAPI

    cd Backend

    python main.py

### Running frontend or dashboard

    cd Frontend

    streamlit run app.py

or

    python -m streamlit run app.py
