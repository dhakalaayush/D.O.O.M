#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// CONFIGURATION

const char* ssid = "AayushM32";
const char* password = "iamaayush";
const char* target_siem_url = "http://192.168.100.30:8001/api/v1/logs"; 

const String DOOMBOT_ID = "doombot-01";
const String OS_TYPE = "Windows";

// LED Pins (D2 and D4)
const int RED_LED = 2;
const int GREEN_LED = 4;

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  // Initialize LEDs
  pinMode(RED_LED, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  
  // Default State: Green ON, Red OFF
  digitalWrite(GREEN_LED, HIGH);
  digitalWrite(RED_LED, LOW);
  
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(ssid);
  
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  
  Serial.println("\nWiFi connected!");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  // Listen for logs pushed via USB by the PowerShell script
  if (Serial.available()) {
    String logLine = Serial.readStringUntil('\n');
    logLine.trim();

    if (logLine.length() > 0) {
      Serial.print("Received from Serial: ");
      Serial.println(logLine);

      if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(target_siem_url);
        http.addHeader("Content-Type", "application/json");

        // Package log into JSON
        DynamicJsonDocument doc(1024);
        doc["doombot_id"] = DOOMBOT_ID;
        doc["os"] = OS_TYPE;
        
        JsonArray logsArray = doc.createNestedArray("logs");
        logsArray.add(logLine);

        String requestBody;
        serializeJson(doc, requestBody);

        // POST to main.py
        int responseCode = http.POST(requestBody);
        Serial.print("HTTP Response code: ");
        Serial.println(responseCode);
        
        // Process the SIEM's immediate response for hardware feedback
        if (responseCode == 200) {
          String responseBody = http.getString();
          
          DynamicJsonDocument responseDoc(512);
          deserializeJson(responseDoc, responseBody);
          
          bool isThreat = responseDoc["threat_detected"];
          
          if (isThreat) {
            // Alert state!
            digitalWrite(GREEN_LED, LOW);
            digitalWrite(RED_LED, HIGH);
            Serial.println(">>> THREAT DETECTED: Red LED ON");
          } else {
            // Safe state. 
            digitalWrite(RED_LED, LOW);
            digitalWrite(GREEN_LED, HIGH);
            Serial.println(">>> Status Safe: Green LED ON");
          }
        } else {
          Serial.print("Error sending POST. Code: ");
          Serial.println(responseCode);
        }
        http.end();
      } else {
        Serial.println("Error: WiFi disconnected!");
      }
    }
  }
}
