#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

const char* ssid = "SSID of wifi";
const char* password = "Password of wifi";
const char* serverUrl = "Fast API URL"; //FastAPI

const int RED = 2; // Red LED
const int GREEN = 3; //Green LED
String inputBuffer = "";

void setup() {
  Serial.begin(115200);
  pinMode(RED, OUTPUT);
  digitalWrite(RED, LOW);
  pinMode(GREEN, OUTPUT);
  digitalWrite(GREEN, HIGH);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
}

void loop() {
  // Read logs coming from the endpoint via USB cable
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\n') {
      if (inputBuffer.length() > 0) {
        
        // Send the logs to FastAPI
        if (WiFi.status() == WL_CONNECTED) {
          HTTPClient http;
          http.begin(serverUrl);
          http.addHeader("Content-Type", "application/json");
          
          int httpResponseCode = http.POST(inputBuffer);
          
          // Check for threat alerts to trigger the LED
          if (httpResponseCode == 200) {
            String response = http.getString();
            DynamicJsonDocument doc(1024);
            deserializeJson(doc, response);
            
            bool threatDetected = doc["threat_detected"];
            if (threatDetected) {
              digitalWrite(RED, HIGH); // Glow red LED
              digitalWrite(GREEN, LOW); // Stop glowing green LED
            } else {
              digitalWrite(RED, LOW);
              digitalWrite(GREEN, HIGH);
            }
          }
          http.end();
        }
        inputBuffer = "";
      }
    } else if (c != '\r') {
      inputBuffer += c;
    }
  }
}
