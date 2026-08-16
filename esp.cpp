#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

// Initial Setup
const char* WIFI_SSID     = "SSID";
const char* WIFI_PASSWORD = "PASSWORD";

const char* MQTT_BROKER   = "192.168.1.79";
const int   MQTT_PORT     = 1883;
const char* TOPIC_PREFIX  = "doom/telemetry/";

const int STATUS_LED      = 2;


// Initialization
WiFiClient espClient;
PubSubClient client(espClient);

String inputBuffer = "";
String deviceMac = "";
String telemetryTopic = "";

// Setup WiFi
void setupWifi() {
  pinMode(STATUS_LED, OUTPUT);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
    delay(300);
  }

  digitalWrite(STATUS_LED, HIGH);
  deviceMac = WiFi.macAddress();
  telemetryTopic = String(TOPIC_PREFIX) + deviceMac;
}

// Keep trying to connect to MQTT unless successful
void reconnectMqtt() {
  while (!client.connected()) {
    String clientId = "Doombot-" + deviceMac;
    if (client.connect(clientId.c_str())) {
      // Successfully connected
    } else {
      delay(2000);
    }
  }
}

// ESP32 setup 
void setup() {
  Serial.begin(115200);
  setupWifi();
  client.setServer(MQTT_BROKER, MQTT_PORT);
  client.setBufferSize(4096); // Expand buffer for large package manifests
}


void loop() {
  if (!client.connected()) {
    reconnectMqtt();
  }
  client.loop();

  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\n') {
      if (inputBuffer.length() > 0) {
        // Build JSON wrapper
        DynamicJsonDocument doc(4096);
        doc["doombot_id"] = deviceMac;
        doc["timestamp"] = millis();
        
        DynamicJsonDocument hostDoc(3072);
        DeserializationError err = deserializeJson(hostDoc, inputBuffer);

        if (!err) {
          doc["telemetry"] = hostDoc;
          String output;
          serializeJson(doc, output);
          client.publish(telemetryTopic.c_str(), output.c_str());
        }
        inputBuffer = "";
      }
    } else if (c != '\r') {
      inputBuffer += c;
    }
  }
}
