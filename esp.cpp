/*
 * This module patiently listens on the Serial port for log telemetry initiated by the D.O.O.M. dashboard commands on the host machine.
 */

#include <Arduino.h>

String logBuffer = "";

// Define a maximum buffer size to prevent memory exhaustion if a host machine pushes an unusually large log entry.
const int MAX_BUFFER_SIZE = 2048; 

void setup() {
  // Initialize the telepathic link at a high baud rate for fast data transfer
  Serial.begin(115200);
  
  // Wait for the serial port to establish a connection
  while (!Serial) {
    delay(10); 
  }
  
  // A startup beacon to confirm the Doombot is alive and listening
  Serial.println("[DOOMBOT] Initialization complete. Awaiting host telemetry...");
}

void loop() {
  // Check if the host machine is actively transmitting logs down the wire
  if (Serial.available() > 0) {
    
    // Read the incoming byte
    char incomingChar = Serial.read();
    
    // Process the data when a newline character is detected (End of log entry)
    if (incomingChar == '\n') {
      
      // 'logBuffer' now contains the complete, raw log string from the host.  Clear the buffer to prepare for the next incoming log
      logBuffer = ""; 
      
    } 
      
    // Ignore carriage returns to ensure clean string formatting
    else if (incomingChar != '\r') { 
      
      // Append the character as long as it does not exceed memory limit
      if (logBuffer.length() < MAX_BUFFER_SIZE) {
        logBuffer += incomingChar;
      } else {
        // If the buffer overflows, flush it to prevent the ESP32 from crashing.
        logBuffer = ""; 
      }
    }
  }
}
