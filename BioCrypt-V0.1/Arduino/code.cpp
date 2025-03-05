#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>

// Pin Definitions
#define RX_PIN 2
#define TX_PIN 3
SoftwareSerial mySerial(RX_PIN, TX_PIN);
Adafruit_Fingerprint finger(&mySerial);

void setup() {
  Serial.begin(9600); // Communication with PC/GUIs
  mySerial.begin(57600); // Communication with the fingerprint module

  Serial.println("Initializing Fingerprint sensor...");
  finger.begin(57600); // Pass the baud rate to initialize the sensor

  if (finger.verifyPassword()) {
    Serial.println("Fingerprint sensor initialized successfully.");
  } else {
    Serial.println("Failed to initialize fingerprint sensor. Check connections.");
    while (1);
  }

  // Display number of templates (optional)
  Serial.print("Template Count: ");
  Serial.println(finger.templateCount);
}

void loop() {
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim(); // Remove any extra spaces or newlines

    if (command == "SCAN") {
      handleScanFingerprint();
    } else if (command == "ADD") {
      handleAddFingerprint();
    } else {
      Serial.println("[ERROR] Unknown command.");
    }
  }
}

void handleScanFingerprint() {
  Serial.println("Scanning for fingerprints...");
  int result = finger.getImage();
  if (result == FINGERPRINT_NOFINGER) {
    Serial.println("No fingerprint detected. Try again.");
    return;
  } else if (result != FINGERPRINT_OK) {
    Serial.println("Error reading fingerprint. Try again.");
    return;
  }

  // Convert the fingerprint to a template
  result = finger.image2Tz();
  if (result != FINGERPRINT_OK) {
    Serial.println("Failed to process fingerprint image.");
    return;
  }

  // Search for the fingerprint in the database
  result = finger.fingerFastSearch();
  if (result == FINGERPRINT_OK) {
    Serial.print("Found Finger ID: #");
    Serial.print(finger.fingerID);
    Serial.print(" with Confidence: ");
    Serial.println(finger.confidence);
  } else if (result == FINGERPRINT_NOTFOUND) {
    Serial.println("Fingerprint not found in the database.");
  } else {
    Serial.println("Error searching for fingerprint.");
  }
}

void handleAddFingerprint() {
  Serial.println("Starting fingerprint enrollment...");
  int id = getAvailableID();
  if (id == -1) {
    Serial.println("Error: No available ID slots.");
    return;
  }

  for (int step = 1; step <= 2; step++) {
    Serial.print("Step ");
    Serial.print(step);
    Serial.println(": Place your finger on the scanner.");

    while (finger.getImage() != FINGERPRINT_OK);

    // Convert the image to a template
    if (finger.image2Tz(step) != FINGERPRINT_OK) {
      Serial.println("Error processing fingerprint image. Start over.");
      return;
    }

    if (step == 1) {
      Serial.println("Step 1 complete. Remove your finger.");
    } else {
      Serial.println("Step 2 complete.");
    }

    delay(2000);
  }

  // Create a model for the fingerprint
  if (finger.createModel() != FINGERPRINT_OK) {
    Serial.println("Error creating fingerprint model.");
    return;
  }

  // Save the model to the database
  if (finger.storeModel(id) == FINGERPRINT_OK) {
    Serial.print("Fingerprint added successfully! ID: ");
    Serial.println(id);
  } else {
    Serial.println("Error saving fingerprint to database.");
  }
}

int getAvailableID() {
  for (int id = 1; id < 128; id++) {
    if (finger.loadModel(id) != FINGERPRINT_OK) {
      return id; // Return the first available ID
    }
  }
  return -1; // No available ID
}
