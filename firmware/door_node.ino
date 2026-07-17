/*
  Public Toilet Payment System — Door Node Firmware (ESP32)
  ------------------------------------------------------------
  Flow:
    1. Idle screen shows price, prompts "# to pay"
    2. User keys in phone number (0712345678) -> POST /charge
    3. Screen shows "Enter code sent by SMS"
    4. User keys in 6-digit OTP -> POST /validate
    5. If valid: fire relay, show "Door Open", auto-relock after RELOCK_MS

  Hardware:
    - 4x4 matrix keypad
    - 16x2 I2C LCD (address 0x27, change if yours differs)
    - Relay module (active LOW typical — check your relay board)

  Libraries needed (Arduino Library Manager):
    - Keypad by Mark Stanley / Alexander Brevig
    - LiquidCrystal_I2C by Frank de Brabander (or johnrickman fork)
    - ArduinoJson by Benoit Blanchon
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Keypad.h>
#include <LiquidCrystal_I2C.h>

// ---- Config: EDIT THESE ----
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* SERVER_BASE_URL = "http://192.168.1.100:3000"; // your backend's LAN/public IP
const char* DOOR_ID = "male";                                // must match a key in DOOR_PRICE_KES on the server
const int PRICE_KES = 10;                                    // shown on screen only; server is source of truth

// ---- Pins ----
const int RELAY_PIN = 4;
const unsigned long RELOCK_MS = 5000;       // how long the door stays unlocked
const unsigned long OTP_WAIT_TIMEOUT_MS = 120000; // give up waiting for OTP after 2 min

// ---- Keypad setup (4x4) ----
const byte ROWS = 4, COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {13, 12, 14, 27}; // adjust to your wiring
byte colPins[COLS] = {26, 25, 33, 32}; // no clash with RELAY_PIN (GPIO4) or the LCD's I2C pins (21/22 default)
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

LiquidCrystal_I2C lcd(0x27, 16, 2);

// ---- State machine ----
enum State { IDLE, ENTERING_PHONE, AWAITING_PAYMENT, ENTERING_OTP, UNLOCKED };
State state = IDLE;

String inputBuffer = "";
unsigned long stateEnteredAt = 0;

void setup() {
  Serial.begin(115200);
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH); // HIGH = locked for an active-LOW relay module — verify against your board

  lcd.init();
  lcd.backlight();

  connectWifi();
  goToIdle();
}

void loop() {
  char key = keypad.getKey();

  switch (state) {
    case IDLE:
      if (key) {
        state = ENTERING_PHONE;
        inputBuffer = "";
        stateEnteredAt = millis();
        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("Enter phone:");
        handleKey(key); // process the key that triggered the transition
      }
      break;

    case ENTERING_PHONE:
      if (key) handleKey(key);
      break;

    case AWAITING_PAYMENT:
      // Screen just shows a wait message; nothing to do here except timeout
      if (millis() - stateEnteredAt > OTP_WAIT_TIMEOUT_MS) {
        showMessage("Payment timeout", "Try again");
        delay(2000);
        goToIdle();
      }
      break;

    case ENTERING_OTP:
      if (key) handleKey(key);
      if (millis() - stateEnteredAt > OTP_WAIT_TIMEOUT_MS) {
        showMessage("Code timeout", "Try again");
        delay(2000);
        goToIdle();
      }
      break;

    case UNLOCKED:
      // handled synchronously in unlockDoor(); nothing to do here
      break;
  }
}

void handleKey(char key) {
  if (key == '#') {
    // Submit whatever's in the buffer
    if (state == ENTERING_PHONE) {
      submitPhone();
    } else if (state == ENTERING_OTP) {
      submitOtp();
    }
  } else if (key == '*') {
    // Clear / backspace
    inputBuffer = "";
    lcd.setCursor(0, 1);
    lcd.print("                "); // clear line
  } else if (key >= '0' && key <= '9') {
    inputBuffer += key;
    lcd.setCursor(0, 1);
    lcd.print(inputBuffer);
  }
  // A/B/C/D unused for now
}

void submitPhone() {
  if (inputBuffer.length() < 9) {
    showMessage("Invalid number", "Try again");
    delay(1500);
    inputBuffer = "";
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Enter phone:");
    return;
  }

  showMessage("Sending STK", "push...");

  StaticJsonDocument<200> body;
  body["phone"] = inputBuffer;
  body["doorId"] = DOOR_ID;

  String response;
  int httpCode = postJson("/charge", body, response);

  if (httpCode == 200) {
    showMessage("Check your phone", "Enter M-Pesa PIN");
    delay(3000);
    showMessage("Then enter code", "sent via SMS:");
    state = ENTERING_OTP;
    inputBuffer = "";
    stateEnteredAt = millis();
  } else {
    showMessage("Payment failed", "Try again");
    delay(2500);
    goToIdle();
  }
}

void submitOtp() {
  if (inputBuffer.length() != 6) {
    showMessage("Code must be", "6 digits");
    delay(1500);
    inputBuffer = "";
    return;
  }

  showMessage("Checking code", "...");

  StaticJsonDocument<200> body;
  body["doorId"] = DOOR_ID;
  body["otp"] = inputBuffer;

  String response;
  int httpCode = postJson("/validate", body, response);

  StaticJsonDocument<200> resDoc;
  deserializeJson(resDoc, response);
  bool valid = resDoc["valid"] | false;

  if (httpCode == 200 && valid) {
    unlockDoor();
  } else {
    const char* reason = resDoc["reason"] | "Invalid code";
    showMessage("Denied:", reason);
    delay(2500);
    inputBuffer = "";
    stateEnteredAt = millis(); // give them another shot within the timeout window
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Re-enter code:");
  }
}

void unlockDoor() {
  state = UNLOCKED;
  digitalWrite(RELAY_PIN, LOW); // unlock (active-LOW relay assumption)
  showMessage("Door Open", "Welcome!");
  delay(RELOCK_MS);
  digitalWrite(RELAY_PIN, HIGH); // relock
  goToIdle();
}

// ---- Helpers ----

void connectWifi() {
  lcd.clear();
  lcd.print("Connecting WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected: " + WiFi.localIP().toString());
}

int postJson(const char* path, JsonDocument& body, String& response) {
  if (WiFi.status() != WL_CONNECTED) {
    connectWifi();
  }

  HTTPClient http;
  http.begin(String(SERVER_BASE_URL) + path);
  http.addHeader("Content-Type", "application/json");

  String payload;
  serializeJson(body, payload);

  int httpCode = http.POST(payload);
  response = http.getString();
  http.end();

  Serial.printf("POST %s -> %d: %s\n", path, httpCode, response.c_str());
  return httpCode;
}

void goToIdle() {
  state = IDLE;
  inputBuffer = "";
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Pay KES ");
  lcd.print(PRICE_KES);
  lcd.setCursor(0, 1);
  lcd.print("Press any key");
}

void showMessage(const char* line1, const char* line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  lcd.print(line2);
}
