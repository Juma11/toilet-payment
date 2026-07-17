# Public Toilet Payment System — Day-One Prototype (Single Door)

Scope: one door (`male`, KES 10), M-Pesa payment via Paystack, OTP entry to unlock.
Designed to scale to all 6 doors later — just deploy more firmware nodes with a
different `DOOR_ID`, and add their prices to `DOOR_PRICE_KES` on the server.

## 1. Backend setup

```bash
cd server
npm install
export PAYSTACK_SECRET_KEY=sk_test_your_real_key_here
npm start
```

Server runs on `http://localhost:3000` (or set `PORT`).

### Paystack dashboard setup
1. Get your **test** secret key from Paystack Dashboard → Settings → API Keys.
2. Set your webhook URL to `https://your-public-url/paystack/webhook`.
   - For local testing, use `ngrok http 3000` to expose your server and paste the
     ngrok URL into Paystack's webhook settings.
3. Confirm your Paystack account has **M-Pesa (mobile money)** enabled for Kenya —
   this may require KYC/business verification before it works with real charges.

### Test the flow with curl before touching hardware

```bash
# 1. Trigger a charge (use a Paystack test M-Pesa number if in test mode)
curl -X POST http://localhost:3000/charge \
  -H "Content-Type: application/json" \
  -d '{"phone":"0712345678","doorId":"male"}'

# 2. Simulate the webhook Paystack would send on success
curl -X POST http://localhost:3000/paystack/webhook \
  -H "Content-Type: application/json" \
  -d '{"event":"charge.success","data":{"reference":"PASTE_REFERENCE_FROM_STEP_1"}}'
# Check your server console — it logs the OTP since SMS sending is stubbed

# 3. Validate the OTP as the door would
curl -X POST http://localhost:3000/validate \
  -H "Content-Type: application/json" \
  -d '{"doorId":"male","otp":"PASTE_OTP_FROM_CONSOLE"}'
```

## 2. Firmware setup

1. Open `firmware/door_node.ino` in Arduino IDE (or PlatformIO).
2. Install libraries: `Keypad`, `LiquidCrystal_I2C`, `ArduinoJson`.
3. Edit the config block at the top: `WIFI_SSID`, `WIFI_PASSWORD`, `SERVER_BASE_URL`
   (your machine's LAN IP while testing, e.g. `http://192.168.1.100:3000`), `DOOR_ID`.
4. Wire it up:
   - Keypad rows → GPIO 13, 12, 14, 27
   - Keypad cols → GPIO 26, 25, 33, 32
   - Relay signal → GPIO 4
   - LCD (I2C) → SDA/SCL (GPIO 21/22 on most ESP32 dev boards)
5. **Check your relay module's logic level** — the firmware assumes active-LOW
   (LOW = unlocked). Some relay boards are active-HIGH; if the door unlocks when
   it should be locked, flip the `HIGH`/`LOW` in `unlockDoor()` and `setup()`.
6. Flash it, open Serial Monitor at 115200 baud to watch the HTTP request/response
   logs while you test.

## Known gaps before this goes to a real installation

- **In-memory transaction store** — restarting the server wipes all pending/paid
  transactions. Move to SQLite/Postgres before deploying.
- **No webhook signature verification** — the code has the check written but
  commented out. Uncomment it before going live so nobody can fake a "payment
  success" webhook.
- **SMS sending is a stub** — `sendSms()` just logs to console. Wire up
  Africa's Talking, Twilio, or another SMS gateway before this is usable without
  you standing next to the server reading logs.
- **Single points of failure** — if the ESP32 loses Wi-Fi mid-OTP-entry, it can't
  validate. Fine for a single-door pilot; worth a fallback (local whitelist sync
  or GSM backup) once you're running all 6 doors unattended.
