#include <WiFi.h>
#include <PubSubClient.h>
#include <PQCMicro.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <esp_random.h>
#include <string.h>

// ---------------- Hardware ----------------
const uint8_t BUTTON_PIN = 4;
const unsigned long DEBOUNCE_MS = 50;

// ---------------- Wi-Fi ----------------
const char* WIFI_SSID     = "Hajjaj2020";
const char* WIFI_PASSWORD = "tSk@2014";

// ---------------- MQTT ----------------
const char* MQTT_BROKER   = "192.168.0.228";
const uint16_t MQTT_PORT  = 1883;
const char* MQTT_USERNAME = "senderuser";
const char* MQTT_PASSWORD = "sendersecure2026";

const char* TOPIC_PUBLIC_KEY = "pqc/publickey";
const char* TOPIC_CIPHERTEXT = "pqc/ciphertext";
const char* TOPIC_SECURE_DATA = "secure/data";

// ---------------- ML-KEM-512 ----------------
const size_t PUBLIC_KEY_HEX_LENGTH = 1600;
const size_t CIPHERTEXT_HEX_LENGTH = 1536;
const size_t SHARED_SECRET_LENGTH  = 32;

// ---------------- Secure packet ----------------
const uint8_t PACKET_MAGIC_0 = 'S';
const uint8_t PACKET_MAGIC_1 = 'I';
const uint8_t PACKET_VERSION = 2;

const size_t NONCE_SIZE = 12;
const size_t TAG_SIZE = 16;
const size_t HEADER_SIZE = 17;

const uint8_t COMMAND_LED_OFF = 0;
const uint8_t COMMAND_LED_ON  = 1;

const size_t ENCRYPTED_PAYLOAD_SIZE = 9;  // 8-byte counter + 1-byte command
const size_t SECURE_PACKET_SIZE =
  HEADER_SIZE + ENCRYPTED_PAYLOAD_SIZE + TAG_SIZE;

// Required because ML-KEM values are transported as long hexadecimal strings.
const uint16_t MQTT_BUFFER_SIZE = 4096;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);
PQCKyber bob;

String pendingPublicKeyHex;
String activePublicKeyHex;
String lastCompletedPublicKeyHex;
String ciphertextHexToPublish;

bool publicKeyPending = false;
bool ciphertextPublishPending = false;
bool sharedSecretReady = false;

unsigned long lastCiphertextPublishAttempt = 0;

uint32_t sessionId = 0;
uint64_t nextCounter = 1;

// Button state.
bool lastRawButtonState = HIGH;
bool stableButtonState = HIGH;
unsigned long lastDebounceTime = 0;
bool requestedLedState = false;

// Exact previous packet, saved for replay demonstration.
uint8_t lastSecurePacket[SECURE_PACKET_SIZE];
size_t lastSecurePacketLength = 0;


// ------------------------------------------------------------
// Byte-order helpers
// ------------------------------------------------------------
void writeUint16BE(uint8_t* output, uint16_t value)
{
  output[0] = (uint8_t)(value >> 8);
  output[1] = (uint8_t)value;
}

void writeUint32BE(uint8_t* output, uint32_t value)
{
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

void writeUint64BE(uint8_t* output, uint64_t value)
{
  for (int i = 7; i >= 0; i--)
  {
    output[i] = (uint8_t)value;
    value >>= 8;
  }
}


// ------------------------------------------------------------
// Serial helpers
// ------------------------------------------------------------
void printHex(const uint8_t* data, size_t length)
{
  for (size_t i = 0; i < length; i++)
  {
    if (data[i] < 0x10)
    {
      Serial.print('0');
    }

    Serial.print(data[i], HEX);
  }

  Serial.println();
}


// ------------------------------------------------------------
// Key fingerprint
//
// The full ML-KEM shared secret is never printed.
// Instead, calculate SHA-256(sharedSecret) and print only the
// first 8 digest bytes (16 hexadecimal characters).
// Alice and Bob must display the same fingerprint.
// ------------------------------------------------------------
bool calculateSha256(
  const uint8_t* input,
  size_t inputLength,
  uint8_t output[32]
)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_sha256(
    input,
    inputLength,
    output,
    0
  ) == 0;
#else
  return mbedtls_sha256_ret(
    input,
    inputLength,
    output,
    0
  ) == 0;
#endif
}


void printKeyFingerprint(
  const uint8_t* sharedSecret,
  size_t secretLength
)
{
  uint8_t digest[32];

  if (!calculateSha256(sharedSecret, secretLength, digest))
  {
    Serial.println("Key fingerprint calculation failed.");
    return;
  }

  Serial.print("Key fingerprint: ");
  printHex(digest, 8);
}


void printUint64(uint64_t value)
{
  char text[24];

  snprintf(
    text,
    sizeof(text),
    "%llu",
    (unsigned long long)value
  );

  Serial.print(text);
}


// ------------------------------------------------------------
// Unique MQTT client ID
// ------------------------------------------------------------
String makeClientId()
{
  uint64_t chipId = ESP.getEfuseMac();
  char clientId[40];

  snprintf(
    clientId,
    sizeof(clientId),
    "ESP32-Bob-%04X%08X",
    (uint16_t)(chipId >> 32),
    (uint32_t)chipId
  );

  return String(clientId);
}


// ------------------------------------------------------------
// Wi-Fi
// ------------------------------------------------------------
void connectWiFi()
{
  if (WiFi.status() == WL_CONNECTED)
  {
    return;
  }

  Serial.print("Connecting to Wi-Fi");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print('.');
  }

  Serial.println();
  Serial.print("Wi-Fi connected. ESP32 IP: ");
  Serial.println(WiFi.localIP());
}


// ------------------------------------------------------------
// MQTT
// ------------------------------------------------------------
void connectMQTT()
{
  while (!mqttClient.connected())
  {
    connectWiFi();

    String clientId = makeClientId();

    Serial.print("Connecting to MQTT as ");
    Serial.print(clientId);
    Serial.print("...");

    bool connected = mqttClient.connect(
      clientId.c_str(),
      MQTT_USERNAME,
      MQTT_PASSWORD
    );

    if (connected)
    {
      Serial.println("connected.");

      if (mqttClient.subscribe(TOPIC_PUBLIC_KEY, 1))
      {
        Serial.println("Subscribed to pqc/publickey.");
      }
      else
      {
        Serial.println("ERROR: Could not subscribe to pqc/publickey.");
      }
    }
    else
    {
      Serial.print("failed, MQTT state = ");
      Serial.print(mqttClient.state());
      Serial.println(". Retrying in 2 seconds.");
      delay(2000);
    }
  }
}


// ------------------------------------------------------------
// MQTT callback
// Rejects duplicate Alice keys while an exchange is pending,
// active, or already completed.
// ------------------------------------------------------------
void mqttCallback(char* topic, byte* payload, unsigned int length)
{
  if (strcmp(topic, TOPIC_PUBLIC_KEY) != 0)
  {
    return;
  }

  if (length != PUBLIC_KEY_HEX_LENGTH)
  {
    Serial.print("ERROR: Rejected public key. Expected ");
    Serial.print(PUBLIC_KEY_HEX_LENGTH);
    Serial.print(" characters, received ");
    Serial.println(length);
    return;
  }

  String incomingPublicKeyHex;
  incomingPublicKeyHex.reserve(length);

  for (unsigned int i = 0; i < length; i++)
  {
    incomingPublicKeyHex += (char)payload[i];
  }

  if (incomingPublicKeyHex == activePublicKeyHex)
  {
    Serial.println(
      "Duplicate public key ignored: exchange already in progress."
    );
    return;
  }

  if (incomingPublicKeyHex == lastCompletedPublicKeyHex)
  {
    Serial.println(
      "Duplicate public key ignored: exchange already complete."
    );
    return;
  }

  if (publicKeyPending &&
      incomingPublicKeyHex == pendingPublicKeyHex)
  {
    Serial.println(
      "Duplicate public key ignored: same key already pending."
    );
    return;
  }

  pendingPublicKeyHex = incomingPublicKeyHex;
  publicKeyPending = true;

  Serial.println("New Alice public key received.");
}


// ------------------------------------------------------------
// ML-KEM encapsulation
// ------------------------------------------------------------
void processPublicKey()
{
  if (!publicKeyPending)
  {
    return;
  }

  publicKeyPending = false;

  if (pendingPublicKeyHex == activePublicKeyHex ||
      pendingPublicKeyHex == lastCompletedPublicKeyHex)
  {
    pendingPublicKeyHex = "";
    return;
  }

  activePublicKeyHex = pendingPublicKeyHex;
  pendingPublicKeyHex = "";

  sharedSecretReady = false;
  lastSecurePacketLength = 0;
  requestedLedState = false;

  if (!bob.setPublicKeyHex(activePublicKeyHex.c_str()))
  {
    Serial.println("ERROR: setPublicKeyHex() rejected Alice's key.");
    activePublicKeyHex = "";
    return;
  }

  Serial.println("Encapsulating with Alice's public key...");

  bob.encapsulate(bob.getPublicKey());
  ciphertextHexToPublish = bob.getCiphertextHex();

  Serial.print("Generated ciphertext hex length: ");
  Serial.println(ciphertextHexToPublish.length());

  if (ciphertextHexToPublish.length() != CIPHERTEXT_HEX_LENGTH)
  {
    Serial.println("ERROR: Unexpected ML-KEM-512 ciphertext length.");
    ciphertextHexToPublish = "";
    activePublicKeyHex = "";
    return;
  }

  ciphertextPublishPending = true;
  lastCiphertextPublishAttempt = 0;
}


// ------------------------------------------------------------
// Publish ML-KEM ciphertext and activate secure session
// ------------------------------------------------------------
void publishCiphertextWhenReady()
{
  if (!ciphertextPublishPending || !mqttClient.connected())
  {
    return;
  }

  unsigned long now = millis();

  if (lastCiphertextPublishAttempt != 0 &&
      now - lastCiphertextPublishAttempt < 1000)
  {
    return;
  }

  lastCiphertextPublishAttempt = now;

  Serial.println("Publishing ciphertext on pqc/ciphertext...");

  bool published = mqttClient.publish(
    TOPIC_CIPHERTEXT,
    ciphertextHexToPublish.c_str(),
    false
  );

  if (!published)
  {
    Serial.println("ERROR: Ciphertext publish failed. Will retry.");
    return;
  }

  ciphertextPublishPending = false;
  sharedSecretReady = true;
  lastCompletedPublicKeyHex = activePublicKeyHex;

  ciphertextHexToPublish = "";
  activePublicKeyHex = "";

  sessionId = esp_random();

  if (sessionId == 0)
  {
    sessionId = 1;
  }

  nextCounter = 1;
  requestedLedState = false;
  lastSecurePacketLength = 0;

  Serial.println("Ciphertext published successfully.");
  Serial.println();
  Serial.println("========================================");
  Serial.println("BOB: ML-KEM-512 SHARED SECRET READY");
  printKeyFingerprint(bob.getSharedSecret(), SHARED_SECRET_LENGTH);
  Serial.print("AES-GCM Session ID: 0x");
  Serial.println(sessionId, HEX);
  Serial.println("Press the GPIO 4 button to toggle Alice's LED.");
  Serial.println("Serial attack-test commands:");
  Serial.println("  r = replay last valid packet");
  Serial.println("  t = send tampered packet");
  Serial.println("  s = send spoofed/forged packet");
  Serial.println("========================================");
  Serial.println();
}


// ------------------------------------------------------------
// Build a valid AES-256-GCM packet without publishing it.
//
// A unique counter is supplied by the caller. The counter must
// never be reused with the same shared key and session ID.
// ------------------------------------------------------------
bool buildEncryptedLedPacket(
  bool turnLedOn,
  uint64_t messageCounter,
  uint8_t packet[SECURE_PACKET_SIZE]
)
{
  memset(packet, 0, SECURE_PACKET_SIZE);

  // Header authenticated as AES-GCM AAD.
  packet[0] = PACKET_MAGIC_0;
  packet[1] = PACKET_MAGIC_1;
  packet[2] = PACKET_VERSION;

  writeUint32BE(packet + 3, sessionId);
  writeUint64BE(packet + 7, messageCounter);
  writeUint16BE(packet + 15, ENCRYPTED_PAYLOAD_SIZE);

  // Counter is also protected inside the encrypted plaintext.
  uint8_t plaintext[ENCRYPTED_PAYLOAD_SIZE];
  writeUint64BE(plaintext, messageCounter);
  plaintext[8] = turnLedOn ? COMMAND_LED_ON : COMMAND_LED_OFF;

  // Nonce = session ID || counter.
  uint8_t nonce[NONCE_SIZE];
  memcpy(nonce, packet + 3, NONCE_SIZE);

  uint8_t* ciphertext = packet + HEADER_SIZE;
  uint8_t* tag = packet + HEADER_SIZE + ENCRYPTED_PAYLOAD_SIZE;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int result = mbedtls_gcm_setkey(
    &gcm,
    MBEDTLS_CIPHER_ID_AES,
    bob.getSharedSecret(),
    256
  );

  if (result == 0)
  {
    result = mbedtls_gcm_crypt_and_tag(
      &gcm,
      MBEDTLS_GCM_ENCRYPT,
      ENCRYPTED_PAYLOAD_SIZE,
      nonce,
      NONCE_SIZE,
      packet,
      HEADER_SIZE,
      plaintext,
      ciphertext,
      TAG_SIZE,
      tag
    );
  }

  mbedtls_gcm_free(&gcm);

  if (result != 0)
  {
    Serial.print("ERROR: AES-GCM encryption failed, code ");
    Serial.println(result);
    return false;
  }

  return true;
}


// ------------------------------------------------------------
// Encrypt and publish a legitimate LED command.
// ------------------------------------------------------------
bool encryptAndPublishLedState(bool turnLedOn)
{
  if (!sharedSecretReady)
  {
    Serial.println("Button ignored: secure session is not ready.");
    return false;
  }

  if (!mqttClient.connected())
  {
    Serial.println("Button ignored: MQTT is disconnected.");
    return false;
  }

  const uint64_t messageCounter = nextCounter;
  uint8_t packet[SECURE_PACKET_SIZE];

  if (!buildEncryptedLedPacket(
        turnLedOn,
        messageCounter,
        packet
      ))
  {
    return false;
  }

  bool published = mqttClient.publish(
    TOPIC_SECURE_DATA,
    packet,
    SECURE_PACKET_SIZE,
    false
  );

  if (!published)
  {
    Serial.println("ERROR: secure/data publish failed.");
    return false;
  }

  memcpy(lastSecurePacket, packet, SECURE_PACKET_SIZE);
  lastSecurePacketLength = SECURE_PACKET_SIZE;

  // This nonce/counter has now been used.
  nextCounter++;

  const uint8_t* tag =
    packet + HEADER_SIZE + ENCRYPTED_PAYLOAD_SIZE;

  Serial.println();
  Serial.println("========================================");
  Serial.println("ENCRYPTED BUTTON MESSAGE PUBLISHED");
  Serial.print("Counter: ");
  printUint64(messageCounter);
  Serial.println();
  Serial.print("Requested LED state: ");
  Serial.println(turnLedOn ? "ON" : "OFF");
  Serial.print("AES-GCM tag: ");
  printHex(tag, TAG_SIZE);
  Serial.println("========================================");
  Serial.println();

  return true;
}


// ------------------------------------------------------------
// Debounced physical button.
// ------------------------------------------------------------
void handleButton()
{
  bool rawState = digitalRead(BUTTON_PIN);

  if (rawState != lastRawButtonState)
  {
    lastDebounceTime = millis();
    lastRawButtonState = rawState;
  }

  if (millis() - lastDebounceTime < DEBOUNCE_MS)
  {
    return;
  }

  if (rawState != stableButtonState)
  {
    stableButtonState = rawState;

    // INPUT_PULLUP: LOW is a press.
    if (stableButtonState == LOW)
    {
      bool newLedState = !requestedLedState;

      if (encryptAndPublishLedState(newLedState))
      {
        requestedLedState = newLedState;
      }
    }
  }
}


// ------------------------------------------------------------
// Replay test: republish the exact last valid packet.
// Alice should reject it on the counter check.
// ------------------------------------------------------------
bool publishReplayPacket()
{
  if (!sharedSecretReady ||
      !mqttClient.connected() ||
      lastSecurePacketLength == 0)
  {
    Serial.println(
      "Replay unavailable: send at least one button message first."
    );
    return false;
  }

  Serial.println();
  Serial.println("========================================");
  Serial.println("REPLAY TEST: REPUBLISHING OLD PACKET");
  Serial.println("Alice should reject it on the counter check.");
  Serial.println("Alice's LED must NOT change.");
  Serial.println("========================================");
  Serial.println();

  bool published = mqttClient.publish(
    TOPIC_SECURE_DATA,
    lastSecurePacket,
    lastSecurePacketLength,
    false
  );

  if (published)
  {
    Serial.println("Replay packet published.");
  }
  else
  {
    Serial.println("ERROR: Replay packet publish failed.");
  }

  return published;
}


// ------------------------------------------------------------
// Tampering test:
// 1. Create a valid encrypted packet with a fresh counter.
// 2. Flip one ciphertext bit after the GCM tag was generated.
// 3. Publish the corrupted packet.
//
// Alice should reach AES-GCM verification, report an
// authentication failure, and leave the LED unchanged.
// ------------------------------------------------------------
bool publishTamperedPacket()
{
  if (!sharedSecretReady || !mqttClient.connected())
  {
    Serial.println(
      "Tampering test unavailable: secure session is not ready."
    );
    return false;
  }

  const uint64_t attackCounter = nextCounter;
  const bool attackedLedState = !requestedLedState;
  uint8_t tamperedPacket[SECURE_PACKET_SIZE];

  if (!buildEncryptedLedPacket(
        attackedLedState,
        attackCounter,
        tamperedPacket
      ))
  {
    return false;
  }

  // Corrupt one ciphertext bit after authentication tag creation.
  tamperedPacket[HEADER_SIZE] ^= 0x01;

  bool published = mqttClient.publish(
    TOPIC_SECURE_DATA,
    tamperedPacket,
    SECURE_PACKET_SIZE,
    false
  );

  if (!published)
  {
    Serial.println("ERROR: Tampered packet publish failed.");
    return false;
  }

  // This counter/nonce was used to create a packet. Never reuse it.
  nextCounter++;

  Serial.println();
  Serial.println("========================================");
  Serial.println("TAMPERING TEST PACKET PUBLISHED");
  Serial.print("Fresh counter: ");
  printUint64(attackCounter);
  Serial.println();
  Serial.println("One ciphertext bit was modified.");
  Serial.println("Alice should report AES-GCM authentication failure.");
  Serial.println("Alice's LED must NOT change.");
  Serial.println("========================================");
  Serial.println();

  return true;
}


// ------------------------------------------------------------
// Spoofing test:
// Create a correctly formatted packet with the active session ID
// and a fresh counter, but use attacker-generated random bytes as
// the ciphertext and tag. The attacker does not know the AES key.
// ------------------------------------------------------------
bool publishSpoofedPacket()
{
  if (!sharedSecretReady || !mqttClient.connected())
  {
    Serial.println(
      "Spoofing test unavailable: secure session is not ready."
    );
    return false;
  }

  const uint64_t attackCounter = nextCounter;
  uint8_t spoofedPacket[SECURE_PACKET_SIZE];
  memset(spoofedPacket, 0, sizeof(spoofedPacket));

  spoofedPacket[0] = PACKET_MAGIC_0;
  spoofedPacket[1] = PACKET_MAGIC_1;
  spoofedPacket[2] = PACKET_VERSION;

  writeUint32BE(spoofedPacket + 3, sessionId);
  writeUint64BE(spoofedPacket + 7, attackCounter);
  writeUint16BE(
    spoofedPacket + 15,
    ENCRYPTED_PAYLOAD_SIZE
  );

  // Attacker-controlled forged ciphertext and forged tag.
  for (size_t i = HEADER_SIZE;
       i < SECURE_PACKET_SIZE;
       i++)
  {
    spoofedPacket[i] = (uint8_t)(esp_random() & 0xFF);
  }

  bool published = mqttClient.publish(
    TOPIC_SECURE_DATA,
    spoofedPacket,
    SECURE_PACKET_SIZE,
    false
  );

  if (!published)
  {
    Serial.println("ERROR: Spoofed packet publish failed.");
    return false;
  }

  // Consume this counter so it is not reused later.
  nextCounter++;

  Serial.println();
  Serial.println("========================================");
  Serial.println("SPOOFING TEST PACKET PUBLISHED");
  Serial.print("Fresh counter: ");
  printUint64(attackCounter);
  Serial.println();
  Serial.println("Ciphertext and tag were forged without the AES key.");
  Serial.println("Alice should report AES-GCM authentication failure.");
  Serial.println("Alice's LED must NOT change.");
  Serial.println("========================================");
  Serial.println();

  return true;
}


void handleSerialCommands()
{
  while (Serial.available() > 0)
  {
    char command = (char)Serial.read();

    if (command == 'r' || command == 'R')
    {
      publishReplayPacket();
    }
    else if (command == 't' || command == 'T')
    {
      publishTamperedPacket();
    }
    else if (command == 's' || command == 'S')
    {
      publishSpoofedPacket();
    }
  }
}


// ------------------------------------------------------------
// Arduino setup / loop
// ------------------------------------------------------------
void setup()
{
  Serial.begin(115200);
  delay(1000);

  pinMode(BUTTON_PIN, INPUT_PULLUP);

  lastRawButtonState = digitalRead(BUTTON_PIN);
  stableButtonState = lastRawButtonState;

  Serial.println();
  Serial.println("ESP32 Sender / Bob starting...");
  Serial.println("Button configured on GPIO 4 using INPUT_PULLUP.");

  pendingPublicKeyHex.reserve(PUBLIC_KEY_HEX_LENGTH);
  activePublicKeyHex.reserve(PUBLIC_KEY_HEX_LENGTH);
  lastCompletedPublicKeyHex.reserve(PUBLIC_KEY_HEX_LENGTH);
  ciphertextHexToPublish.reserve(CIPHERTEXT_HEX_LENGTH);

  connectWiFi();

  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(MQTT_BUFFER_SIZE);
  mqttClient.setKeepAlive(30);

  connectMQTT();
}


void loop()
{
  if (WiFi.status() != WL_CONNECTED)
  {
    connectWiFi();
  }

  if (!mqttClient.connected())
  {
    connectMQTT();
  }

  mqttClient.loop();

  processPublicKey();
  publishCiphertextWhenReady();
  handleButton();
  handleSerialCommands();

  delay(2);
}