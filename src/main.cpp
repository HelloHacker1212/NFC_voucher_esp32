
#include <Wire.h>
#include <SPI.h>
#include <Adafruit_PN532.h>


// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
#define PN532_IRQ   (2)
#define PN532_RESET (3)  // Not connected by default on the NFC Shield

const int DELAY_BETWEEN_CARDS = 500;
long timeLastCardRead = 0;
boolean readerDisabled = false;
int irqCurr;
int irqPrev;

volatile boolean cardDetected = false;
bool irqDetectionArmed = false;
bool irqDetectionWarned = false;

constexpr uint8_t NTAG215_FIRST_USER_PAGE = 4;
constexpr uint8_t NTAG215_LAST_USER_PAGE = 129;
constexpr uint8_t NTAG215_CFG1_PAGE = 131;       // AUTH0 in byte 3
constexpr uint8_t NTAG215_ACCESS_PAGE = 132;     // ACCESS in byte 0, PROT bit is bit 7
constexpr uint8_t NTAG215_PWD_PAGE = 133;
constexpr uint8_t NTAG215_PACK_PAGE = 134;

enum PendingAction {
  ACTION_NONE,
  ACTION_ERASE,
  ACTION_WRITE,
  ACTION_SET_PASSWORD,
  ACTION_REMOVE_PASSWORD
};

PendingAction pendingAction = ACTION_NONE;
String pendingWriteText;
uint8_t pendingPassword[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t pendingPack[2] = { 0x00, 0x00 };

uint8_t currentPassword[4] = { 0xFF, 0xFF, 0xFF, 0xFF };


// This example uses the IRQ line, which is available when in I2C mode.
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);

//Adafruit_PN532 nfc(0x24);     // pn532 i2c adresse


void startListeningToNFC();
void handleCardDetected();
void processSerialCommands();
void printHelp();
void dumpTagPages(uint8_t firstPage, uint8_t lastPage);
bool eraseTagUserMemory();
bool writeStringToTag(const String& text);
bool setTagPassword(const uint8_t pwd[4], const uint8_t pack[2], uint8_t auth0);
bool removeTagPassword();
bool authenticateTag(const uint8_t pwd[4], uint8_t packOut[2]);
bool parseHexBytes(const String& hex, uint8_t* out, size_t outLen);
void printActionPrompt();

void IRAM_ATTR isrNFCCardDetected() {
  cardDetected = true;
}

void setup(void) {
  Serial.begin(115200);
  Serial.println("Hello from NFC reader!");
  pinMode(PN532_IRQ, INPUT_PULLUP);

  attachInterrupt(digitalPinToInterrupt(PN532_IRQ), isrNFCCardDetected, FALLING);
  Wire.begin(8, 9); // SDA, SCL
  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);

  if (!nfc.SAMConfig()) {
    Serial.println("SAMConfig failed");
    while (1);
  }

  startListeningToNFC();
  printHelp();
}

void loop(void) {
  processSerialCommands();

    
  if (cardDetected && !readerDisabled) {
    cardDetected = false;
    handleCardDetected();
    }
  // Fallback polling: some PN532 + ESP32-S3 setups don't deliver reliable IRQ.
  if (!readerDisabled && !irqDetectionArmed) {
    handleCardDetected();
  }
  if (readerDisabled && (millis() - timeLastCardRead > DELAY_BETWEEN_CARDS)) {
    readerDisabled = false;
    startListeningToNFC();
    // Serial.println("Reader enabled again, waiting for a card...");
  }
}

void handleCardDetected() {
    bool success = false;
    uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
    uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)

    // Prefer IRQ response if armed, otherwise (or on failure) use short polling read.
    if (irqDetectionArmed) {
    success = nfc.readDetectedPassiveTargetID(uid, &uidLength);
    }
    if (!success) {
      success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 30);
    }

    if (success) {
      Serial.println("Read successful");
      // Display some basic information about the card
      Serial.println("Found an ISO14443A card");
      Serial.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
      Serial.print("  UID Value: ");
      nfc.PrintHex(uid, uidLength);

      if (uidLength == 4)
      {
        // We probably have a Mifare Classic card ...
        uint32_t cardid = uid[0];
        cardid <<= 8;
        cardid |= uid[1];
        cardid <<= 8;
        cardid |= uid[2];
        cardid <<= 8;
        cardid |= uid[3];
        Serial.print("Seems to be a Mifare Classic card #");
        Serial.println(cardid);
      }
      Serial.println("");

      bool opSuccess = true;
      switch (pendingAction) {
        case ACTION_ERASE:
          Serial.println("Running erase...");
          opSuccess = eraseTagUserMemory();
          Serial.println(opSuccess ? "Erase finished." : "Erase failed.");
          pendingAction = ACTION_NONE;
          break;
        case ACTION_WRITE:
          Serial.println("Running write...");
          opSuccess = writeStringToTag(pendingWriteText);
          Serial.println(opSuccess ? "Write finished." : "Write failed.");
          pendingAction = ACTION_NONE;
          break;
        case ACTION_SET_PASSWORD:
          Serial.println("Running setPassword...");
          opSuccess = setTagPassword(pendingPassword, pendingPack, NTAG215_FIRST_USER_PAGE);
          if (opSuccess) {
            memcpy(currentPassword, pendingPassword, sizeof(currentPassword));
          }
          Serial.println(opSuccess ? "Password set." : "setPassword failed.");
          pendingAction = ACTION_NONE;
          break;
        case ACTION_REMOVE_PASSWORD:
          Serial.println("Running removePassword...");
          opSuccess = removeTagPassword();
          Serial.println(opSuccess ? "Password removed." : "removePassword failed.");
          pendingAction = ACTION_NONE;
          break;
        case ACTION_NONE:
        default:
          dumpTagPages(NTAG215_FIRST_USER_PAGE, NTAG215_LAST_USER_PAGE);
          break;
      }

      timeLastCardRead = millis();
    }

    // The reader will be enabled again after DELAY_BETWEEN_CARDS ms will pass.
    readerDisabled = true;
}

void startListeningToNFC() {
  irqDetectionArmed = nfc.startPassiveTargetIDDetection(PN532_MIFARE_ISO14443A);
  if (!irqDetectionArmed && !irqDetectionWarned) {
    Serial.println("IRQ detection could not be armed, using polling fallback.");
    irqDetectionWarned = true;
  }
}

void processSerialCommands() {
  if (!Serial.available()) {
    return;
  }

  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) {
    return;
  }

  String cmd = line;
  cmd.toLowerCase();

  if (cmd == "help") {
    printHelp();
    return;
  }

  if (cmd == "dump") {
    pendingAction = ACTION_NONE;
    printActionPrompt();
    return;
  }

  if (cmd == "erase") {
    pendingAction = ACTION_ERASE;
    printActionPrompt();
    return;
  }

  if (cmd.startsWith("write ")) {
    pendingWriteText = line.substring(6);
    if (pendingWriteText.length() == 0) {
      Serial.println("write braucht einen String.");
      return;
    }
    pendingAction = ACTION_WRITE;
    printActionPrompt();
    return;
  }

  if (cmd.startsWith("setpassword ")) {
    String rest = line.substring(12);
    rest.trim();
    int sep = rest.indexOf(' ');

    String pwdHex = rest;
    String packHex = "0000";
    if (sep >= 0) {
      pwdHex = rest.substring(0, sep);
      packHex = rest.substring(sep + 1);
      packHex.trim();
    }

    if (!parseHexBytes(pwdHex, pendingPassword, sizeof(pendingPassword))) {
      Serial.println("setpassword: Passwort muss 8 Hex-Zeichen haben (z.B. A1B2C3D4).");
      return;
    }
    if (!parseHexBytes(packHex, pendingPack, sizeof(pendingPack))) {
      Serial.println("setpassword: PACK muss 4 Hex-Zeichen haben (z.B. 1234).");
      return;
    }

    pendingAction = ACTION_SET_PASSWORD;
    printActionPrompt();
    return;
  }

  if (cmd == "removepassword") {
    pendingAction = ACTION_REMOVE_PASSWORD;
    printActionPrompt();
    return;
  }

  Serial.println("Unbekannter Befehl. 'help' fuer Hilfe.");
}

void printHelp() {
  Serial.println("");
  Serial.println("Befehle:");
  Serial.println("  dump");
  Serial.println("  erase");
  Serial.println("  write <text>");
  Serial.println("  setpassword <pwdHex8> [packHex4]");
  Serial.println("  removepassword");
  Serial.println("Beispiele:");
  Serial.println("  write Hallo Welt");
  Serial.println("  setpassword A1B2C3D4 1234");
  Serial.println("");
}

void printActionPrompt() {
  Serial.println("Befehl gespeichert. Tag auflegen.");
}

void dumpTagPages(uint8_t firstPage, uint8_t lastPage) {
  uint8_t pageData[4];
  String text = "";
  bool endOfText = false;

  Serial.println("Reading tag as string:");
  for (uint8_t page = firstPage; page <= lastPage; page++) {
    if (nfc.ntag2xx_ReadPage(page, pageData)) {
      for (uint8_t i = 0; i < 4; i++) {
        uint8_t c = pageData[i];
        if (c == 0x00 || c == 0xFE) {
          endOfText = true;
          break;
        }
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
          text += static_cast<char>(c);
        } else {
          text += '.';
        }
      }
      if (endOfText) {
        break;
      }
    } else {
      Serial.print("Read failed at page ");
      Serial.println(page);
      break;
    }
  }
  if (text.length() == 0) {
    Serial.println("(leer)");
  } else {
    Serial.println(text);
  }
  Serial.println("String read finished.");
}

bool eraseTagUserMemory() {
  uint8_t data[4] = { 0, 0, 0, 0 };
  for (uint8_t page = NTAG215_FIRST_USER_PAGE; page <= NTAG215_LAST_USER_PAGE; page++) {
    if (!nfc.ntag2xx_WritePage(page, data)) {
      Serial.print("Erase failed at page ");
      Serial.println(page);
      return false;
    }
  }
  return true;
}

bool writeStringToTag(const String& text) {
  const size_t maxUserBytes = (NTAG215_LAST_USER_PAGE - NTAG215_FIRST_USER_PAGE + 1) * 4;
  const size_t payloadBytes = text.length() + 1;  // Include terminating 0x00.
  if (payloadBytes > maxUserBytes) {
    Serial.print("String zu lang. Max Bytes inkl. Terminator: ");
    Serial.println(maxUserBytes);
    return false;
  }

  if (!eraseTagUserMemory()) {
    return false;
  }

  size_t srcIndex = 0;
  for (uint8_t page = NTAG215_FIRST_USER_PAGE; page <= NTAG215_LAST_USER_PAGE; page++) {
    uint8_t data[4] = { 0, 0, 0, 0 };
    for (uint8_t i = 0; i < 4; i++) {
      if (srcIndex < text.length()) {
        data[i] = static_cast<uint8_t>(text[srcIndex++]);
      } else if (srcIndex == text.length()) {
        data[i] = 0x00;
        srcIndex++;
      }
    }

    if (!nfc.ntag2xx_WritePage(page, data)) {
      Serial.print("Write failed at page ");
      Serial.println(page);
      return false;
    }

    if (srcIndex > text.length()) {
      break;
    }
  }

  return true;
}

bool authenticateTag(const uint8_t pwd[4], uint8_t packOut[2]) {
  uint8_t cmd[5] = { 0x1B, pwd[0], pwd[1], pwd[2], pwd[3] };  // PWD_AUTH
  uint8_t resp[8] = { 0 };
  uint8_t respLen = sizeof(resp);
  if (!nfc.inDataExchange(cmd, sizeof(cmd), resp, &respLen)) {
    return false;
  }
  if (respLen < 2) {
    return false;
  }
  packOut[0] = resp[0];
  packOut[1] = resp[1];
  return true;
}

bool setTagPassword(const uint8_t pwd[4], const uint8_t pack[2], uint8_t auth0) {
  uint8_t cfg1[4] = { 0 };
  uint8_t access[4] = { 0 };
  uint8_t packPage[4] = { pack[0], pack[1], 0x00, 0x00 };

  if (!nfc.ntag2xx_WritePage(NTAG215_PWD_PAGE, const_cast<uint8_t*>(pwd))) {
    Serial.println("Write PWD failed.");
    return false;
  }
  if (!nfc.ntag2xx_WritePage(NTAG215_PACK_PAGE, packPage)) {
    Serial.println("Write PACK failed.");
    return false;
  }

  if (!nfc.ntag2xx_ReadPage(NTAG215_ACCESS_PAGE, access)) {
    Serial.println("Read ACCESS page failed.");
    return false;
  }
  access[0] |= 0x80;  // PROT=1 (read+write protection from AUTH0)
  if (!nfc.ntag2xx_WritePage(NTAG215_ACCESS_PAGE, access)) {
    Serial.println("Write ACCESS page failed.");
    return false;
  }

  if (!nfc.ntag2xx_ReadPage(NTAG215_CFG1_PAGE, cfg1)) {
    Serial.println("Read CFG1 page failed.");
    return false;
  }
  cfg1[3] = auth0;
  if (!nfc.ntag2xx_WritePage(NTAG215_CFG1_PAGE, cfg1)) {
    Serial.println("Write CFG1 page failed.");
    return false;
  }

  return true;
}

bool removeTagPassword() {
  uint8_t packOut[2] = { 0 };
  if (!authenticateTag(currentPassword, packOut)) {
    Serial.println("PWD_AUTH failed (falsches oder unbekanntes Passwort?).");
  } else {
    Serial.print("PWD_AUTH ok, PACK=");
    nfc.PrintHex(packOut, 2);
  }

  uint8_t cfg1[4] = { 0 };
  if (!nfc.ntag2xx_ReadPage(NTAG215_CFG1_PAGE, cfg1)) {
    Serial.println("Read CFG1 page failed.");
    return false;
  }
  cfg1[3] = 0xFF;  // Disable password protection
  if (!nfc.ntag2xx_WritePage(NTAG215_CFG1_PAGE, cfg1)) {
    Serial.println("Write CFG1 page failed.");
    return false;
  }

  uint8_t access[4] = { 0 };
  if (!nfc.ntag2xx_ReadPage(NTAG215_ACCESS_PAGE, access)) {
    Serial.println("Read ACCESS page failed.");
    return false;
  }
  access[0] &= 0x7F;  // PROT=0
  if (!nfc.ntag2xx_WritePage(NTAG215_ACCESS_PAGE, access)) {
    Serial.println("Write ACCESS page failed.");
    return false;
  }

  uint8_t defaultPwd[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
  uint8_t defaultPack[4] = { 0x00, 0x00, 0x00, 0x00 };
  if (!nfc.ntag2xx_WritePage(NTAG215_PWD_PAGE, defaultPwd)) {
    Serial.println("Reset PWD failed.");
    return false;
  }
  if (!nfc.ntag2xx_WritePage(NTAG215_PACK_PAGE, defaultPack)) {
    Serial.println("Reset PACK failed.");
    return false;
  }

  memcpy(currentPassword, defaultPwd, sizeof(currentPassword));
  return true;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

bool parseHexBytes(const String& hex, uint8_t* out, size_t outLen) {
  if (hex.length() != outLen * 2) {
    return false;
  }
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexValue(hex[i * 2]);
    int lo = hexValue(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}
