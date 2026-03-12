#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include "credentials.h"

#if ESP_IDF_VERSION_MAJOR >= 5
	#include <esp_eap_client.h>
#else
	#include "esp_wpa2.h" //Nur bei Schulnetz notwendig
#endif

#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <Adafruit_PN532.h>
#include <Adafruit_NeoPixel.h>
#include <LittleFS.h>



// PN532 over I2C with IRQ/RESET lines
constexpr uint8_t PN532_IRQ_PIN = 2;
constexpr uint8_t PN532_RESET_PIN = 3;
constexpr uint8_t I2C_SDA_PIN = 9;
constexpr uint8_t I2C_SCL_PIN = 8;
constexpr uint8_t STATUS_LED_PIN = 48;
constexpr uint8_t STATUS_LED_COUNT = 1;

// NTAG215 layout
constexpr uint8_t NTAG215_FIRST_USER_PAGE = 4;
constexpr uint8_t NTAG215_LAST_USER_PAGE = 129;
constexpr uint8_t NTAG215_CFG1_PAGE = 131;    // AUTH0 in byte 3
constexpr uint8_t NTAG215_ACCESS_PAGE = 132;  // PROT bit in byte 0 bit 7
constexpr uint8_t NTAG215_PWD_PAGE = 133;
constexpr uint8_t NTAG215_PACK_PAGE = 134;

constexpr uint16_t TAG_WAIT_TIMEOUT_MS = 3500;
constexpr uint8_t UID_READ_ATTEMPTS = 4;
constexpr uint8_t PAGE_READ_ATTEMPTS = 4;
constexpr uint8_t PAGE_WRITE_ATTEMPTS = 3;


Adafruit_PN532 nfc(PN532_IRQ_PIN, PN532_RESET_PIN);
AsyncWebServer server(80);
Adafruit_NeoPixel statusLed(STATUS_LED_COUNT, STATUS_LED_PIN, NEO_GRB + NEO_KHZ800);
uint32_t apiRequestCounter = 0;

void logLine(const String &msg) {
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms] ");
  Serial.println(msg);
}

void logRequest(uint32_t reqId, const String &msg) {
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms][REQ ");
  Serial.print(reqId);
  Serial.print("] ");
  Serial.println(msg);
}

enum LedState {
  LED_BOOT,
  LED_WIFI_READY,
  LED_IDLE,
  LED_BUSY,
  LED_OK,
  LED_ERROR
};

void setStatusLed(LedState state) {
  uint8_t r = 0;
  uint8_t g = 0;
  uint8_t b = 0;

  switch (state) {
    case LED_BOOT:
      r = 40; g = 0; b = 40;   // purple
      break;
    case LED_WIFI_READY:
      r = 0; g = 35; b = 35;   // cyan
      break;
    case LED_IDLE:
      r = 0; g = 15; b = 0;    // dim green
      break;
    case LED_BUSY:
      r = 40; g = 20; b = 0;   // yellow/orange
      break;
    case LED_OK:
      r = 0; g = 60; b = 0;    // green
      break;
    case LED_ERROR:
      r = 60; g = 0; b = 0;    // red
      break;
  }

  statusLed.setPixelColor(0, statusLed.Color(r, g, b));
  statusLed.show();
}

String jsonError(const String &msg) {
  JsonDocument doc;
  doc["ok"] = false;
  doc["error"] = msg;
  String out;
  serializeJson(doc, out);
  return out;
}

String uidToHex(const uint8_t *uid, uint8_t uidLength) {
  static const char *hex = "0123456789ABCDEF";
  String out;
  out.reserve(uidLength * 2);
  for (uint8_t i = 0; i < uidLength; i++) {
    out += hex[(uid[i] >> 4) & 0x0F];
    out += hex[uid[i] & 0x0F];
  }
  return out;
}

String currentIp() {
  IPAddress ip = WiFi.localIP();
  if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
    ip = WiFi.softAPIP();
  }
  return ip.toString();
}

String detectTagType(uint8_t uidLength) {
  if (uidLength == 7) {
    return "NTAG2xx/Ultralight-compatible";
  }
  if (uidLength == 4) {
    return "MIFARE Classic compatible";
  }
  return "ISO14443A";
}

bool readTagUid(uint8_t *uid, uint8_t *uidLength, uint16_t timeoutMs = TAG_WAIT_TIMEOUT_MS) {
  const uint32_t deadline = millis() + timeoutMs;
  uint8_t localUid[7] = {0};
  uint8_t localUidLen = 0;
  uint16_t totalAttempts = 0;

  while (millis() < deadline) {
    for (uint8_t attempt = 0; attempt < UID_READ_ATTEMPTS; attempt++) {
      totalAttempts++;
      if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, localUid, &localUidLen, 120)) {
        memcpy(uid, localUid, localUidLen);
        *uidLength = localUidLen;
        logLine("UID read OK after " + String(totalAttempts) + " attempts, uidLen=" + String(localUidLen));
        return true;
      }
      logLine("UID read attempt failed: " + String(totalAttempts));
      vTaskDelay(1);
    }
    vTaskDelay(1);
  }
  logLine("UID read timeout after attempts=" + String(totalAttempts));
  return false;
}

bool readPageWithRetry(uint8_t page, uint8_t *buffer) {
  for (uint8_t attempt = 0; attempt < PAGE_READ_ATTEMPTS; attempt++) {
    if (nfc.ntag2xx_ReadPage(page, buffer)) {
      if (attempt > 0) {
        logLine("Page " + String(page) + " read recovered on retry " + String(attempt + 1));
      }
      return true;
    }
    logLine("Page read failed: page=" + String(page) + " attempt=" + String(attempt + 1));
    vTaskDelay(1);
  }
  logLine("Page read failed permanently: page=" + String(page));
  return false;
}

bool writePageWithRetry(uint8_t page, uint8_t *buffer) {
  for (uint8_t attempt = 0; attempt < PAGE_WRITE_ATTEMPTS; attempt++) {
    if (nfc.ntag2xx_WritePage(page, buffer)) {
      if (attempt > 0) {
        logLine("Page " + String(page) + " write recovered on retry " + String(attempt + 1));
      }
      return true;
    }
    logLine("Page write failed: page=" + String(page) + " attempt=" + String(attempt + 1));
    vTaskDelay(1);
  }
  logLine("Page write failed permanently: page=" + String(page));
  return false;
}

bool readTagText(String &textOut) {
  textOut = "";
  uint8_t pageData[4] = {0};
  bool reachedEnd = false;
  uint16_t bytesRead = 0;

  for (uint8_t page = NTAG215_FIRST_USER_PAGE; page <= NTAG215_LAST_USER_PAGE; page++) {
    if (!readPageWithRetry(page, pageData)) {
      return false;
    }
    for (uint8_t i = 0; i < 4; i++) {
      const uint8_t c = pageData[i];
      if (c == 0x00 || c == 0xFE) {
        reachedEnd = true;
        break;
      }
      bytesRead++;
      if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
        textOut += static_cast<char>(c);
      } else {
        textOut += '.';
      }
    }
    if (reachedEnd) {
      break;
    }
  }
  logLine("Tag text read complete, bytes=" + String(bytesRead) + ", textLen=" + String(textOut.length()));
  return true;
}

bool eraseTagUserMemory() {
  uint8_t blank[4] = {0, 0, 0, 0};
  for (uint8_t page = NTAG215_FIRST_USER_PAGE; page <= NTAG215_LAST_USER_PAGE; page++) {

  if (!writePageWithRetry(page, blank)) {
    return false;
  }

  if (page % 4 == 0) {
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}
  return true;
}

bool writeStringToTag(const String &text) {
  const size_t maxUserBytes =
      (NTAG215_LAST_USER_PAGE - NTAG215_FIRST_USER_PAGE + 1) * 4;
  const size_t payloadBytes = text.length() + 1;  // Include trailing 0x00.

  if (payloadBytes > maxUserBytes) {
    return false;
  }
  if (!eraseTagUserMemory()) {
    return false;
  }

  size_t srcIndex = 0;
  for (uint8_t page = NTAG215_FIRST_USER_PAGE; page <= NTAG215_LAST_USER_PAGE; page++) {

  uint8_t data[4] = {0,0,0,0};

  for (uint8_t i = 0; i < 4; i++) {
    if (srcIndex < text.length()) {
      data[i] = text[srcIndex++];
    } else if (srcIndex == text.length()) {
      data[i] = 0x00;
      srcIndex++;
    }
  }

  if (!writePageWithRetry(page, data)) {
    return false;
  }

  if (page % 4 == 0) {
    vTaskDelay(pdMS_TO_TICKS(2));
  }

  if (srcIndex > text.length()) {
    break;
  }
}
  return true;
}

void passwordToBytes(const String &password, uint8_t pwd[4]) {
  pwd[0] = 0xFF;
  pwd[1] = 0xFF;
  pwd[2] = 0xFF;
  pwd[3] = 0xFF;
  for (size_t i = 0; i < 4 && i < password.length(); i++) {
    pwd[i] = static_cast<uint8_t>(password[i]);
  }
}

bool authenticateTag(const uint8_t pwd[4], uint8_t packOut[2]) {
  uint8_t cmd[5] = {0x1B, pwd[0], pwd[1], pwd[2], pwd[3]};  // PWD_AUTH
  uint8_t resp[8] = {0};
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

bool setTagPassword(const uint8_t pwd[4], uint8_t auth0 = NTAG215_FIRST_USER_PAGE) {
  uint8_t access[4] = {0};
  uint8_t cfg1[4] = {0};
  uint8_t packPage[4] = {pwd[0], pwd[1], 0x00, 0x00};  // PACK = first 2 pwd bytes

  if (!writePageWithRetry(NTAG215_PWD_PAGE, const_cast<uint8_t *>(pwd))) {
    return false;
  }
  if (!writePageWithRetry(NTAG215_PACK_PAGE, packPage)) {
    return false;
  }
  if (!readPageWithRetry(NTAG215_ACCESS_PAGE, access)) {
    return false;
  }
  access[0] |= 0x80;  // PROT = 1 (read + write protection)
  if (!writePageWithRetry(NTAG215_ACCESS_PAGE, access)) {
    return false;
  }
  if (!readPageWithRetry(NTAG215_CFG1_PAGE, cfg1)) {
    return false;
  }
  cfg1[3] = auth0;  // Protection starts at user page
  if (!writePageWithRetry(NTAG215_CFG1_PAGE, cfg1)) {
    return false;
  }
  return true;
}

bool removeTagPassword(const uint8_t oldPwd[4]) {
  uint8_t packOut[2] = {0};
  if (!authenticateTag(oldPwd, packOut)) {
    return false;
  }

  uint8_t cfg1[4] = {0};
  uint8_t access[4] = {0};
  uint8_t defaultPwd[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t defaultPack[4] = {0x00, 0x00, 0x00, 0x00};

  if (!readPageWithRetry(NTAG215_CFG1_PAGE, cfg1)) {
    return false;
  }
  cfg1[3] = 0xFF;  // Disable protection
  if (!writePageWithRetry(NTAG215_CFG1_PAGE, cfg1)) {
    return false;
  }

  if (!readPageWithRetry(NTAG215_ACCESS_PAGE, access)) {
    return false;
  }
  access[0] &= 0x7F;  // PROT = 0
  if (!writePageWithRetry(NTAG215_ACCESS_PAGE, access)) {
    return false;
  }

  if (!writePageWithRetry(NTAG215_PWD_PAGE, defaultPwd)) {
    return false;
  }
  if (!writePageWithRetry(NTAG215_PACK_PAGE, defaultPack)) {
    return false;
  }

  return true;
}

String bodyToString(uint8_t *data, size_t len) {
  String out;
  out.reserve(len);
  for (size_t i = 0; i < len; i++) {
    out += static_cast<char>(data[i]);
  }
  return out;
}

String getBodyField(const String &body, const char *key) {
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  if (err) {
    return "";
  }
  if (!doc[key].is<const char *>()) {
    return "";
  }
  return String(doc[key].as<const char *>());
}

void sendJson(AsyncWebServerRequest *request, int statusCode, const JsonDocument &doc) {
  String out;
  serializeJson(doc, out);
  request->send(statusCode, "application/json", out);
}



void setupEAPWiFi() {
	WiFi.mode(WIFI_STA);
	#if ESP_IDF_VERSION_MAJOR >= 5
		esp_eap_client_clear_ca_cert();
		esp_eap_client_clear_certificate_and_key();

		// esp_eap_client_set_ttls_phase2_method(ESP_EAP_TTLS_PHASE2_EAP);
		esp_eap_client_set_ttls_phase2_method(ESP_EAP_TTLS_PHASE2_MSCHAPV2);
		// esp_eap_client_set_identity((const unsigned char *)WIFI_USER, strlen(WIFI_USER));
		esp_eap_client_clear_identity();
		esp_eap_client_set_username((const unsigned char *)WIFI_USER, strlen(WIFI_USER));
		esp_eap_client_set_password((const unsigned char *)WIFI_PASSWORD, strlen(WIFI_PASSWORD));
		esp_eap_client_set_disable_time_check(true);
		esp_wifi_sta_enterprise_enable();
	#else
		//setzen von username und password
		esp_wifi_sta_wpa2_ent_set_username((uint8_t *) WIFI_USER,
				strlen(WIFI_USER)); //provide username
		esp_wifi_sta_wpa2_ent_set_password((uint8_t *) WIFI_PASSWORD,
				strlen(WIFI_PASSWORD)); //provide password
		esp_wifi_sta_wpa2_ent_enable();
	#endif
	//starten der Netzwerkverbindung
	WiFi.begin(WIFI_SSID);
	WiFi.setHostname("myESPdevice"); //set Hostname for your device
	while (WiFi.waitForConnectResult() != WL_CONNECTED) {
		Serial.println("Connection Failed! Rebooting...");
		delay(5000);
		ESP.restart();
	}
	Serial.println("");
	Serial.println("WiFi connected");
	Serial.println("IP address set: ");
	Serial.println(WiFi.localIP()); //print LAN IP	
}


void setupApiRoutes() {
  server.on("/api/health", HTTP_GET, [](AsyncWebServerRequest *request) {
    uint32_t reqId = ++apiRequestCounter;
    logRequest(reqId, "GET /api/health from " + request->client()->remoteIP().toString());
    JsonDocument doc;
    doc["ok"] = true;
    doc["service"] = "nfc-api";
    doc["ip"] = currentIp();
    sendJson(request, 200, doc);
    logRequest(reqId, "GET /api/health -> 200");
  });

  auto readHandler = [](AsyncWebServerRequest *request) {
    uint32_t reqId = ++apiRequestCounter;
    String method = request->method() == HTTP_GET ? "GET" : "POST";
    logRequest(reqId, method + " /api/tag/read from " + request->client()->remoteIP().toString());
    setStatusLed(LED_BUSY);
    uint8_t uid[7] = {0};
    uint8_t uidLength = 0;
    String text;

    if (!readTagUid(uid, &uidLength)) {
      setStatusLed(LED_ERROR);
      request->send(404, "application/json", jsonError("Kein Tag erkannt."));
      logRequest(reqId, "/api/tag/read -> 404 no tag");
      return;
    }
    if (!readTagText(text)) {
      setStatusLed(LED_ERROR);
      request->send(500, "application/json", jsonError("Tag erkannt, Text konnte nicht gelesen werden."));
      logRequest(reqId, "/api/tag/read -> 500 text read failed");
      return;
    }

    JsonDocument doc;
    doc["ok"] = true;
    doc["tagType"] = detectTagType(uidLength);
    doc["uid"] = uidToHex(uid, uidLength);
    doc["text"] = text;
    setStatusLed(LED_OK);
    sendJson(request, 200, doc);
    logRequest(reqId, "/api/tag/read -> 200 uid=" + String(doc["uid"].as<const char*>()) + " textLen=" + String(text.length()));
  };
  server.on("/api/tag/read", HTTP_GET, readHandler);
  server.on("/api/tag/read", HTTP_POST, readHandler);

  server.on(
      "/api/tag/write",
      HTTP_POST,
      [](AsyncWebServerRequest *request) {},
      nullptr,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
        if (index != 0 || len != total) {
          return;
        }
        uint32_t reqId = ++apiRequestCounter;
        logRequest(reqId, "POST /api/tag/write from " + request->client()->remoteIP().toString());
        setStatusLed(LED_BUSY);
        String body = bodyToString(data, len);
        String text = getBodyField(body, "text");
        if (text.length() == 0 && request->hasParam("text", true)) {
          text = request->getParam("text", true)->value();
        }
        if (text.length() == 0) {
          setStatusLed(LED_ERROR);
          request->send(400, "application/json", jsonError("Feld 'text' fehlt."));
          logRequest(reqId, "/api/tag/write -> 400 missing text");
          return;
        }

        uint8_t uid[7] = {0};
        uint8_t uidLength = 0;
        if (!readTagUid(uid, &uidLength)) {
          setStatusLed(LED_ERROR);
          request->send(404, "application/json", jsonError("Kein Tag erkannt."));
          logRequest(reqId, "/api/tag/write -> 404 no tag");
          return;
        }
        if (!writeStringToTag(text)) {
          setStatusLed(LED_ERROR);
          request->send(500, "application/json", jsonError("Schreiben fehlgeschlagen."));
          logRequest(reqId, "/api/tag/write -> 500 write failed");
          return;
        }

        JsonDocument doc;
        doc["ok"] = true;
        doc["uid"] = uidToHex(uid, uidLength);
        doc["writtenText"] = text;
        setStatusLed(LED_OK);
        sendJson(request, 200, doc);
        logRequest(reqId, "/api/tag/write -> 200 uid=" + String(doc["uid"].as<const char*>()) + " textLen=" + String(text.length()));
      });

  server.on(
      "/api/tag/password/set",
      HTTP_POST,
      [](AsyncWebServerRequest *request) {},
      nullptr,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
        if (index != 0 || len != total) {
          return;
        }
        uint32_t reqId = ++apiRequestCounter;
        logRequest(reqId, "POST /api/tag/password/set from " + request->client()->remoteIP().toString());
        setStatusLed(LED_BUSY);
        String body = bodyToString(data, len);
        String password = getBodyField(body, "password");
        if (password.length() == 0 && request->hasParam("password", true)) {
          password = request->getParam("password", true)->value();
        }
        if (password.length() == 0) {
          setStatusLed(LED_ERROR);
          request->send(400, "application/json", jsonError("Feld 'password' fehlt."));
          logRequest(reqId, "/api/tag/password/set -> 400 missing password");
          return;
        }

        uint8_t uid[7] = {0};
        uint8_t uidLength = 0;
        if (!readTagUid(uid, &uidLength)) {
          setStatusLed(LED_ERROR);
          request->send(404, "application/json", jsonError("Kein Tag erkannt."));
          logRequest(reqId, "/api/tag/password/set -> 404 no tag");
          return;
        }

        uint8_t pwd[4];
        passwordToBytes(password, pwd);
        if (!setTagPassword(pwd, NTAG215_FIRST_USER_PAGE)) {
          setStatusLed(LED_ERROR);
          request->send(500, "application/json", jsonError("Passwort konnte nicht gesetzt werden."));
          logRequest(reqId, "/api/tag/password/set -> 500 set failed");
          return;
        }

        JsonDocument doc;
        doc["ok"] = true;
        doc["uid"] = uidToHex(uid, uidLength);
        doc["message"] = "Passwort gesetzt.";
        setStatusLed(LED_OK);
        sendJson(request, 200, doc);
        logRequest(reqId, "/api/tag/password/set -> 200");
      });

  server.on(
      "/api/tag/password/remove",
      HTTP_POST,
      [](AsyncWebServerRequest *request) {},
      nullptr,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
        if (index != 0 || len != total) {
          return;
        }
        uint32_t reqId = ++apiRequestCounter;
        logRequest(reqId, "POST /api/tag/password/remove from " + request->client()->remoteIP().toString());
        setStatusLed(LED_BUSY);
        String body = bodyToString(data, len);
        String oldPassword = getBodyField(body, "oldPassword");
        if (oldPassword.length() == 0 && request->hasParam("oldPassword", true)) {
          oldPassword = request->getParam("oldPassword", true)->value();
        }
        if (oldPassword.length() == 0) {
          setStatusLed(LED_ERROR);
          request->send(400, "application/json", jsonError("Feld 'oldPassword' fehlt."));
          logRequest(reqId, "/api/tag/password/remove -> 400 missing oldPassword");
          return;
        }

        uint8_t uid[7] = {0};
        uint8_t uidLength = 0;
        if (!readTagUid(uid, &uidLength)) {
          setStatusLed(LED_ERROR);
          request->send(404, "application/json", jsonError("Kein Tag erkannt."));
          logRequest(reqId, "/api/tag/password/remove -> 404 no tag");
          return;
        }

        uint8_t oldPwd[4];
        passwordToBytes(oldPassword, oldPwd);
        if (!removeTagPassword(oldPwd)) {
          setStatusLed(LED_ERROR);
          request->send(401, "application/json", jsonError("Altes Passwort falsch oder Tag konnte nicht entsperrt werden."));
          logRequest(reqId, "/api/tag/password/remove -> 401 auth failed");
          return;
        }

        JsonDocument doc;
        doc["ok"] = true;
        doc["uid"] = uidToHex(uid, uidLength);
        doc["message"] = "Passwort entfernt.";
        setStatusLed(LED_OK);
        sendJson(request, 200, doc);
        logRequest(reqId, "/api/tag/password/remove -> 200");
      });

  server.on("/api/tag/erase", HTTP_POST, [](AsyncWebServerRequest *request) {
    uint32_t reqId = ++apiRequestCounter;
    logRequest(reqId, "POST /api/tag/erase from " + request->client()->remoteIP().toString());
    setStatusLed(LED_BUSY);
    uint8_t uid[7] = {0};
    uint8_t uidLength = 0;

    if (!readTagUid(uid, &uidLength)) {
      setStatusLed(LED_ERROR);
      request->send(404, "application/json", jsonError("Kein Tag erkannt."));
      logRequest(reqId, "/api/tag/erase -> 404 no tag");
      return;
    }
    if (!eraseTagUserMemory()) {
      setStatusLed(LED_ERROR);
      request->send(500, "application/json", jsonError("Tag konnte nicht geloescht werden."));
      logRequest(reqId, "/api/tag/erase -> 500 erase failed");
      return;
    }

    JsonDocument doc;
    doc["ok"] = true;
    doc["uid"] = uidToHex(uid, uidLength);
    doc["message"] = "Tag geloescht.";
    setStatusLed(LED_OK);
    sendJson(request, 200, doc);
    logRequest(reqId, "/api/tag/erase -> 200");
  });

}

bool setupFileSystem() {
  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS mount failed");
    setStatusLed(LED_ERROR);
    return false;
  }
  return true;
}

void setupWebRoutes() {
  // React app deployment target: LittleFS:/webapp
  server.serveStatic("/", LittleFS, "/webapp/").setDefaultFile("index.html");

  server.onNotFound([](AsyncWebServerRequest *request) {
    String url = request->url();
    if (url.startsWith("/api/")) {
      request->send(404, "application/json", jsonError("Route nicht gefunden."));
      return;
    }
    request->send(LittleFS, "/webapp/index.html", "text/html");
  });
}

void setupNfc() {
  logLine("NFC init start: IRQ=" + String(PN532_IRQ_PIN) + " RESET=" + String(PN532_RESET_PIN) +
          " SDA=" + String(I2C_SDA_PIN) + " SCL=" + String(I2C_SCL_PIN));
  pinMode(PN532_IRQ_PIN, INPUT_PULLUP);
  Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN);

  if (!nfc.begin()) {
    Serial.println("nfc.begin() failed");
    setStatusLed(LED_ERROR);
    while (1) {
      delay(1000);
    }
  }

  uint32_t version = nfc.getFirmwareVersion();
  if (!version) {
    Serial.println("PN532 not found");
    setStatusLed(LED_ERROR);
    while (1) {
      delay(1000);
    }
  }

  if (!nfc.SAMConfig()) {
    Serial.println("SAMConfig failed");
    setStatusLed(LED_ERROR);
    while (1) {
      delay(1000);
    }
  }

  Serial.print("PN532 ready, firmware: ");
  Serial.print((version >> 16) & 0xFF, DEC);
  Serial.print(".");
  Serial.println((version >> 8) & 0xFF, DEC);
}

void setupWiFi() {
  WiFi.mode(WIFI_AP);
  bool ok = WiFi.softAP(AP_SSID, AP_PASSWORD);
  if (!ok) {
    Serial.println("SoftAP start failed");
    setStatusLed(LED_ERROR);
    while (1) {
      delay(1000);
    }
  }
  Serial.print("AP SSID: ");
  Serial.println(AP_SSID);
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());
}

void setup() {
  Serial.begin(115200);
  delay(300);
  Wire.begin(I2C_SDA_PIN,I2C_SCL_PIN);
  Serial.println("I2C Scanner Start");
  for(byte addr=1; addr<127; addr++){
    Wire.beginTransmission(addr);
    if(Wire.endTransmission() == 0){
      Serial.print("Found I2C device at 0x");
      Serial.println(addr,HEX);
    }
  }
  Serial.println("NFC REST API booting...");
  logLine("Debug logging enabled");
  statusLed.begin();
  statusLed.setBrightness(40);
  setStatusLed(LED_BOOT);

  //setupWiFi();
  setupEAPWiFi();

  setStatusLed(LED_WIFI_READY);
  if (!setupFileSystem()) {
    while (1) {
      delay(1000);
    }
  }
  setupNfc();
  setupApiRoutes();
  setupWebRoutes();
  server.begin();
  setStatusLed(LED_IDLE);

  Serial.println("REST API ready.");
  Serial.println("GET|POST /api/tag/read");
  Serial.println("POST /api/tag/write      body: {\"text\":\"Hallo\"}");
  Serial.println("POST /api/tag/password/set    body: {\"password\":\"abcd\"}");
  Serial.println("POST /api/tag/password/remove body: {\"oldPassword\":\"abcd\"}");
  Serial.println("POST /api/tag/erase");
}

void loop() {
  delay(10);
}
