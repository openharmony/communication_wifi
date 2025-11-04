/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#ifndef OHOS_WIFI_WIFI_CHR_ADAPTER_H
#define OHOS_WIFI_WIFI_CHR_ADAPTER_H
 
#include "wifi_hisysevent.h"
#include <string>
#include "wifi_msg.h"
#define AP_ERR_CODE 3
#define AP_STA_PSK_MISMATCH_CNT 1
 
#define ENCRYPTION_EVENT 0
#define DECRYPTION_EVENT 1
#define NONE_ENCRYTION_UTIL 2
 
#define SOFTAP_MOUDLE_EVENT 0
#define STA_MOUDLE_EVENT 1
 
namespace OHOS {
namespace Wifi {
 
void EnhanceWriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType);
 
void EnhanceWriteWifiApStateHiSysEvent(int32_t state);
 
void EnhanceWriteWifiBridgeStateHiSysEvent(int32_t state);
 
void EnhanceWriteWifiP2pStateHiSysEvent(const std::string& inter, int32_t type, int32_t state);
 
void EnhanceWriteWifiConnectionHiSysEvent(int type, const std::string& pkgName);
 
void EnhanceWriteAssocFailHiSysEvent(const std::string &assocFailReason, int subErrCode = 0);
 
void EnhanceWriteDhcpFailHiSysEvent(const std::string &dhcpFailReason, int subErrCode = 0);
 
void EnhanceWriteAutoConnectFailEvent(const std::string &failReason, const std::string &subReason = "");
 
void EnhanceWriteWifiScanHiSysEvent(const int result, const std::string& pkgName);
 
void EnhanceWriteWifiEventReceivedHiSysEvent(const std::string& eventType, int value);
 
void EnhanceWriteWifiBandHiSysEvent(int band);
 
void EnhanceWriteWifiSignalHiSysEvent(int direction, int txPackets, int rxPackets);
 
void EnhanceWriteWifiAbnormalDisconnectHiSysEvent(int errorCode, int locallyGenerated);
 
void EnhanceWriteWifiConnectionInfoHiSysEvent(int networkId);
 
void EnhanceWriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState);
 
void EnhanceWriteWifiAccessIntFailedHiSysEvent(int operateRes, int failCnt, int selfCureResetState,
    std::string selfCureHistory);
 
void EnhanceWriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server);
 
void EnhanceWriteIsInternetHiSysEvent(int isInternet);
 
void EnhanceWritePortalStateHiSysEvent(int portalState);
 
void EnhanceWriteArpInfoHiSysEvent(uint64_t arpRtt, int32_t arpFailedCount, int32_t gatewayCnt = 0);
 
void EnhanceWriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed);
 
void EnhanceWriteConnectTypeHiSysEvent(int connectType, bool isFirstConnect = false);
 
void EnhanceWriteWifiLinkTypeHiSysEvent(const std::string &ssid,
    int32_t wifiLinkType, const std::string &triggerReason);
 
void EnhanceWriteEmlsrExitReasonHiSysEvent(const std::string &ssid, int32_t reason);
 
void EnhanceWriteStaConnectIface(const std::string &ifName);
 
void EnhanceWriteWifiWpaStateHiSysEvent(int state);
 
void EnhanceWritePortalAuthExpiredHisysevent(int respCode, int detectNum, time_t connTime,
    time_t portalAuthTime, bool isNotificationClicked);
 
void EnhanceWriteWifiSelfcureHisysevent(int type);
 
void EnhanceWrite3VapConflictHisysevent(int type);
 
void EnhanceWrite5gPrefFailedHisysevent(Pref5gStatisticsInfo &info);
 
void EnhanceWriteAutoSelectHiSysEvent(int selectType, const std::string &selectedInfo,
    const std::string &filteredReason, const std::string &savedResult);
 
void EnhanceWriteDhcpInfoHiSysEvent(const IpInfo &ipInfo, const IpV6Info &ipv6Info);
 
void EnhanceWriteIodHiSysEvent(const IodStatisticInfo &iodStatisticInfo);
}  // namespace Wifi
}  // namespace OHOS
#endif