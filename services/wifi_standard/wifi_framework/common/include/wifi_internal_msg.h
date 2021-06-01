/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_INTERNAL_MSG_H
#define OHOS_WIFI_INTERNAL_MSG_H

#include "wifi_msg.h"
#include "wifi_message_queue.h"
#include "refbase.h"

namespace OHOS {
namespace Wifi {
#define PRIORITY_1 1
#define PRIORITY_2 2
#define PRIORITY_3 3
#define SCORE_SLOPE 5
#define INIT_SCORE 10
#define SAME_BSSID_SCORE 8
#define SAME_NETWORK_SCORE 5
#define FREQUENCY_5_GHZ_SCORE 10
#define LAST_SELECTION_SCORE 120
#define SECURITY_SCORE 20
#define MIN_RSSI_24GHZ (-83)
#define MIN_RSSI_5GHZ (-80)
#define RSSI_LEVEL_1_2G (-88)
#define RSSI_LEVEL_2_2G (-82)
#define RSSI_LEVEL_3_2G (-75)
#define RSSI_LEVEL_4_2G (-65)
#define RSSI_LEVEL_1_5G (-85)
#define RSSI_LEVEL_2_5G (-79)
#define RSSI_LEVEL_3_5G (-72)
#define RSSI_LEVEL_4_5G (-65)

enum WifiInternalMsgCode {
    MAIN_EXIT_CODE = -9999, /* special code, using when program exits. */

    /* STA SERVICE MESSAGE CODE DEFINE, START WITH 1000 AND MUST LESS THEN 2000 */
    STA_START_MSG_CODE = 1000, /* IDENTIFY: START MSGCODE FOR STA SERVICE. PLEASE ADD NEW CODE FOR STA AFTER THIS ! */
    STA_OPEN_RES,
    STA_CLOSE_RES,
    STA_CONNECT_REQ,
    STA_CONNECT_RES,
    STA_RECONNECT_REQ,
    STA_RECONNECT_RES,
    STA_REASSOCIATE_REQ,
    STA_REASSOCIATE_RES,
    STA_DISCONNECT_REQ,
    STA_DISCONNECT_RES,
    STA_START_WPS_REQ,
    STA_START_WPS_RES,
    STA_CANCEL_WPS_REQ,
    STA_CANCEL_WPS_RES,
    STA_REMOVE_DEVICE_REQ,
    STA_CONNECT_MANAGE_REQ,
    STA_SET_COUNTRY_CODE,
    STA_END_MSG_CODE, /* IDENTIFY: MAX MSGCODE FOR STA SERVICE . PLEASE ADD NEW CODE FOR STA BEFORE THIS ! */

    /* AP SERVICE MESSAGE CODE DEFINE, START WITH 2000 AND MUST LESS THEN 3000 */
    AP_START_MSG_CODE = 2000, /* IDENTIFY: START MSGCODE FOR AP SERVICE . PLEASE ADD NEW CODE FOR AP AFTER THIS ! */
    AP_OPEN_RES,
    AP_CLOSE_RES,
    AP_JOIN_RES,
    AP_LEAVE_RES,
    AP_SET_HOTSPOT_CONFIG_REQ,
    AP_ADD_BLOCK_LIST_REQ,
    AP_DEL_BLOCK_LIST_REQ,
    AP_DISCCONECT_STA_BY_MAC_REQ,
    AP_END_MSG_CODE, /* IDENTIFY: MAX MSGCODE FOR AP SERVICE . PLEASE ADD NEW CODE FOR AP BEFORE THIS ! */

    /* SCAN SERVICE MESSAGE CODE DEFINE, START WITH 3000 AND MUST LESS THEN 4000 */
    SCAN_START_MSG_CODE =
        3000, /* IDENTIFY: START MSGCODE FOR SCAN SERVICE. PLEASE ADD NEW CODE FOR SCAN AFTER THIS ! */
    SCAN_START_RES,
    SCAN_STOP_RES,
    SCAN_REQ,
    SCAN_RES,
    SCAN_PARAM_REQ,
    SCAN_PARAM_RES,
    SCAN_RECONNECT_REQ,
    SCAN_RESULT_RES,
    SCAN_NOTIFY_STA_CONN_REQ,
    SCAN_END_MSG_CODE, /* IDENTIFY: MAX MSGCODE FOR SCAN SERVICE . PLEASE ADD NEW CODE FOR SCAN BEFORE THIS ! */
    SCAN_CONTROL_REQ,

    /* MOCK SYSTEM STATUS CHANGED MESSAGE CODE DEFINE, START WITH 4000 AND MUST LESS THEN 5000 */
    SCREEN_CHANGE_NOTICE = 4000,            /* notify screen state */
    AIRPLANE_MODE_CHANGE_NOTICE = 4001,     /* notify airplane state */
    APP_RUNNING_MODE_CHANGE_NOTICE = 4002,  /* notify App running state */
    POWER_SAVING_MODE_CHANGE_NOTICE = 4003, /* notify power saving state */
    FRONT_BACK_STATUS_CHANGE_NOTICE = 4004, /* notify front/backend state */
    CUSTOM_STATUS_CHANGE_NOTICE = 4005,     /* notify other custom state */
};

enum class WifiOprMidState { CLOSED = 0, OPENING = 1, RUNNING = 2, CLOSING = 3, UNKNOWN };

enum class OperateResState {
    OPEN_WIFI_SUCCEED = 0,             /* open wifi succeed */
    OPEN_WIFI_FAILED,                  /* open wifi failed */
    OPEN_WIFI_OVERRIDE_OPEN_FAILED,    /* enable wifi repeatedly */
    OPEN_WIFI_DISABLED,                /* open wifi failed, set wifi disabled */
    OPEN_WIFI_SUPPLICANT_INIT_FAILED,  /* wpa_supplicant not inited or init failed */
    OPEN_WIFI_OPEN_SUPPLICANT_FAILED,  /* wpa_supplicant start failed */
    OPEN_WIFI_CONN_SUPPLICANT_FAILED,  /* connect wpa_supplicant failed */
    CLOSE_WIFI_SUCCEED,                /* close wifi succeed */
    CLOSE_WIFI_FAILED,                 /* close wifi failed */
    CONNECT_CONNECTING,                /* connecting */
    CONNECT_CONNECTING_TIMEOUT,        /* connecting time out */
    CONNECT_TO_OWN_AP_FAILED,          /* connect own ap failed */
    CONNECT_ENABLE_NETWORK_FAILED,     /* wpa_supplicant enable network failed */
    CONNECT_SELECT_NETWORK_FAILED,     /* wpa_supplicant select network failed */
    CONNECT_SAVE_DEVICE_CONFIG_FAILED, /* wpa_supplicant save network config failed */
    CONNECT_AP_CONNECTED,              /* connect succeed */
    CONNECT_CHECK_PORTAL,              /* check connect to a portal hotspot */
    CONNECT_NETWORK_ENABLED,           /* can visit internet */
    CONNECT_NETWORK_DISABLED,          /* cannot visit internet */
    DISCONNECT_DISCONNECTING,          /* disconnecting */
    DISCONNECT_DISCONNECT_FAILED,      /* disconnect failed */
    DISCONNECT_DISCONNECTED,           /* disconnect succeed */
    CONNECT_PASSWORD_WRONG,            /* wrong password */
    CONNECT_OBTAINING_IP,              /* obtain ip */
};

struct WifiRequestParams {
    WifiScanParams wifiScanParams;
    WpsConfig wpsConfig;
    HotspotConfig hotspotConfig;
    WifiDeviceConfig deviceConfig;
    StationInfo stationInfo;
    std::vector<WifiScanInfo> scanResults;
    WifiMockState wifiMockState;
    int argInt;

    WifiRequestParams() : argInt(-1)
    {}

    WifiRequestParams(const WifiRequestParams &) = delete;
    WifiRequestParams &operator=(const WifiRequestParams &) = delete;
};

struct WifiResponseParams {
    int result;
    int argInt;
    WifiLinkedInfo linkedInfo;
    StationInfo staInfo;
    std::vector<WifiScanInfo> scanResults;
    WifiResponseParams() : result(0), argInt(0)
    {}
};

struct WifiRequestMsgInfo {
    int msgCode;

    WifiRequestParams params;

    WifiRequestMsgInfo() : msgCode(0)
    {}

    WifiRequestMsgInfo(const WifiRequestMsgInfo &) = delete;
    WifiRequestMsgInfo &operator=(const WifiRequestMsgInfo &) = delete;
};

struct WifiResponseMsgInfo {
    int msgCode;
    WifiResponseParams params;

    WifiResponseMsgInfo() : msgCode(0)
    {}
};

struct WifiEventCallbackMsg {
    int msgCode;
    int msgData;
    std::string pinCode; /* wps pin mode code */
    WifiLinkedInfo linkInfo;
    StationInfo staInfo;

    WifiEventCallbackMsg()
    {
        msgCode = 0;
        msgData = 0;
    }
};

enum class DhcpIpType { /* dhcp IP type: ipv4 ipv6 mix */
    DHCP_IPTYPE_IPV4,
    DHCP_IPTYPE_IPV6,
    DHCP_IPTYPE_MIX,
};

/* wifi config store */
struct WifiConfig {
    /* scan always switch */
    bool scanAlwaysSwitch;
    /* airplane mode can use sta switch */
    bool staAirplaneMode;
    /**
     * last sta service state, when service started, power
     * saving off, airplane mode off we use this saved state to
     * discuss whether need restore sta service. when open sta
     * service, set true; when user call DisableWifi succeed,
     * set false;
     */
    bool staLastState;
    int savedNetworkEvaluatorPriority;
    int scoredNetworkEvaluatorPriority;
    int passpointNetworkEvaluatorPriority;
    int scoretacticsScoreSlope;
    int scoretacticsInitScore;
    int scoretacticsSameBssidScore;
    int scoretacticsSameNetworkScore;
    int scoretacticsFrequency5GHzScore;
    int scoretacticsLastSelectionScore;
    int scoretacticsSecurityScore;
    bool whetherToAllowNetworkSwitchover;
    int dhcpIpType;
    std::string defaultWifiInterface;
    /* pre load sta/scan/ap/p2p/aware so switch */
    bool preLoadSta;
    bool preLoadScan;
    bool preLoadAp;
    bool preLoadP2p;
    bool preLoadAware;
    bool supportHwPnoFlag;
    int minRssi2Dot4Ghz;
    int minRssi5Ghz;
    int firstRssiLevel2G;
    int secondRssiLevel2G;
    int thirdRssiLevel2G;
    int fourthRssiLevel2G;
    int firstRssiLevel5G;
    int secondRssiLevel5G;
    int thirdRssiLevel5G;
    int fourthRssiLevel5G;

    WifiConfig()
    {
        scanAlwaysSwitch = false;
        staAirplaneMode = false;
        staLastState = false;
        savedNetworkEvaluatorPriority = PRIORITY_1;
        scoredNetworkEvaluatorPriority = PRIORITY_2;
        passpointNetworkEvaluatorPriority = PRIORITY_3;
        scoretacticsScoreSlope = SCORE_SLOPE;
        scoretacticsInitScore = INIT_SCORE;
        scoretacticsSameBssidScore = SAME_BSSID_SCORE;
        scoretacticsSameNetworkScore = SAME_NETWORK_SCORE;
        scoretacticsFrequency5GHzScore = FREQUENCY_5_GHZ_SCORE;
        scoretacticsLastSelectionScore = LAST_SELECTION_SCORE;
        scoretacticsSecurityScore = SECURITY_SCORE;
        whetherToAllowNetworkSwitchover = true;
        dhcpIpType = static_cast<int>(DhcpIpType::DHCP_IPTYPE_MIX);
        defaultWifiInterface = "wlan0";
        preLoadSta = false;
        preLoadScan = false;
        preLoadAp = false;
        preLoadP2p = false;
        preLoadAware = false;
        supportHwPnoFlag = true;
        minRssi2Dot4Ghz = MIN_RSSI_24GHZ;
        minRssi5Ghz = MIN_RSSI_5GHZ;
        firstRssiLevel2G = RSSI_LEVEL_1_2G;
        secondRssiLevel2G = RSSI_LEVEL_2_2G;
        thirdRssiLevel2G = RSSI_LEVEL_3_2G;
        fourthRssiLevel2G = RSSI_LEVEL_4_2G;
        firstRssiLevel5G = RSSI_LEVEL_1_5G;
        secondRssiLevel5G = RSSI_LEVEL_2_5G;
        thirdRssiLevel5G = RSSI_LEVEL_3_5G;
        fourthRssiLevel5G = RSSI_LEVEL_4_5G;
    }
};
}  // namespace Wifi
}  // namespace OHOS
#endif
