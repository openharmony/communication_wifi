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

#ifndef OHOS_WIFIMSG_H
#define OHOS_WIFIMSG_H

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "ip_tools.h"
#include "wifi_ap_msg.h"
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
#define MAX_COUNTRY_CODE_LEN 2
#define WEPKEYS_SIZE 4
#define INVALID_NETWORK_ID (-1)
#define REOPEN_STA_INTERVAL 500
#define BAND_2_G 1
#define BAND_5_G 2
#define IPV4_ADDRESS_TYPE 0
#define IPV6_ADDRESS_TYPE 1

#define DEVICE_CONFIG_INDEX_SSID 0
#define DEVICE_CONFIG_INDEX_BSSID 1

enum class SupplicantState {
    DISCONNECTED = 0,
    INTERFACE_DISABLED = 1,
    INACTIVE = 2,
    SCANNING = 3,
    AUTHENTICATING = 4,
    ASSOCIATING = 5,
    ASSOCIATED = 6,
    FOUR_WAY_HANDSHAKE = 7,
    GROUP_HANDSHAKE = 8,
    COMPLETED = 9,
    UNKNOWN = 10,

    INVALID = 0xFF,
};

enum class DetailedState {
    AUTHENTICATING = 0,
    BLOCKED = 1,
    CAPTIVE_PORTAL_CHECK = 2,
    CONNECTED = 3,
    CONNECTING = 4,
    DISCONNECTED = 5,
    DISCONNECTING = 6,
    FAILED = 7,
    IDLE = 8,
    OBTAINING_IPADDR = 9,
    WORKING = 10,
    NOTWORKING = 11,
    SCANNING = 12,
    SUSPENDED = 13,
    VERIFYING_POOR_LINK = 14,

    INVALID = 0xFF,
};

enum class ConnState {
    IDLE,
    SCANNING,
    CONNECTING,
    AUTHENTICATING,
    OBTAINING_IPADDR,
    CONNECTED,
    SUSPENDED,
    DISCONNECTING,
    DISCONNECTED,
    FAILED
};

struct WifiLinkedInfo {
    int networkId;
    std::string ssid;
    std::string bssid;
    int rssi; /* signal level */
    int band; /* 2.4G / 5G */
    int frequency;
    int linkSpeed; /* units: Mbps */
    std::string macAddress;
    unsigned int ipAddress;
    ConnState connState;
    bool ifHiddenSSID;
    std::string rxLinkSpeed; /* Downstream network speed */
    std::string txLinkSpeed; /* Upstream network speed */
    int chload;
    int snr;                         /* Signal-to-Noise Ratio */
    SupplicantState supplicantState; /* wpa_supplicant state */
    DetailedState detailedState;     /* connection state */

    WifiLinkedInfo()
    {
        networkId = INVALID_NETWORK_ID;
        rssi = 0;
        band = 0;
        frequency = 0;
        linkSpeed = 0;
        ipAddress = 0;
        connState = ConnState::FAILED;
        ifHiddenSSID = false;
        chload = 0;
        snr = 0;
        supplicantState = SupplicantState::INVALID;
        detailedState = DetailedState::INVALID;
    }
};

/* use WPS type */
enum class SetupMethod {
    PBC = 0,
    DISPLAY = 1,
    KEYPAD = 2,
    LABEL = 3,
    INVALID = 4,
};

/* is wps connected to a network */
enum class IsWpsConnected {
    WPS_CONNECTED = 0,
    WPS_INVALID = -1,
};
/* WifiLock mode */
enum class WifiLockMode {
    WIFI_MODE_FULL = 0,
    WIFI_MODE_SCAN_ONLY = 1,
    WIFI_MODE_FULL_HIGH_PERF = 2,
    WIFI_MODE_FULL_LOW_LATENCY = 3,
    WIFI_MODE_NO_LOCKS_HELD = 4
};

enum class LowLatecySupport {
    LOW_LATENCY_SUPPORT_UNDEFINED = 0,
    LOW_LATENCY_SUPPORTED = 1,
    LOW_LATENCY_NOT_SUPPORTED = 2
};

/* WPS config */
struct WpsConfig {
    SetupMethod setup; /* WPS type */
    std::string pin;   /* pin code */
    std::string bssid; /* KEYPAD mode pin code */

    WpsConfig()
    {
        setup = SetupMethod::INVALID;
    }
};

enum class WifiDeviceConfigStatus {
    INVALID = -1, /* invalid */
    CURRENT = 0,  /* using */
    DISABLED = 1, /* disabled */
    ENABLED = 2,  /* enable */

    UNKNOWN
};

enum class AssignIpMethod { DHCP, STATIC, UNASSIGNED };

class WifiIpAddress {
public:
    int family;                             /* ip type */
    unsigned int addressIpv4;               /* IPv4 */
    std::vector<unsigned char> addressIpv6; /* IPv6 */

    WifiIpAddress()
    {
        family = -1;
        addressIpv4 = 0;
    }

    ~WifiIpAddress()
    {}

    std::string GetIpv4Address()
    {
        return IpTools::ConvertIpv4Address(addressIpv4);
    }

    void SetIpv4Address(const std::string &address)
    {
        family = IPV4_ADDRESS_TYPE;
        addressIpv4 = IpTools::ConvertIpv4Address(address);
        return;
    }

    std::string GetIpv6Address()
    {
        return IpTools::ConvertIpv6Address(addressIpv6);
    }

    void SetIpv6Address(const std::string &address)
    {
        family = IPV6_ADDRESS_TYPE;
        IpTools::ConvertIpv6Address(address, addressIpv6);
        return;
    }
};

class WifiLinkAddress {
public:
    WifiIpAddress address; /* IP address */
    int prefixLength;
    int flags;
    int scope;

    WifiLinkAddress()
    {
        prefixLength = 0;
        flags = 0;
        scope = 0;
    }

    ~WifiLinkAddress()
    {}
};

class StaticIpAddress {
public:
    WifiLinkAddress ipAddress;
    WifiIpAddress gateway;
    WifiIpAddress dnsServer1; /* main DNS */
    WifiIpAddress dnsServer2; /* backup DNS */
    std::string domains;

    std::string GetIpv4Mask()
    {
        return IpTools::ConvertIpv4Mask(ipAddress.prefixLength);
    }

    std::string GetIpv6Mask()
    {
        return IpTools::ConvertIpv6Mask(ipAddress.prefixLength);
    }
};

class WifiIpConfig {
public:
    AssignIpMethod assignMethod;
    StaticIpAddress staticIpAddress;

    WifiIpConfig()
    {
        assignMethod = AssignIpMethod::DHCP;
    }
    ~WifiIpConfig()
    {}
};

class WifiEapConfig {
public:
    std::string eap;      /* EAP mode Encryption Mode: PEAP/TLS/TTLS/PWD/SIM/AKA/AKA */
    std::string identity; /* EAP mode identity */
    std::string password; /* EAP mode password */
};

enum class ConfigureProxyMethod { AUTOCONFIGUE, MANUALCONFIGUE, CLOSED };

class AutoProxyConfig {
public:
    std::string pacWebAddress;
};

class ManualProxyConfig {
public:
    std::string serverHostName;
    int serverPort;
    std::string exclusionObjectList;

    void GetExclusionObjectList(std::vector<std::string> &exclusionList)
    {
        IpTools::GetExclusionObjectList(exclusionObjectList, exclusionList);
        return;
    }

    ManualProxyConfig()
    {
        serverPort = 0;
    }
    ~ManualProxyConfig()
    {}
};

class WifiProxyConfig {
public:
    ConfigureProxyMethod configureMethod;
    AutoProxyConfig autoProxyConfig;
    ManualProxyConfig manualProxyConfig;

    WifiProxyConfig()
    {
        configureMethod = ConfigureProxyMethod::CLOSED;
    }
    ~WifiProxyConfig()
    {}
};

enum class WifiPrivacyConfig { RANDOMMAC, DEVICEMAC };

/* Network configuration information */
struct WifiDeviceConfig {
    int networkId;
    /* 0: CURRENT, using 1: DISABLED 2: ENABLED */
    int status;
    /* mac address */
    std::string bssid;
    /* network name */
    std::string ssid;
    int band;
    int channel;
    int frequency;
    /* Signal strength */
    int rssi;
    /**
     * signal level，
     * rssi<=-100    level : 0
     * (-100, -88]   level : 1
     * (-88, -77]    level : 2
     * (-66, -55]    level : 3
     * rssi>=-55     level : 4
     */
    int level;
    /* Is Passpoint network */
    bool isPasspoint;
    /* is ephemeral network */
    bool isEphemeral;
    /* WPA-PSK mode pre shared key */
    std::string preSharedKey;
    /* Encryption Mode */
    std::string keyMgmt;
    /* WEP mode key, max size: 4 */
    std::string wepKeys[WEPKEYS_SIZE];
    /* use WEP key index */
    int wepTxKeyIndex;
    /* network priority */
    int priority;
    /* is hidden network */
    bool hiddenSSID;
    /* Is enable WPAI Certified */
    bool isEnableWPAICertified;
    /**
     * support encryption mode, use bit define enable/disable;
     * 0: NONE,1:WPA_PSK,2:WPA_EAP,3:IEEE8021X example:
     * value is 7 and binary is 0111, this defines
     * support NONE, WPA_PSK and WPA_EAP
     */
    unsigned int allowedKeyManagement;
    /**
     * support encryption protocols, use bit define enable/disable
     * 0: WPA, 1: RSN example: value is 2 and binary is 0010,
     * this defines support RSN.
     */
    int allowedProtocols;
    /**
     * support auth algorithms, use bit define enable/disable;
     * bit 0: OPEN 1: SHARED 2 LEAP example: value is 3 and binary
     * is 0011, this defines support OPEN and SHARED。
     */
    int allowedAuthAlgorithms;
    /**
     * support PairwiseCiphers, use bit define enable/disable;
     * 0: NONE 1: TKIP 2:CCMP example: value is 3 and binary is 0011,
     * this defines support NONE and TKIP.
     */
    int allowedPairwiseCiphers;
    /* Random mac address */
    std::string macAddress;
    /**
     * support GroupCiphers, use bit define enable/disable;
     * 0: WEP40, 1: WEP104, 2: TKIP, 3: CCMP example: value is 7 and
     * binary is 0111, this defines support WEP40, WEP104 and TKIP.
     */
    int allowedGroupCiphers;
    WifiIpConfig wifiIpConfig;
    WifiEapConfig wifiEapConfig;
    WifiProxyConfig wifiProxyconfig;
    WifiPrivacyConfig wifiPrivacySetting;

    WifiDeviceConfig()
    {
        networkId = INVALID_NETWORK_ID;
        status = static_cast<int>(WifiDeviceConfigStatus::INVALID);
        band = 0;
        channel = 0;
        frequency = 0;
        level = 0;
        isPasspoint = false;
        isEphemeral = false;
        wepTxKeyIndex = 0;
        priority = 0;
        hiddenSSID = false;
        isEnableWPAICertified = false;
        allowedKeyManagement = 0;
        allowedProtocols = 0;
        allowedAuthAlgorithms = 0;
        allowedPairwiseCiphers = 0;
        allowedGroupCiphers = 0;
        wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        rssi = -100;
    }
};

enum class WifiState { DISABLING = 0, DISABLED = 1, ENABLING = 2, ENABLED = 3, UNKNOWN = 4 };

enum class ConnectionState {
    CONNECT_CONNECTING = 0,
    CONNECT_AP_CONNECTED = 1,
    CONNECT_CHECK_PORTAL = 2,
    CONNECT_NETWORK_ENABLED = 3,
    CONNECT_NETWORK_DISABLED = 4,
    DISCONNECT_DISCONNECTING = 5,
    DISCONNECT_DISCONNECT_FAILED = 6,
    DISCONNECT_DISCONNECTED = 7,
    CONNECT_PASSWORD_WRONG = 8,
    CONNECT_CONNECTING_TIMEOUT = 9,
    UNKNOWN,
};

/* wps state */
enum class WpsStartState {
    START_PBC_SUCCEED = 0,
    START_PIN_SUCCEED = 1,
    START_PBC_FAILED = 2,
    PBC_STARTED_ALREADY = 3,
    START_PIN_FAILED = 4,
    PIN_STARTED_ALREADY = 5,
    STOP_PBC_SUCCEED = 6,
    STOP_PBC_FAILED = 7,
    STOP_PIN_SUCCEED = 8,
    STOP_PIN_FAILED = 9,
    START_PBC_FAILED_OVERLAP = 10,
    START_WPS_FAILED = 11,
    WPS_TIME_OUT = 12,
};

/* mock api state */
struct WifiMockState {
    /* mock type: 1 screen 2 airplane 3 App run mode 4 power saving 5 Customer-defined scenario */
    int type;
    /**
     * when screen: 1 on 2 off;
     * airplane: 1 on 2 off;
     * App run state: 1 front 2 backend;
     * power saving: 1 on 2 off;
     * other Customer-defined scene: 1 on 2 off
     */
    int state;
    WifiMockState()
    {
        type = 0;
        state = 0;
    }
};

struct SingleAppForbid {
    int appID;
    ScanIntervalMode scanIntervalMode;
    int lessThanIntervalNum;
    time_t continueScanTime;
    time_t blockListScanTime;
    int expScanCount;
    int fixedScanCount;
    time_t fixedCurrentTime;
    SingleAppForbid()
    {
        appID = 0;
        lessThanIntervalNum = 0;
        continueScanTime = 0;
        blockListScanTime = 0;
        expScanCount = 0;
        fixedScanCount = 0;
        fixedCurrentTime = 0;
    }
};

/* DHCP info */
struct DhcpInfo {
    int ipAddress;     /* ip address */
    int netGate;       /* gate */
    int netMask;       /* mask */
    int dns1;          /* main dns */
    int dns2;          /* backup dns */
    int serverAddress; /* DHCP server's address */
    int leaseDuration;

    DhcpInfo()
    {
        ipAddress = 0;
        netGate = 0;
        netMask = 0;
        dns1 = 0;
        dns2 = 0;
        serverAddress = 0;
        leaseDuration = 0;
    }
};

struct WifiEvent {
    void (*OnWifiStateChanged)(int state);
    void (*OnWifiConnectionChanged)(int state, const WifiLinkedInfo &info);
    void (*OnWifiScanStateChanged)(int state);
    void (*OnWifiRssiChanged)(int rssi);
    void (*OnWifiWpsStateChanged)(int state, std::string pinCode);
    void (*OnHotspotStateChanged)(int state);
    void (*OnHotspotStaJoin)(const StationInfo &info);
    void (*OnHotspotStaLeave)(const StationInfo &info);
    void (*OnStreamChanged)(int direction);

    WifiEvent()
    {
        OnWifiStateChanged = nullptr;
        OnWifiConnectionChanged = nullptr;
        OnWifiScanStateChanged = nullptr;
        OnWifiRssiChanged = nullptr;
        OnWifiWpsStateChanged = nullptr;
        OnHotspotStateChanged = nullptr;
        OnHotspotStaJoin = nullptr;
        OnHotspotStaLeave = nullptr;
        OnStreamChanged = nullptr;
    }
};
}  // namespace Wifi
}  // namespace OHOS
#endif