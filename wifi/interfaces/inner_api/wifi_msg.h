/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_MSG_H
#define OHOS_WIFI_MSG_H

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "ip_tools.h"
#include "wifi_scan_msg.h"
#include "securec.h"

namespace OHOS {
namespace Wifi {
#define WIFI_COUNTRY_CODE_LEN 2
#define WEPKEYS_SIZE 4
#define INVALID_NETWORK_ID (-1)
#define WIFI_INVALID_UID (-1)
#define IPV4_ADDRESS_TYPE 0
#define IPV6_ADDRESS_TYPE 1
#define WIFI_INVALID_SIM_ID (0)
#define WIFI_EAP_OPEN_EXTERNAL_SIM 1
#define WIFI_EAP_CLOSE_EXTERNAL_SIM 0
#define WIFI_PASSWORD_LEN 128
#define MAX_PID_LIST_SIZE 128

const std::string KEY_MGMT_NONE = "NONE";
const std::string KEY_MGMT_WEP = "WEP";
const std::string KEY_MGMT_WPA_PSK = "WPA-PSK";
const std::string KEY_MGMT_SAE = "SAE";
const std::string KEY_MGMT_EAP = "WPA-EAP";

const std::string EAP_METHOD_NONE = "NONE";
const std::string EAP_METHOD_PEAP = "PEAP";
const std::string EAP_METHOD_TLS = "TLS";
const std::string EAP_METHOD_TTLS = "TTLS";
const std::string EAP_METHOD_PWD = "PWD";
const std::string EAP_METHOD_SIM = "SIM";
const std::string EAP_METHOD_AKA = "AKA";
const std::string EAP_METHOD_AKA_PRIME = "AKA'";

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
    PASSWORD_ERROR = 15,
    CONNECTION_REJECT = 16,
    CONNECTION_FULL = 17,
    CONNECTION_TIMEOUT = 18,
    OBTAINING_IPADDR_FAIL = 19,
    INVALID = 0xFF,
};

enum ConnState {
    /** The device is searching for an available AP. */
    SCANNING,

    /** The Wi-Fi connection is being set up. */
    CONNECTING,

    /** The Wi-Fi connection is being authenticated. */
    AUTHENTICATING,

    /** The IP address of the Wi-Fi connection is being obtained. */
    OBTAINING_IPADDR,

    /** The Wi-Fi connection has been set up. */
    CONNECTED,

    /** The Wi-Fi connection is being torn down. */
    DISCONNECTING,

    /** The Wi-Fi connection has been torn down. */
    DISCONNECTED,

    /** The Wi-Fi special connection. */
    SPECIAL_CONNECT,

    /** Failed to set up the Wi-Fi connection. */
    UNKNOWN
};

enum class DisconnectedReason {
    /* Default reason */
    DISC_REASON_DEFAULT = 0,

    /* Password is wrong */
    DISC_REASON_WRONG_PWD = 1,

    /* The number of router's connection reaches the maximum number limit */
    DISC_REASON_CONNECTION_FULL = 2,

    /* Connection Rejected */
    DISC_REASON_CONNECTION_REJECTED = 3
};

enum class WifiOperateType {
    STA_OPEN,
    STA_CLOSE,
    STA_CONNECT,
    STA_ASSOC,
    STA_AUTH,
    STA_DHCP
};

enum class WifiOperateState {
    STA_OPENING,
    STA_OPENED,
    STA_CONNECTING,
    STA_CONNECTED,
    STA_CONNECT_EXCEPTION,
    STA_DISCONNECTED,
    STA_ASSOCIATING,
    STA_ASSOCIATED,
    STA_ASSOC_FULL_REJECT,
    STA_AUTHING,
    STA_AUTHED,
    STA_DHCP,
    STA_DHCP_SUCCESS,
    STA_DISCONNECT,
    STA_DHCP_FAIL,
    STA_CLOSING,
};

enum class DisconnectDetailReason {
    UNUSED = 0,
    UNSPECIFIED = 1,
    DEAUTH_STA_IS_LEFING = 3,
    DISASSOC_STA_HAS_LEFT = 8
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
    int macType;
    unsigned int ipAddress;
    ConnState connState;
    bool ifHiddenSSID;
    int rxLinkSpeed; /* Downstream network speed */
    int txLinkSpeed; /* Upstream network speed */
    int chload;
    int snr;                         /* Signal-to-Noise Ratio */
    int isDataRestricted;
    std::string platformType;
    std::string portalUrl;
    SupplicantState supplicantState; /* wpa_supplicant state */
    DetailedState detailedState;     /* connection state */
    int wifiStandard;                /* wifi standard */
    int maxSupportedRxLinkSpeed;
    int maxSupportedTxLinkSpeed;
    WifiChannelWidth channelWidth; /* curr ap channel width */
    int lastPacketDirection;
    int lastRxPackets;
    int lastTxPackets;
    int retryedConnCount;
    bool isAncoConnected;
    WifiCategory supportedWifiCategory;
    bool isHiLinkNetwork;
    WifiLinkedInfo()
    {
        networkId = INVALID_NETWORK_ID;
        rssi = 0;
        band = 0;
        frequency = 0;
        linkSpeed = 0;
        macType = 0;
        ipAddress = 0;
        connState = ConnState::UNKNOWN;
        ifHiddenSSID = false;
        rxLinkSpeed = 0;
        txLinkSpeed = 0;
        chload = 0;
        snr = 0;
        isDataRestricted = 0;
        supplicantState = SupplicantState::INVALID;
        detailedState = DetailedState::INVALID;
        wifiStandard = 0;
        maxSupportedRxLinkSpeed = 0;
        maxSupportedTxLinkSpeed = 0;
        channelWidth = WifiChannelWidth::WIDTH_INVALID;
        lastPacketDirection = 0;
        lastRxPackets = 0;
        lastTxPackets = 0;
        retryedConnCount = 0;
        isAncoConnected = false;
        isHiLinkNetwork = false;
        supportedWifiCategory = WifiCategory::DEFAULT;
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
    ENABLED, /* enable */
    DISABLED, /* disabled */
    UNKNOWN
};

enum class AssignIpMethod { DHCP, STATIC, UNASSIGNED };

enum class ConfigChange {
    CONFIG_ADD = 0,
    CONFIG_UPDATE = 1,
    CONFIG_REMOVE = 2,
};

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
        addressIpv4 = IpTools::ConvertIpv4Address(address);
        if (addressIpv4 != 0) {
            family = IPV4_ADDRESS_TYPE;
        }
        return;
    }

    std::string GetIpv6Address()
    {
        return IpTools::ConvertIpv6Address(addressIpv6);
    }

    void SetIpv6Address(const std::string &address)
    {
        IpTools::ConvertIpv6Address(address, addressIpv6);
        if (addressIpv6.size() != 0) {
            family = IPV6_ADDRESS_TYPE;
        }
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

enum class EapMethod {
    EAP_NONE       = 0,
    EAP_PEAP       = 1,
    EAP_TLS        = 2,
    EAP_TTLS       = 3,
    EAP_PWD        = 4,
    EAP_SIM        = 5,
    EAP_AKA        = 6,
    EAP_AKA_PRIME  = 7,
    EAP_UNAUTH_TLS = 8
};

enum class Phase2Method {
    NONE      = 0,
    PAP       = 1,  // only EAP-TTLS support this mode
    MSCHAP    = 2,  // only EAP-TTLS support this mode
    MSCHAPV2  = 3,  // only EAP-PEAP/EAP-TTLS support this mode
    GTC       = 4,  // only EAP-PEAP/EAP-TTLS support this mode
    SIM       = 5,  // only EAP-PEAP support this mode
    AKA       = 6,  // only EAP-PEAP support this mode
    AKA_PRIME = 7   // only EAP-PEAP support this mode
};

class WifiEapConfig {
public:
    std::string eap;                        /* EAP authentication mode:PEAP/TLS/TTLS/PWD/SIM/AKA/AKA' */
    Phase2Method phase2Method;              /* Second stage authentication method */
    std::string identity;                   /* Identity information */
    std::string anonymousIdentity;          /* Anonymous identity information */
    std::string password;                   /* EAP mode password */
    std::string encryptedData;              /* EAP mode password encryptedData */
    std::string IV;                         /* EAP mode password encrypted IV */

    std::string caCertPath;                 /* CA certificate path */
    std::string caCertAlias;                /* CA certificate alias */
    std::vector<uint8_t> certEntry;         /* CA certificate entry */

    std::string clientCert;                 /* Client certificate */
    char certPassword[WIFI_PASSWORD_LEN];   /* Certificate password */
    std::string privateKey;                 /* Client certificate private key */

    std::string altSubjectMatch;            /* Alternative topic matching */
    std::string domainSuffixMatch;          /* Domain suffix matching */
    std::string realm;                      /* The field of passport credentials */
    std::string plmn;                       /* PLMN */
    int eapSubId;                           /* Sub ID of SIM card */

    WifiEapConfig()
    {
        phase2Method = Phase2Method::NONE;
        (void) memset_s(certPassword, sizeof(certPassword), 0, sizeof(certPassword));
        eapSubId = -1;
    }
    ~WifiEapConfig()
    {}
    /**
     * @Description convert Phase2Method to string
     *
     * @param eap - eap method
     * @param method - phase2method
     * @return string
     */
    static std::string Phase2MethodToStr(const std::string& eap, const int& method);

    /**
     * @Description convert string to Phase2Method
     *
     * @param str - phase2method string
     * @return Phase2Method
     */
    static Phase2Method Phase2MethodFromStr(const std::string& str);

    /**
     * @Description convert string to EapMethod
     *
     * @param str - EapMethod string
     * @return EapMethod
     */
    static EapMethod Str2EapMethod(const std::string& str);
};

enum class ConfigureProxyMethod { CLOSED, AUTOCONFIGUE, MANUALCONFIGUE };

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
    int instanceId;
    int networkId;
    /* 0: CURRENT, using 1: DISABLED 2: ENABLED */
    int status;
    /* mac address */
    std::string bssid;
    /* bssid type. */
    int bssidType;
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
    std::string encryptedData;
    std::string IV;
    /* Encryption Mode */
    std::string keyMgmt;
    /* WEP mode key, max size: 4 */
    std::string wepKeys[WEPKEYS_SIZE];
    /* use WEP key index */
    int wepTxKeyIndex;
    std::string encryWepKeys[WEPKEYS_SIZE];
    std::string IVWep;
    /* network priority */
    int priority;
    /* is hidden network */
    bool hiddenSSID;
    /* Random mac address */
    std::string macAddress;
    int uid;
    time_t lastConnectTime;
    int numRebootsSinceLastUse;
    int numAssociation;
    int connFailedCount;
    unsigned int networkStatusHistory;
    bool isPortal;
    time_t lastHasInternetTime;
    bool noInternetAccess;
    /* save select mac address */
    std::string userSelectBssid;
    WifiIpConfig wifiIpConfig;
    WifiEapConfig wifiEapConfig;
    WifiProxyConfig wifiProxyconfig;
    WifiPrivacyConfig wifiPrivacySetting;
    std::string callProcessName;
    std::string ancoCallProcessName;
    std::string internetSelfCureHistory;
    int isReassocSelfCureWithFactoryMacAddress;
    int version;
    bool randomizedMacSuccessEver;
    WifiDeviceConfig()
    {
        instanceId = 0;
        networkId = INVALID_NETWORK_ID;
        status = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
        bssidType = REAL_DEVICE_ADDRESS;
        band = 0;
        channel = 0;
        frequency = 0;
        level = 0;
        isPasspoint = false;
        isEphemeral = false;
        wepTxKeyIndex = 0;
        priority = 0;
        hiddenSSID = false;
        wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        rssi = -100;
        uid = WIFI_INVALID_UID;
        lastConnectTime = -1;
        numRebootsSinceLastUse = 0;
        numAssociation = 0;
        connFailedCount = 0;
        networkStatusHistory = 0;
        isPortal = false;
        lastHasInternetTime = -1;
        noInternetAccess = false;
        callProcessName = "";
        ancoCallProcessName = "";
        internetSelfCureHistory = "";
        isReassocSelfCureWithFactoryMacAddress = 0;
        version = -1;
        randomizedMacSuccessEver = false;
    }
};

enum class WifiState { DISABLING = 0, DISABLED = 1, ENABLING = 2, ENABLED = 3, UNKNOWN = 4 };

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
    START_AP_PIN_SUCCEED = 13,
    START_AP_PIN_FAILED = 14,
    STOP_AP_PIN_SUCCEED = 15,
    STOP_AP_PIN_FAILED = 16,
};

enum class StreamDirection {
    STREAM_DIRECTION_NONE = 0,
    STREAM_DIRECTION_DOWN = 1,
    STREAM_DIRECTION_UP = 2,
    STREAM_DIRECTION_UPDOWN = 3,
};

/* WifiProtectType  */
enum class WifiProtectType  {
    WIFI_PROTECT_MULTICAST = 0,
    WIFI_PROTECT_COMMON = 1
};

/* WifiProtectMode  */
enum class WifiProtectMode {
    WIFI_PROTECT_FULL = 0,
    WIFI_PROTECT_SCAN_ONLY = 1,
    WIFI_PROTECT_FULL_HIGH_PERF = 2,
    WIFI_PROTECT_FULL_LOW_LATENCY = 3,
    WIFI_PROTECT_NO_HELD = 4
};

/* DHCP info */
struct IpInfo {
    unsigned int ipAddress;     /* ip address */
    unsigned int gateway;       /* gate */
    unsigned int netmask;       /* mask */
    unsigned int primaryDns;          /* main dns */
    unsigned int secondDns;          /* backup dns */
    unsigned int serverIp; /* DHCP server's address */
    unsigned int leaseDuration;
    std::vector<unsigned int> dnsAddr;

    IpInfo()
    {
        ipAddress = 0;
        gateway = 0;
        netmask = 0;
        primaryDns = 0;
        secondDns = 0;
        serverIp = 0;
        leaseDuration = 0;
        dnsAddr.clear();
    }
};

/* DHCP IpV6Info */
struct IpV6Info {
    std::string linkIpV6Address;
    std::string globalIpV6Address;
    std::string randGlobalIpV6Address;
    std::string gateway;
    std::string netmask;
    std::string primaryDns;
    std::string secondDns;
    std::string uniqueLocalAddress1;
    std::string uniqueLocalAddress2;
    std::vector<std::string> dnsAddr;
    
    IpV6Info()
    {
        linkIpV6Address = "";
        globalIpV6Address = "";
        randGlobalIpV6Address = "";
        gateway = "";
        netmask = "";
        primaryDns = "";
        secondDns = "";
        uniqueLocalAddress1 = "";
        uniqueLocalAddress2 = "";
        dnsAddr.clear();
    }
};

struct Wifi6BlackListInfo {
    /* 0:HTC, 1:WIFI6, -1:invalid */
    int actionType = -1;
    int64_t updateTime = 0;

    Wifi6BlackListInfo(int type, int64_t time)
    {
        this->actionType = type;
        this->updateTime = time;
    }
};

// SIM authentication
struct EapSimGsmAuthParam {
    std::vector<std::string> rands;
};

// AKA/AKA' authentication
struct EapSimUmtsAuthParam {
    std::string rand;
    std::string autn;
    EapSimUmtsAuthParam()
    {
        rand = "";
        autn = "";
    }
};
typedef enum {
    BG_LIMIT_CONTROL_ID_GAME = 1,
    BG_LIMIT_CONTROL_ID_STREAM,
    BG_LIMIT_CONTROL_ID_TEMP,
    BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT,
} BgLimitControl;

typedef enum {
    BG_LIMIT_OFF = 0,
    BG_LIMIT_LEVEL_1,
    BG_LIMIT_LEVEL_2,
    BG_LIMIT_LEVEL_3,
    BG_LIMIT_LEVEL_4,
    BG_LIMIT_LEVEL_5,
    BG_LIMIT_LEVEL_6,
    BG_LIMIT_LEVEL_7,
    BG_LIMIT_LEVEL_8,
    BG_LIMIT_LEVEL_9,
    BG_LIMIT_LEVEL_10,
    BG_LIMIT_LEVEL_11,
} BgLimitLevel;
}  // namespace Wifi
}  // namespace OHOS
#endif
