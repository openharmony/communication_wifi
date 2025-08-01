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
#define UNKNOWN_HILINK_NETWORK_ID (-2)
#define WIFI_INVALID_UID (-1)
#define INVALID_SIGNAL_LEVEL (-1)
#define INVALID_LINK_ID (-1)
#define IPV4_ADDRESS_TYPE 0
#define IPV6_ADDRESS_TYPE 1
#define WIFI_INVALID_SIM_ID (0)
#define WIFI_EAP_OPEN_EXTERNAL_SIM 1
#define WIFI_EAP_CLOSE_EXTERNAL_SIM 0
#define WIFI_PASSWORD_LEN 128
#define MAX_PID_LIST_SIZE 128
#define REGISTERINFO_MAX_NUM 1000
#define WIFI_MAX_MLO_LINK_NUM 2
#define EXTERNAL_HILINK_MAX_VALUE 3
#define INTERNAL_HILINK_MAX_VALUE 10

inline const std::string KEY_MGMT_NONE = "NONE";
inline const std::string KEY_MGMT_WEP = "WEP";
inline const std::string KEY_MGMT_WPA_PSK = "WPA-PSK";
inline const std::string KEY_MGMT_SAE = "SAE";
inline const std::string KEY_MGMT_EAP = "WPA-EAP";
inline const std::string KEY_MGMT_SUITE_B_192 = "WPA-EAP-SUITE-B-192";
inline const std::string KEY_MGMT_WAPI_CERT = "WAPI-CERT";
inline const std::string KEY_MGMT_WAPI_PSK = "WAPI-PSK";
inline const std::string KEY_MGMT_WAPI = "WAPI";
inline const int KEY_MGMT_TOTAL_NUM = 8;
inline const std::string KEY_MGMT_ARRAY[KEY_MGMT_TOTAL_NUM] = {
    KEY_MGMT_NONE,
    KEY_MGMT_WEP,
    KEY_MGMT_WPA_PSK,
    KEY_MGMT_SAE,
    KEY_MGMT_EAP,
    KEY_MGMT_SUITE_B_192,
    KEY_MGMT_WAPI_CERT,
    KEY_MGMT_WAPI_PSK
};
inline const std::string EAP_METHOD_NONE = "NONE";
inline const std::string EAP_METHOD_PEAP = "PEAP";
inline const std::string EAP_METHOD_TLS = "TLS";
inline const std::string EAP_METHOD_TTLS = "TTLS";
inline const std::string EAP_METHOD_PWD = "PWD";
inline const std::string EAP_METHOD_SIM = "SIM";
inline const std::string EAP_METHOD_AKA = "AKA";
inline const std::string EAP_METHOD_AKA_PRIME = "AKA'";

inline const int INVALID_NETWORK_SELECTION_DISABLE_TIMESTAMP = -1;

enum SigLevel {
    SIG_LEVEL_0 = 0,
    SIG_LEVEL_1 = 1,
    SIG_LEVEL_2 = 2,
    SIG_LEVEL_3 = 3,
    SIG_LEVEL_4 = 4,
    SIG_LEVEL_MAX = 4,
};

enum WifiRestrictedType {
    MDM_BLOCKLIST = 0,
    MDM_WHITELIST = 1,
    MDM_INVALID_LIST = 2
};

enum GameSceneId : int {
    MSG_GAME_STATE_START = 0,
    MSG_GAME_STATE_END = 1,
    MSG_GAME_ENTER_PVP_BATTLE = 2,
    MSG_GAME_EXIT_PVP_BATTLE = 3,
    MSG_GAME_STATE_FOREGROUND = 4,
    MSG_GAME_STATE_BACKGROUND = 5,
};
 
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

enum WurState {
    WUR_DISABLE = 0,
    WUR_ENABLE = 1,
    WUR_ENABLE_FAIL = 2
};

enum WifiLinkType:int32_t {
    DISCONNECT = -1,
    DEFAULT_LINK = 0,
    WIFI7_SINGLE_LINK = 1,
    WIFI7_MLSR = 2,
    WIFI7_EMLSR = 3,
    WIFI7_STR = 4
};

enum class DisconnectedReason {
    /* Default reason */
    DISC_REASON_DEFAULT = 0,

    /* Password is wrong */
    DISC_REASON_WRONG_PWD = 1,

    /* The number of router's connection reaches the maximum number limit */
    DISC_REASON_CONNECTION_FULL = 2,

    /* Connection Rejected */
    DISC_REASON_CONNECTION_REJECTED = 3,
 
    /* Connect mdm blocklist or  wifi is fail*/
    DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL = 5,

    /* Connect fail reason max value, add new reason before this*/
    DISC_REASON_MAX_VALUE
};

enum class WifiOperateType {
    STA_OPEN,
    STA_CLOSE,
    STA_CONNECT,
    STA_ASSOC,
    STA_AUTH,
    STA_DHCP,
    STA_SEMI_OPEN
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
    STA_CLOSED,
    STA_SEMI_OPENING,
    STA_SEMI_OPENED,
};

enum class DisconnectDetailReason {
    UNUSED = 0,
    UNSPECIFIED = 1,
    PREV_AUTH_NOT_VALID = 2,
    DEAUTH_STA_IS_LEFING = 3,
    DISASSOC_DUE_TO_INACTIVITY = 4,
    DISASSOC_AP_BUSY = 5,
    DISASSOC_STA_HAS_LEFT = 8,
    DISASSOC_IEEE_802_1X_AUTH_FAILED = 23,
    DISASSOC_LOW_ACK = 34
};

struct WifiMloSignalInfo {
    int32_t linkId {INVALID_LINK_ID};
    int32_t frequency {0};
    int32_t rssi {0};
    int32_t linkSpeed {0};
    int32_t rxLinkSpeed {0};
    int32_t txLinkSpeed {0};
    int32_t rxPackets {0};
    int32_t txPackets {0};
    WifiChannelWidth channelWidth {WifiChannelWidth::WIDTH_INVALID};
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
    WifiLinkType wifiLinkType; /* MLO connected state */
    int wifiStandard;                /* wifi standard */
    int maxSupportedRxLinkSpeed;
    int maxSupportedTxLinkSpeed;
    WifiChannelWidth channelWidth; /* curr ap channel width */
    int lastPacketDirection;
    int lastRxPackets;
    int lastTxPackets;
    bool isAncoConnected;
    WifiCategory supportedWifiCategory;
    bool isMloConnected;
    int isHiLinkNetwork;
    bool isHiLinkProNetwork;
    bool isWurEnable;
    int c0Rssi;
    int c1Rssi;
    int linkId;
    int centerFrequency0; /* 40M center frequency */
    int centerFrequency1; /* 160M center frequency */
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
        wifiLinkType = WifiLinkType::DEFAULT_LINK;
        wifiStandard = 0;
        maxSupportedRxLinkSpeed = 0;
        maxSupportedTxLinkSpeed = 0;
        channelWidth = WifiChannelWidth::WIDTH_INVALID;
        lastPacketDirection = 0;
        lastRxPackets = 0;
        lastTxPackets = 0;
        isAncoConnected = false;
        isHiLinkNetwork = 0;
        isHiLinkProNetwork = false;
        supportedWifiCategory = WifiCategory::DEFAULT;
        isMloConnected = false;
        isWurEnable = false;
        c0Rssi = 0;
        c1Rssi = 0;
        linkId = INVALID_LINK_ID;
        centerFrequency0 = 0;
        centerFrequency1 = 0;
    }
};

/* Wifi access list info */
struct WifiRestrictedInfo {
    std::string ssid;
    std::string bssid;
    WifiRestrictedType wifiRestrictedType;
    int uid;
 
    WifiRestrictedInfo()
    {
        ssid = "";
        bssid = "";
        wifiRestrictedType = MDM_INVALID_LIST;
        uid = 0;
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
    PERMEMANTLY_DISABLED, /* permanently disabled */
    UNKNOWN
};

enum class AssignIpMethod { DHCP, STATIC, UNASSIGNED };

enum class ConfigChange {
    CONFIG_ADD = 0,
    CONFIG_UPDATE = 1,
    CONFIG_REMOVE = 2,
};

enum class CandidateApprovalStatus {
    USER_ACCEPT = 0,
    USER_REJECT = 1,
    USER_NO_RESPOND = 2,
};

struct VoWifiSignalInfo {
    int rssi;
    int noise;
    int bler;
    int deltaTxPacketCounter;
    int accessType;
    int reverse;
    int64_t txGood;
    int64_t txBad;
    std::string macAddress;
};
 
struct WifiDetectConfInfo {
    int wifiDetectMode;
    int threshold;
    int envalueCount;
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

    std::string GetIpv6Address() const
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

enum class DisabledReason {
    DISABLED_UNKNOWN_REASON = -1,
    DISABLED_NONE = 0,
    DISABLED_ASSOCIATION_REJECTION = 1,
    DISABLED_AUTHENTICATION_FAILURE = 2,
    DISABLED_DHCP_FAILURE = 3,
    DISABLED_NO_INTERNET_TEMPORARY = 4,
    DISABLED_AUTHENTICATION_NO_CREDENTIALS = 5,
    DISABLED_NO_INTERNET_PERMANENT = 6,
    DISABLED_BY_WIFI_MANAGER = 7,
    DISABLED_BY_WRONG_PASSWORD = 8,
    DISABLED_AUTHENTICATION_NO_SUBSCRIPTION = 9,
    DISABLED_AUTHENTICATION_PRIVATE_EAP_ERROR = 10,
    DISABLED_NETWORK_NOT_FOUND = 11,
    DISABLED_CONSECUTIVE_FAILURES = 12,
    DISABLED_BY_SYSTEM = 13,
    DISABLED_EAP_AKA_FAILURE = 14,
    DISABLED_DISASSOC_REASON = 15,
    DISABLED_MDM_RESTRICTED = 16,
    NETWORK_SELECTION_DISABLED_MAX = 17
};

struct NetworkSelectionStatus {
    WifiDeviceConfigStatus status;
    DisabledReason networkSelectionDisableReason;
    int64_t networkDisableTimeStamp;
    int networkDisableCount;

    /**
     * Connect Choice over this configuration
     * when current wifi config is visible to the user but user explicitly choose to connect to another network X,
     * the another network X's config network ID will be stored here. We will consider user has a preference of X
     * over this network. And in the future, network Select will always give X a higher preference over this config
     */
    int connectChoice;

    /**
     * The system timestamp when we records the connectChoice. Used to calculate if timeout of network selected by user
     */
    long connectChoiceTimestamp;

    /**
     * Indicate whether this network is visible in last Qualified Network Selection. This means there is scan result
     * found to this WifiDeviceConfig and meet the minimum requirement.
     */
    bool seenInLastQualifiedNetworkSelection;
    NetworkSelectionStatus()
    {
        status = WifiDeviceConfigStatus::ENABLED;
        networkSelectionDisableReason = DisabledReason::DISABLED_NONE;
        networkDisableTimeStamp = -1;
        networkDisableCount = 0;
        connectChoice = INVALID_NETWORK_ID;
        connectChoiceTimestamp = INVALID_NETWORK_SELECTION_DISABLE_TIMESTAMP;
        seenInLastQualifiedNetworkSelection = false;
    }
};

class WifiWapiConfig {
public:
    int wapiPskType;
    std::string wapiAsCertData;
    std::string wapiUserCertData;
    std::string encryptedAsCertData;
    std::string asCertDataIV;
    std::string encryptedUserCertData;
    std::string userCertDataIV;

    WifiWapiConfig()
    {
        wapiPskType = -1;
    }

    ~WifiWapiConfig()
    {}
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

/* Network control information */
struct WifiNetworkControlInfo {
    int uid;
    int pid;
    std::string bundleName;
    int state;
    int sceneId;
    int rtt;

    WifiNetworkControlInfo()
    {
        uid = -1;
        pid = -1;
        bundleName = "";
        state = -1;
        sceneId = -1;
        rtt = -1;
    }
};

/* Network configuration information */
struct WifiDeviceConfig {
    int instanceId;
    int networkId;
    /* int status; @deprecated : CURRENT, using 1: DISABLED 2: ENABLED */
    /*  network selection status*/
    NetworkSelectionStatus networkSelectionStatus;
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
    /* Available Encryption Mode */
    uint32_t keyMgmtBitset;
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
    /* last update time */
    time_t lastUpdateTime;
    int numRebootsSinceLastUse;
    int numAssociation;
    int connFailedCount;
    unsigned int networkStatusHistory;
    bool isPortal;
    time_t portalAuthTime;
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
    bool everConnected;
    bool acceptUnvalidated;
    WifiWapiConfig wifiWapiConfig;
    IpInfo lastDhcpResult;
    bool isShared;
    int64_t lastTrySwitchWifiTimestamp { -1 };
    bool isAllowAutoConnect { true };
    bool isSecureWifi { true };
    time_t lastDetectTime;

    WifiDeviceConfig()
    {
        instanceId = 0;
        networkId = INVALID_NETWORK_ID;
        bssidType = REAL_DEVICE_ADDRESS;
        band = 0;
        channel = 0;
        frequency = 0;
        level = 0;
        isPasspoint = false;
        isEphemeral = false;
        keyMgmtBitset = 0u;
        wepTxKeyIndex = 0;
        priority = 0;
        hiddenSSID = false;
        wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        rssi = -100;
        uid = WIFI_INVALID_UID;
        lastConnectTime = -1;
        lastUpdateTime = -1;
        numRebootsSinceLastUse = 0;
        numAssociation = 0;
        connFailedCount = 0;
        networkStatusHistory = 0;
        isPortal = false;
        portalAuthTime = -1;
        lastHasInternetTime = -1;
        noInternetAccess = false;
        callProcessName = "";
        ancoCallProcessName = "";
        internetSelfCureHistory = "";
        isReassocSelfCureWithFactoryMacAddress = 0;
        version = -1;
        randomizedMacSuccessEver = false;
        isShared = true;
        everConnected = false;
        acceptUnvalidated = false;
        lastDetectTime = -1;
    }
};

enum class WifiState { DISABLING = 0, DISABLED = 1, ENABLING = 2, ENABLED = 3, UNKNOWN = 4 };

enum class WifiDetailState {
    STATE_UNKNOWN = -1,
    STATE_INACTIVE = 0,
    STATE_ACTIVATED = 1,
    STATE_ACTIVATING = 2,
    STATE_DEACTIVATING = 3,
    STATE_SEMI_ACTIVATING = 4,
    STATE_SEMI_ACTIVE = 5
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
    WIFI_PROTECT_DEFAULT = -1,
    WIFI_PROTECT_FULL = 0,
    WIFI_PROTECT_SCAN_ONLY = 1,
    WIFI_PROTECT_FULL_HIGH_PERF = 2,
    WIFI_PROTECT_FULL_LOW_LATENCY = 3,
    WIFI_PROTECT_NO_HELD = 4
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

struct WifiCategoryBlackListInfo {
    /* 0:HTC, 1:WIFI6, -1:invalid */
    /* 0:MLD, 1:WIFI7, -1:invalid */
    int actionType = -1;
    int64_t updateTime = 0;

    WifiCategoryBlackListInfo() {}

    WifiCategoryBlackListInfo(int type, int64_t time)
    {
        this->actionType = type;
        this->updateTime = time;
    }
};

struct WifiCategoryConnectFailInfo {
    /* 0:MLD, 1:WIFI7, 2:Cure Fail,-1:invalid */
    int actionType = -1;
    int connectFailTimes = 0;
    int64_t updateTime = 0;

    WifiCategoryConnectFailInfo() {}

    WifiCategoryConnectFailInfo(int type, int failTimes, int64_t time)
    {
        this->actionType = type;
        this->connectFailTimes = failTimes;
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

struct MloStateParam {
    uint8_t feature;
    uint8_t state;
    uint16_t reasonCode;
};

typedef enum {
    BG_LIMIT_CONTROL_ID_GAME = 1,
    BG_LIMIT_CONTROL_ID_STREAM,
    BG_LIMIT_CONTROL_ID_TEMP,
    BG_LIMIT_CONTROL_ID_KEY_FG_APP,
    BG_LIMIT_CONTROL_ID_AUDIO_PLAYBACK,
    BG_LIMIT_CONTROL_ID_WINDOW_VISIBLE,
    BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT,
    BG_LIMIT_CONTROL_ID_VIDEO_CALL,
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

enum class WapiPskType {
    WAPI_PSK_ASCII = 0,
    WAPI_PSK_HEX = 1,
};

typedef struct {
    std::string ifName;
    int scene;
    int rssiThreshold;
    std::string peerMacaddr;
    std::string powerParam;
    int powerParamLen;
} WifiLowPowerParam;

enum class OperationCmd {
    DHCP_OFFER_ADD,
    DHCP_OFFER_SIZE_GET,
    DHCP_OFFER_CLEAR,
    CURRENT_IP_INFO_SET,
};

enum class WifiSelfcureType {
    DNS_ABNORMAL,
    TCP_RX_ABNORMAL,
    ROAMING_ABNORMAL,
    GATEWAY_ABNORMAL,
    RAND_MAC_REASSOC_SELFCURE,
    MULTI_GATEWAY_SELFCURE,
    DNS_SELFCURE_SUCC,
    STATIC_IP_SELFCURE_SUCC,
    REASSOC_SELFCURE_SUCC,
    RESET_SELFCURE_SUCC,
    RAND_MAC_REASSOC_SELFCURE_SUCC,
    MULTI_GATEWAY_SELFCURE_SUCC,
};

enum class Wifi3VapConflictType {
    STA_HML_SOFTAP_CONFLICT_CNT,
    STA_P2P_SOFTAP_CONFLICT_CNT,
    P2P_HML_SOFTAP_CONFLICT_CNT,
    HML_SOFTAP_STA_CONFLICT_CNT,
    P2P_SOFTAP_STA_CONFLICT_CNT,
    P2P_HML_STA_CONFLICT_CNT,
};

enum class NetworkLagType {
    DEFAULT = 0,
    WIFIPRO_QOE_SLOW,
    WIFIPRO_QOE_REPORT,
};
 
struct NetworkLagInfo {
    uint32_t uid { 0 };
    uint32_t rssi { 0 };
    uint32_t tcpRtt { 0 };
 
    NetworkLagInfo()
    {
        uid = 0;
        rssi = 0;
        tcpRtt = 0;
    }
};

struct WifiSignalPollInfo {
    int signal;
    int txrate;
    int rxrate;
    int noise;
    int frequency;
    int txPackets;
    int rxPackets;
    int snr;
    int chload;
    int ulDelay;
    unsigned int txBytes;
    unsigned int rxBytes;
    int txFailed;
    int chloadSelf;
    int c0Rssi;
    int c1Rssi;
    std::vector<uint8_t> ext;
    int extLen;
    int64_t timeStamp;

    WifiSignalPollInfo() : signal(0), txrate(0), rxrate(0), noise(0), frequency(0),
        txPackets(0), rxPackets(0), snr(0), chload(0), ulDelay(0), txBytes(0), rxBytes(0),
        txFailed(0), chloadSelf(0), c0Rssi(0), c1Rssi(0), ext(), extLen(0), timeStamp(0)
    {}

    ~WifiSignalPollInfo()
    {}
};

enum class LimitSwitchScenes {
    NOT_LIMIT = 0,
    DUAL_BAND_ROAM = 1,
};
struct WpaEapData {
    int32_t msgId;
    int32_t code; /* eap code */
    int32_t type; /* eap type */
    int32_t bufferLen; /* length of data in the buffer */
    std::vector<uint8_t> eapBuffer; /* eap Data */
};
}  // namespace Wifi
}  // namespace OHOS
#endif
