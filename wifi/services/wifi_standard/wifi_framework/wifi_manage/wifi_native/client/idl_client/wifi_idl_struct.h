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

#ifndef OHOS_WIFI_IDL_STRUCT_H
#define OHOS_WIFI_IDL_STRUCT_H

#include <string>
#include <vector>

#define WIFI_PASSWORD_LEN 128
namespace OHOS {
namespace Wifi {
struct WifiApConnectionNofify {
    int type;
    std::string mac;

    WifiApConnectionNofify() : type(0)
    {}

    ~WifiApConnectionNofify()
    {}
};

constexpr int MAX_WEPKEYS_SIZE = 4;
constexpr int AUTH_ALGORITHM_MAX = 8;

enum class IdlPhase2Method {
    PHASE2_NONE      = 0,
    PHASE2_PAP       = 1,  // EAP-TTLS
    PHASE2_MSCHAP    = 2,  // EAP-TTLS
    PHASE2_MSCHAPV2  = 3,  // EAP-PEAP/EAP-TTLS
    PHASE2_GTC       = 4,  // EAP-PEAP/EAP-TTLS
    PHASE2_SIM       = 5,  // EAP-PEAP
    PHASE2_AKA       = 6,  // EAP-PEAP
    PHASE2_AKA_PRIME = 7   // EAP-PEAP
};

struct WifiIdlEapConfig {
    std::string eap;                        /* EAP authentication mode:PEAP/TLS/TTLS/PWD/SIM/AKA/AKA' */
    int phase2Method;                       /* Second stage authentication method */
    std::string identity;                   /* Identity information */
    std::string anonymousIdentity;          /* Anonymous identity information */
    char password[WIFI_PASSWORD_LEN];       /* EAP mode password */

    std::string caCertPath;                 /* CA certificate path */
    std::string caCertAlias;                /* CA certificate alias */
    std::vector<uint8_t> certEntry;       /* CA certificate entry */

    std::string clientCert;                 /* Client certificate */
    char certPassword[WIFI_PASSWORD_LEN];   /* Certificate password */
    std::string privateKey;                 /* Client certificate private key */

    std::string altSubjectMatch;            /* Alternative topic matching */
    std::string domainSuffixMatch;          /* Domain suffix matching */
    std::string realm;                      /* The field of passport credentials */
    std::string plmn;                       /* PLMN */
    int eapSubId;                           /* Sub ID of SIM card */
    WifiIdlEapConfig() : phase2Method(0), password{0}, certPassword{0}, eapSubId(-1)
    {}

    ~WifiIdlEapConfig()
    {}
};

struct WifiIdlDeviceConfig {
    int networkId;
    int priority;
    int scanSsid;
    int authAlgorithms; /* WifiDeviceConfig.allowedAuthAlgorithms */
    int wepKeyIdx;
    std::string wepKeys[MAX_WEPKEYS_SIZE]; /* max set 4 wepkeys */
    std::string ssid;
    std::string psk;
    std::string keyMgmt;
    WifiIdlEapConfig eapConfig;
    std::string bssid;
    bool isRequirePmf;
    int allowedProtocols;
    int allowedPairwiseCiphers;
    int allowedGroupCiphers;
    WifiIdlDeviceConfig() : networkId(-1), priority(-1), scanSsid(-1), authAlgorithms(-1), wepKeyIdx(-1)
    {}

    ~WifiIdlDeviceConfig()
    {}
};

struct WifiIdlGetDeviceConfig {
    int networkId;
    std::string param;
    std::string value;

    WifiIdlGetDeviceConfig() : networkId(-1)
    {}

    ~WifiIdlGetDeviceConfig()
    {}
};

struct WifiIdlWpsConfig {
    int anyFlag;
    int multiAp;
    std::string bssid;
    std::string pinCode;

    WifiIdlWpsConfig() : anyFlag(-1), multiAp(-1)
    {}

    ~WifiIdlWpsConfig()
    {}
};

struct WifiWpaSignalInfo {
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
    int txBytes;
    int rxBytes;
    int txFailed;

    WifiWpaSignalInfo() : signal(0), txrate(0), rxrate(0), noise(0), frequency(0),
        txPackets(0), rxPackets(0), snr(0), chload(0), ulDelay(0), txBytes(0), rxBytes(0),
        txFailed(0)
    {}

    ~WifiWpaSignalInfo()
    {}
};

struct WifiIdlRoamCapability {
    int maxBlocklistSize;
    int maxTrustlistSize;

    WifiIdlRoamCapability() : maxBlocklistSize(0), maxTrustlistSize(0)
    {}

    ~WifiIdlRoamCapability()
    {}
};

struct WifiIdlRoamConfig {
    std::vector<std::string> blocklistBssids;
    std::vector<std::string> trustlistBssids;
};

struct WifiWpaNetworkInfo {
    int id;
    std::string ssid;
    std::string bssid;
    std::string flag;

    WifiWpaNetworkInfo() : id(0)
    {}

    ~WifiWpaNetworkInfo()
    {}
};

struct IdlP2pDeviceFound {
    std::string srcAddress;
    std::string p2pDeviceAddress;
    std::string primaryDeviceType;
    std::string deviceName;
    int configMethods;
    int deviceCapabilities;
    int groupCapabilities;
    std::vector<char> wfdDeviceInfo;

    IdlP2pDeviceFound() : configMethods(0), deviceCapabilities(0), groupCapabilities(0)
    {}

    ~IdlP2pDeviceFound()
    {}
};

struct IdlP2pInvitationInfo {
    int type; /* 0:Received, 1:Accepted */
    int persistentNetworkId;
    int operatingFrequency;
    std::string srcAddress;
    std::string goDeviceAddress;
    std::string bssid;

    IdlP2pInvitationInfo() : type(0), persistentNetworkId(0), operatingFrequency(0)
    {}

    ~IdlP2pInvitationInfo()
    {}
};

struct IdlP2pGroupInfo {
    int isGo;
    int isPersistent;
    int frequency;
    std::string groupName;
    std::string ssid;
    std::string psk;
    std::string passphrase;
    std::string goDeviceAddress;

    IdlP2pGroupInfo() : isGo(0), isPersistent(0), frequency(0)
    {}

    ~IdlP2pGroupInfo()
    {}
};

struct IdlP2pServDiscReqInfo {
    int freq;
    int dialogToken;
    int updateIndic;
    std::string mac;
    std::vector<unsigned char> tlvList;

    IdlP2pServDiscReqInfo() : freq(0), dialogToken(0), updateIndic(0)
    {}

    ~IdlP2pServDiscReqInfo()
    {}
};

struct IdlP2pGroupConfig {
    std::string ssid;
    std::string bssid;
    std::string psk;
    std::string proto;
    std::string keyMgmt;
    std::string pairwise;
    std::string authAlg;
    int mode;
    int disabled;

    IdlP2pGroupConfig()
        : bssid("00:00:00:00:00:00"),
          proto("RSN"),
          keyMgmt("WPA-PSK"),
          pairwise("CCMP"),
          authAlg("OPEN"),
          mode(0),
          disabled(0)
    {}

    ~IdlP2pGroupConfig()
    {}
};
}  // namespace Wifi
}  // namespace OHOS
#endif
