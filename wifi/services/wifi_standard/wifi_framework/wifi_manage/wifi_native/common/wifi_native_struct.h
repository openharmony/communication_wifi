/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_NATIVE_STRUCT_H
#define OHOS_WIFI_NATIVE_STRUCT_H

#include <string>
#include <vector>
#include "wifi_native_define.h"

namespace OHOS {
namespace Wifi {
struct WifiHalEapConfig {
    std::string eap;                        /* EAP authentication mode:PEAP/TLS/TTLS/PWD/SIM/AKA/AKA' */
    int phase2Method;                       /* Second stage authentication method */
    std::string identity;                   /* Identity information */
    std::string anonymousIdentity;          /* Anonymous identity information */
    char password[HAL_PASSWORD_LEN];       /* EAP mode password */

    std::string caCertPath;                 /* CA certificate path */
    std::string caCertAlias;                /* CA certificate alias */
    std::vector<uint8_t> certEntry;       /* CA certificate entry */

    std::string clientCert;                 /* Client certificate */
    char certPassword[HAL_PASSWORD_LEN];   /* Certificate password */
    std::string privateKey;                 /* Client certificate private key */

    std::string altSubjectMatch;            /* Alternative topic matching */
    std::string domainSuffixMatch;          /* Domain suffix matching */
    std::string realm;                      /* The field of passport credentials */
    std::string plmn;                       /* PLMN */
    int eapSubId;                           /* Sub ID of SIM card */
    WifiHalEapConfig() : phase2Method(0), password{0}, certPassword{0}, eapSubId(-1)
    {}

    ~WifiHalEapConfig()
    {}
};

struct WifiHalDeviceConfig {
    int networkId;
    int priority;
    int scanSsid;
    int authAlgorithms; /* WifiDeviceConfig.allowedAuthAlgorithms */
    int wepKeyIdx;
    std::string wepKeys[HAL_MAX_WEPKEYS_SIZE]; /* max set 4 wepkeys */
    std::string ssid;
    std::string psk;
    std::string keyMgmt;
    WifiHalEapConfig eapConfig;
    std::string bssid;
    bool isRequirePmf;
    int allowedProtocols;
    int allowedPairwiseCiphers;
    int allowedGroupCiphers;
    int allowedGroupMgmtCiphers;
    int wapiPskType;
    std::string wapiAsCertData;
    std::string wapiUserCertData;
    WifiHalDeviceConfig() : networkId(-1), priority(-1), scanSsid(-1), authAlgorithms(-1), wepKeyIdx(-1),
                            isRequirePmf(false), allowedProtocols(-1), allowedPairwiseCiphers(-1),
                            allowedGroupCiphers(-1), allowedGroupMgmtCiphers(-1), wapiPskType(-1)
    {}

    ~WifiHalDeviceConfig()
    {}
};

struct WifiHalGetDeviceConfig {
    int networkId;
    std::string param;
    std::string value;

    WifiHalGetDeviceConfig() : networkId(-1)
    {}

    ~WifiHalGetDeviceConfig()
    {}
};

struct WifiHalWpsConfig {
    int anyFlag;
    int multiAp;
    std::string bssid;
    std::string pinCode;

    WifiHalWpsConfig() : anyFlag(-1), multiAp(-1)
    {}

    ~WifiHalWpsConfig()
    {}
};

struct WifiHalRoamCapability {
    int maxBlocklistSize;
    int maxTrustlistSize;

    WifiHalRoamCapability() : maxBlocklistSize(0), maxTrustlistSize(0)
    {}

    ~WifiHalRoamCapability()
    {}
};

struct WifiHalRoamConfig {
    std::vector<std::string> blocklistBssids;
    std::vector<std::string> trustlistBssids;
};

struct WifiHalWpaNetworkInfo {
    int id;
    std::string ssid;
    std::string bssid;
    std::string flag;

    WifiHalWpaNetworkInfo() : id(0)
    {}

    ~WifiHalWpaNetworkInfo()
    {}
};

struct HalP2pDeviceFound {
    std::string srcAddress;
    std::string p2pDeviceAddress;
    std::string primaryDeviceType;
    std::string deviceName;
    int configMethods;
    int deviceCapabilities;
    int groupCapabilities;
    std::vector<char> wfdDeviceInfo;

    HalP2pDeviceFound() : configMethods(0), deviceCapabilities(0), groupCapabilities(0)
    {}

    ~HalP2pDeviceFound()
    {}
};

struct HalP2pInvitationInfo {
    int type; /* 0:Received, 1:Accepted */
    int persistentNetworkId;
    int operatingFrequency;
    std::string srcAddress;
    std::string goDeviceAddress;
    std::string bssid;

    HalP2pInvitationInfo() : type(0), persistentNetworkId(0), operatingFrequency(0)
    {}

    ~HalP2pInvitationInfo()
    {}
};

struct HalP2pGroupInfo {
    int isGo;
    int isPersistent;
    int frequency;
    std::string groupName;
    std::string ssid;
    std::string psk;
    std::string passphrase;
    std::string goDeviceAddress;
    std::string goRandomAddress;

    HalP2pGroupInfo() : isGo(0), isPersistent(0), frequency(0)
    {}

    ~HalP2pGroupInfo()
    {}
};

struct HalP2pServDiscReqInfo {
    int freq;
    int dialogToken;
    int updateIndic;
    std::string mac;
    std::vector<unsigned char> tlvList;

    HalP2pServDiscReqInfo() : freq(0), dialogToken(0), updateIndic(0)
    {}

    ~HalP2pServDiscReqInfo()
    {}
};

struct HalP2pGroupConfig {
    std::string ssid;
    std::string bssid;
    std::string psk;
    std::string proto;
    std::string keyMgmt;
    std::string pairwise;
    std::string authAlg;
    int mode;
    int disabled;

    HalP2pGroupConfig()
        : bssid("00:00:00:00:00:00"),
          proto("RSN"),
          keyMgmt("WPA-PSK"),
          pairwise("CCMP"),
          authAlg("OPEN"),
          mode(0),
          disabled(0)
    {}

    ~HalP2pGroupConfig()
    {}
};

struct WifiHalScanParam {
    std::vector<std::string> hiddenNetworkSsid; /* Hiding Network SSIDs */
    std::vector<int> scanFreqs;                 /* Scan frequency */
    int scanStyle;
    WifiHalScanParam()
    {
        scanStyle = 0;
    }
};

struct WifiHalPnoScanParam {
    int scanInterval;                    /* PNO Scan Interval */
    std::vector<int> scanFreqs;          /* Scanning frequency */
    std::vector<std::string> hiddenSsid; /* Network name of hidden network */
    std::vector<std::string> savedSsid;  /* Network name of saved network */
    int minRssi2Dot4Ghz;                 /* Minimum 2.4 GHz network signal strength */
    int minRssi5Ghz;                     /* Minimum 5 GHz network signal strength */

    WifiHalPnoScanParam()
    {
        scanFreqs.clear();
        hiddenSsid.clear();
        savedSsid.clear();

        scanInterval = 0;
        minRssi2Dot4Ghz = 0;
        minRssi5Ghz = 0;
    }

    ~WifiHalPnoScanParam()
    {
        scanFreqs.clear();
        hiddenSsid.clear();
        savedSsid.clear();
    }
};

struct WifiHalApConnectionNofify {
    int type;
    std::string mac;

    WifiHalApConnectionNofify() : type(0)
    {}

    ~WifiHalApConnectionNofify()
    {}
};

}  // namespace Wifi
}  // namespace OHOS
#endif