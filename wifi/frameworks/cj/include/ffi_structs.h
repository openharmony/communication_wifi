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

#ifndef CJ_WIFI_FFI_STRUCTS_H
#define CJ_WIFI_FFI_STRUCTS_H

#include <cstdint>

#include "cj_ffi/cj_common_ffi.h"

extern "C" {
struct CWifiInfoElem {
    uint32_t eid;
    CArrUI8 content;
};

struct CWifiScanInfo {
    char* ssid;
    char* bssid;
    int32_t bssidType;
    char* capabilities;
    int32_t securityType;
    int32_t rssi;
    int32_t band;
    int32_t frequency;
    int32_t channelWidth;
    int32_t centerFrequency0;
    int32_t centerFrequency1;
    CWifiInfoElem* infoElems;
    int64_t elemsSize;
    int64_t timestamp;
    int32_t supportedWifiCategory;
    bool isHiLinkNetwork;
};

struct WifiScanInfoArr {
    CWifiScanInfo* head;
    int64_t size;
};

struct CWifiEapConfig {
    int32_t eapMethod;       /* EAP authentication mode:PEAP/TLS/TTLS/PWD/SIM/AKA/AKA' */
    int32_t phase2Method;    /* Second stage authentication method */
    char* identity;          /* Identity information */
    char* anonymousIdentity; /* Anonymous identity information */
    char* password;          /* EAP mode password */
    char* caCertAlias;       /* CA certificate alias */
    char* caPath;            /* CA certificate path */
    char* clientCertAlias;
    CArrUI8 certEntry;       /* CA certificate entry */
    char* certPassword;      /* Certificate password */
    char* altSubjectMatch;   /* Alternative topic matching */
    char* domainSuffixMatch; /* Domain suffix matching */
    char* realm;             /* The field of passport credentials */
    char* plmn;              /* PLMN */
    int32_t eapSubId;        /* Sub ID of SIM card */
    bool isNone;
};

struct CWifiWapiConfig {
    int32_t wapiPskType;
    char* wapiAsCert;
    char* wapiUserCert;
    bool isNone;
};

struct CIpInfo {
    uint32_t ipAddress;
    uint32_t gateway;
    uint32_t netmask;
    uint32_t primaryDns;
    uint32_t secondDns;
    uint32_t serverIp;
    uint32_t leaseDuration;
};

struct CIpv6Info {
    char* linkIpV6Address;
    char* globalIpV6Address;
    char* randomGlobalIpV6Address;
    char* uniqueIpv6Address;
    char* randomUniqueIpv6Address;
    char* gateway;
    char* netmask;
    char* primaryDns;
    char* secondDNS;
};

struct CWifiP2PConfig {
    char* deviceAddress;
    char* passphrase;
    char* groupName;
    int32_t netId;
    int32_t goBand;
    int32_t deviceAddressType;
};

struct CWifiP2PLinkedInfo {
    int32_t connectState;
    bool isGroupOwner;
    char* groupOwnerAddr;
};

struct CWifiP2pDevice {
    char* deviceName;
    char* deviceAddress;
    char* primaryDeviceType;
    int32_t deviceStatus;
    int32_t groupCapabilities;
    int32_t deviceAddressType;
};

struct WifiP2pDeviceArr {
    CWifiP2pDevice* head;
    int64_t size;
};

struct CWifiP2PGroupInfo {
    bool isP2pGo;
    CWifiP2pDevice ownerInfo;
    char* passphrase;
    char* interfaceName;
    char* groupName;
    int32_t networkId;
    int32_t frequency;
    CWifiP2pDevice* clientDevices;
    int64_t clientSize;
    char* goIpAddress;
};

struct CWifiLinkedInfo {
    char* ssid;
    char* bssid;
    int32_t rssi;
    int32_t band;
    int32_t linkSpeed;
    int32_t rxLinkSpeed;
    int32_t maxSupportedTxLinkSpeed;
    int32_t maxSupportedRxLinkSpeed;
    int32_t frequency;
    bool isHidden;
    bool isRestricted;
    int32_t macType;
    char* macAddress;
    uint32_t ipAddress;
    int32_t connState;
    int32_t channelWidth;
    int32_t wifiStandard;
    int32_t supportedWifiCategory;
    bool isHiLinkNetwork;
};

struct CWifiDeviceConfig {
    int32_t securityType;
    int32_t bssidType;
    bool isHiddenSsid;
    char* bssid;
    char* ssid;
    char* preSharedKey;
    CWifiEapConfig eapConfig;
    CWifiWapiConfig wapiConfig;
};

struct WifiDeviceConfigArr {
    CWifiDeviceConfig* head;
    int64_t size;
};
}

#endif // CJ_WIFI_FFI_STRUCTS_H