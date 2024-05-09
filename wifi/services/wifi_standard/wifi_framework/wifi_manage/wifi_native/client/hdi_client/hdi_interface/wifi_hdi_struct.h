/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HDI_STRUCT_H
#define OHOS_WIFI_HDI_STRUCT_H

#include <stdint.h>
#include "wifi_hdi_define.h"
#include "i_wifi_struct.h"
#include "wifi_error_no.h"

#ifdef __cplusplus
extern "C" {
#endif

struct HdiIeHdr {
    uint8_t elemId;
    uint8_t len;
    uint8_t oui[4];
    uint8_t version[2];
};

struct HdiElem {
    uint8_t id;
    uint8_t datalen;
    uint8_t data[];
};

struct HdiMdie {
    uint8_t mobilityDomain[HDI_MOBILITY_DOMAIN_ID_LEN];
    uint8_t ftCapab;
};

struct HdiFtie {
    uint8_t micControl[2];
    uint8_t mic[16];
    uint8_t anonce[HDI_NONCE_LEN];
    uint8_t snonce[HDI_NONCE_LEN];
};

struct HdiRsnIeHdr {
    uint8_t elemId;
    uint8_t len;
    uint8_t version[2];
};

struct HdiIesInfo {
    struct {
        const uint8_t *ie;
        uint8_t ieLen;
    } ies[HDI_MAX_IES_SUPPORTED];
    uint8_t nofIes;
};


struct HdiElems {
    const uint8_t *ssid;
    const uint8_t *suppRates;
    const uint8_t *dsParams;
    const uint8_t *challenge;
    const uint8_t *erpInfo;
    const uint8_t *extSuppRates;
    const uint8_t *hdiIe;
    const uint8_t *rsnIe;
    const uint8_t *wmm; /* WMM Information or Parameter Element */
    const uint8_t *wmmTspec;
    const uint8_t *wpsIe;
    const uint8_t *hdiChannels;
    const uint8_t *mdie;
    const uint8_t *ftie;
    const uint8_t *timeout;
    const uint8_t *htCapabilities;
    const uint8_t *htOperation;
    const uint8_t *meshCfg;
    const uint8_t *meshId;
    const uint8_t *peerMgmt;
    const uint8_t *vhtCapabilities;
    const uint8_t *vhtOperation;
    const uint8_t *vhtOpmodeNotif;
    const uint8_t *vendorHtCap;
    const uint8_t *vendorVht;
    const uint8_t *p2p;
    const uint8_t *wfd;
    const uint8_t *linkId;
    const uint8_t *interworking;
    const uint8_t *mapSet;
    const uint8_t *hs20;
    const uint8_t *extCapab;
    const uint8_t *maxIdlePeriod;
    const uint8_t *ssidList;
    const uint8_t *osen;
    const uint8_t *mbo;
    const uint8_t *ampe;
    const uint8_t *mic;
    const uint8_t *prefFreqList;
    const uint8_t *opClasses;
    const uint8_t *rrmEnabled;
    const uint8_t *cagNumber;
    const uint8_t *apCsn;
    const uint8_t *filsIndic;
    const uint8_t *dils;
    const uint8_t *assocDelayInfo;
    const uint8_t *filsReqParams;
    const uint8_t *filsKeyConfirm;
    const uint8_t *filsSession;
    const uint8_t *filsHlp;
    const uint8_t *addrAssign;
    const uint8_t *delivery;
    const uint8_t *wrappedData;
    const uint8_t *filsPk;
    const uint8_t *filsNonce;
    const uint8_t *oweDh;
    const uint8_t *powerCapab;
    const uint8_t *roamingConsSel;
    const uint8_t *passwordId;
    const uint8_t *oci;
    const uint8_t *multiAp;
    const uint8_t *heCapabilities;
    const uint8_t *heOperation;

    uint8_t ssidLen;
    uint8_t ratesLen;
    uint8_t challengeLen;
    uint8_t suppRatesLlen;
    uint8_t wpaIeLen;
    uint8_t rsnIeLen;
    uint8_t wmmLen; /* 7 = WMM Information; 24 = WMM Parameter */
    uint8_t wmmTspecLen;
    uint8_t hdiIeLen;
    uint8_t channelsLen;
    uint8_t mdieLen;
    uint8_t ftieLen;
    uint8_t meshConfigLen;
    uint8_t meshIdLen;
    uint8_t peerMgmtLen;
    uint8_t vendorHtCapLen;
    uint8_t vendorVhtLen;
    uint8_t p2pLen;
    uint8_t wfdLen;
    uint8_t interworkingLen;
    uint8_t qosMapSetLen;
    uint8_t hs20Len;
    uint8_t extCapabLen;
    uint8_t ssidListLen;
    uint8_t osenLen;
    uint8_t mboLen;
    uint8_t ampeLen;
    uint8_t micLen;
    uint8_t prefFreqListLen;
    uint8_t suppOpClassesLen;
    uint8_t rrmEnabledLen;
    uint8_t cagNumberLen;
    uint8_t filsIndicLen;
    uint8_t dilsLen;
    uint8_t filsReqParamsLen;
    uint8_t filsKeyConfirmLen;
    uint8_t filsHlpLen;
    uint8_t filsIpAddrAssignLen;
    uint8_t keyDeliveryLen;
    uint8_t filWrappedDataLen;
    uint8_t filsPkLen;
    uint8_t oweDhLen;
    uint8_t powerCapabLen;
    uint8_t roamingConsSelLen;
    uint8_t passwordIdLen;
    uint8_t ociLen;
    uint8_t multiApLen;
    uint8_t heCapabilitiesLen;
    uint8_t heOperationLen;

    struct HdiIesInfo hdiIes;
};

struct HdiIeData {
    int proto;
    int pairwiseCipher;
    int hasPairwise;
    int groupCipher;
    int hasGroup;
    int keyMgmt;
    int capabilities;
    size_t numPmkid;
    const uint8_t *pmkid;
    int mgmtGroupCipher;
};

/* HT Capabilities HdiElem */
struct HdiHtCapabilities {
    uint16_t htCapabilitiesInfo;
    uint8_t mpduParams; /* Maximum A-MPDU Length Exponent B0..B1
               * Minimum MPDU Start Spacing B2..B4
               * Reserved B5..B7 */
    uint8_t supportedMcsSet[16];
    uint16_t htExtendedCapabilities;
    uint32_t txbfCapabilityInfo;
    uint8_t aselCapabilities;
};

struct HdiHtOperation {
    uint8_t primaryChan;
    uint8_t htParam;
    uint16_t operationMode;
    uint16_t param;
    uint8_t basicMcsSet[16];
};

struct HdiVhtCapabilities {
    uint32_t capabilitiesInfo;
    struct {
        uint16_t rxMap;
        uint16_t rxHighest;
        uint16_t txMap;
        uint16_t txHighest;
    } vhtSupportedset;
};

struct HdiVhtOperation {
    uint8_t chwidth;
    uint8_t seg0Idx;
    uint8_t seg1Idx;
    uint16_t set;
};

struct HdiParseAttr {
    const uint8_t *version;
    const uint8_t *version2;
    const uint8_t *msgType;
    const uint8_t *enrolleeNonce;
    const uint8_t *registrarNonce;
    const uint8_t *uuidr;
    const uint8_t *uuide;
    const uint8_t *authFlags;
    const uint8_t *encrflags;
    const uint8_t *connFlags;
    const uint8_t *methods;
    const uint8_t *configMethods;
    const uint8_t *primaryDevType;
    const uint8_t *rfBands;
    const uint8_t *tate;
    const uint8_t *error;
    const uint8_t *passwordId;
    const uint8_t *version3;
    const uint8_t *state;
    const uint8_t *authenticator;
    const uint8_t *hash1;
    const uint8_t *hash2;
    const uint8_t *hash3;
    const uint8_t *hash4;
    const uint8_t *snonce1;
    const uint8_t *snonce2;
    const uint8_t *snonce3;
    const uint8_t *snonce4;
    const uint8_t *auth;
    const uint8_t *authType;
    const uint8_t *encrType;
    const uint8_t *idx;
    const uint8_t *keyIdx;
    const uint8_t *mac;
    const uint8_t *registrar;
    const uint8_t *requestType;
    const uint8_t *responseType;
    const uint8_t *setupLocked;
    const uint8_t *delayTime;
    const uint8_t *shareable;
    const uint8_t *enroll;
    const uint8_t *channel;
    const uint8_t *methods2;

    const uint8_t *manufacturer;
    const uint8_t *modelNname;
    const uint8_t *modelNumber;
    const uint8_t *serialNumber;
    const uint8_t *devName;
    const uint8_t *publicKey;
    const uint8_t *encrSettings;
    const uint8_t *ssid;
    const uint8_t *networkKey;
    const uint8_t *authorizedMacs;
    const uint8_t *typeList;
    const uint8_t *devPassword;
    uint16_t manufacturerLen;
    uint16_t modelNameLen;
    uint16_t modelNumberLen;
    uint16_t serialNumberLen;
    uint16_t devNameLen;
    uint16_t publicKeyLen;
    uint16_t encrSettingsLen;
    uint16_t ssidLen;
    uint16_t networkKeyLen;
    uint16_t authorizedMacsLen;
    uint16_t secDevTypeListLen;
    uint16_t oobDevPasswordLen;

    unsigned int numCred;
    unsigned int numReqDevType;
    unsigned int numVendorExt;

    uint16_t credLen[HDI_MAX_CRED_COUNT];
    uint16_t vendorExtLen[HDI_MAX__VENDOR_EXT];

    const uint8_t *cred[HDI_MAX_CRED_COUNT];
    const uint8_t *reqDevType[HDI_MAX_REQ_DEV_TYPE_COUNT];
    const uint8_t *vendorExt[HDI_MAX__VENDOR_EXT];
    uint8_t multiApExt;
};

struct WifiScanResultExt {
    uint32_t flags;
    uint8_t* bssid;
    uint32_t bssidLen;
    uint16_t caps;
    uint32_t freq;
    uint16_t beaconInt;
    int32_t qual;
    int32_t level;
    uint32_t age;
    uint64_t tsf;
    uint8_t* variable;
    uint32_t variableLen;
    uint8_t* ie;
    uint32_t ieLen;
    uint8_t* beaconIe;
    uint32_t beaconIeLen;
};

#ifdef __cplusplus
}
#endif
#endif