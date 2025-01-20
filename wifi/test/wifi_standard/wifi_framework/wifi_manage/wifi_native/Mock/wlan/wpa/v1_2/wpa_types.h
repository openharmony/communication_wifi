/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WPATYPES_H
#define WPATYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RETURN
#define HDI_CHECK_VALUE_RETURN(lv, compare, rv, ret) do { \
    if ((lv) compare (rv)) { \
        return ret; \
    } \
} while (false)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) do { \
    if ((lv) compare (rv)) { \
        ret = value; \
        goto table; \
    } \
} while (false)
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfSBuf;

struct HdiFeatureInfo {
    char* ifName;
    int32_t type;
};

struct HdiWifiStatus {
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t freq;
    char* ssid;
    int32_t ssidLen;
    char* keyMgmt;
    int32_t keyMgmtLen;
    uint8_t* address;
    uint32_t addressLen;
};

struct HdiWifiWpaNetworkInfo {
    int32_t id;
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* flags;
    uint32_t flagsLen;
};

struct HdiWifiWpsParam {
    int32_t anyFlag;
    int32_t multiAp;
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* pinCode;
    uint32_t pinCodeLen;
};

struct HdiWpaCmdStatus {
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t freq;
    uint8_t* ssid;
    uint32_t ssidLen;
    int32_t id;
    uint8_t* keyMgmt;
    uint32_t keyMgmtLen;
    uint8_t* address;
    uint32_t addressLen;
};

struct HdiWpaDisconnectParam {
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t reasonCode;
    int32_t locallyGenerated;
};

struct HdiWpaConnectParam {
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t networkId;
};

struct HdiWpaBssidChangedParam {
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* reason;
    uint32_t reasonLen;
};

struct HdiWpaStateChangedParam {
    int32_t status;
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t networkId;
    uint8_t* ssid;
    uint32_t ssidLen;
};

struct HdiWpaTempDisabledParam {
    int32_t networkId;
    uint8_t* ssid;
    uint32_t ssidLen;
    int32_t authFailures;
    int32_t duration;
    uint8_t* reason;
    uint32_t reasonLen;
};

struct HdiWpaAssociateRejectParam {
    uint8_t* bssid;
    uint32_t bssidLen;
    int32_t statusCode;
    int32_t timeOut;
};

struct HdiWpaRecvScanResultParam {
    uint32_t scanId;
} __attribute__ ((aligned(8)));

enum WifiTechnology {
    UNKNOWN_TECHNOLOGY = 0,
    LEGACY = 1,
    HT = 2,
    VHT = 3,
    HE = 4,
};

enum WifiChannelWidthInMhz {
    WIDTH_20 = 0,
    WIDTH_40 = 1,
    WIDTH_80 = 2,
    WIDTH_160 = 3,
    WIDTH_80P80 = 4,
    WIDTH_5 = 5,
    WIDTH_10 = 6,
    WIDTH_INVALID = -1,
};

enum LegacyMode {
    UNKNOWN_MODE = 0,
    A_MODE = 1,
    B_MODE = 2,
    G_MODE = 3,
};

struct ConnectionCapabilities {
    enum WifiTechnology technology;
    enum WifiChannelWidthInMhz channelBandwidth;
    int32_t maxNumberTxSpatialStreams;
    int32_t maxNumberRxSpatialStreams;
    enum LegacyMode legacyMode;
} __attribute__ ((aligned(8)));

struct HdiP2pNetworkInfo {
    int32_t id;
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* flags;
    uint32_t flagsLen;
};

struct HdiP2pNetworkList {
    int32_t infoNum;
    struct HdiP2pNetworkInfo* infos;
    uint32_t infosLen;
};

struct HdiP2pDeviceInfo {
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    uint8_t* p2pDeviceAddress;
    uint32_t p2pDeviceAddressLen;
    uint8_t* primaryDeviceType;
    uint32_t primaryDeviceTypeLen;
    uint8_t* deviceName;
    uint32_t deviceNameLen;
    int32_t configMethods;
    int32_t deviceCapabilities;
    int32_t groupCapabilities;
    uint8_t* wfdDeviceInfo;
    uint32_t wfdDeviceInfoLen;
    uint32_t wfdLength;
    uint8_t* operSsid;
    uint32_t operSsidLen;
};

struct HdiP2pServiceInfo {
    int32_t mode;
    int32_t version;
    uint8_t* name;
    uint32_t nameLen;
    uint8_t* query;
    uint32_t queryLen;
    uint8_t* resp;
    uint32_t respLen;
};

struct HdiP2pReqService {
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* msg;
    uint32_t msgLen;
};

struct HdiP2pServDiscReqInfo {
    int32_t freq;
    int32_t dialogToken;
    int32_t updateIndic;
    uint8_t* mac;
    uint32_t macLen;
    uint8_t* tlvs;
    uint32_t tlvsLen;
};

struct HdiHid2dConnectInfo {
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* bssid;
    uint32_t bssidLen;
    uint8_t* passphrase;
    uint32_t passphraseLen;
    int32_t frequency;
};

struct HdiP2pConnectInfo {
    int32_t persistent;
    int32_t mode;
    int32_t goIntent;
    int32_t provdisc;
    uint8_t* peerDevAddr;
    uint32_t peerDevAddrLen;
    uint8_t* pin;
    uint32_t pinLen;
};

struct HdiP2pDeviceInfoParam {
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    uint8_t* p2pDeviceAddress;
    uint32_t p2pDeviceAddressLen;
    uint8_t* primaryDeviceType;
    uint32_t primaryDeviceTypeLen;
    uint8_t* deviceName;
    uint32_t deviceNameLen;
    int32_t configMethods;
    int32_t deviceCapabilities;
    int32_t groupCapabilities;
    uint8_t* wfdDeviceInfo;
    uint32_t wfdDeviceInfoLen;
    uint32_t wfdLength;
    uint8_t* operSsid;
    uint32_t operSsidLen;
};

struct HdiP2pDeviceLostParam {
    uint8_t* p2pDeviceAddress;
    uint32_t p2pDeviceAddressLen;
    int32_t networkId;
};

struct HdiP2pGoNegotiationRequestParam {
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    int32_t passwordId;
};

struct HdiP2pGoNegotiationCompletedParam {
    int32_t status;
} __attribute__ ((aligned(8)));

struct HdiP2pInvitationReceivedParam {
    int32_t type;
    int32_t persistentNetworkId;
    int32_t operatingFrequency;
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    uint8_t* goDeviceAddress;
    uint32_t goDeviceAddressLen;
    uint8_t* bssid;
    uint32_t bssidLen;
};

struct HdiP2pInvitationResultParam {
    int32_t status;
    uint8_t* bssid;
    uint32_t bssidLen;
};

struct HdiP2pGroupStartedParam {
    int32_t isGo;
    int32_t isPersistent;
    int32_t frequency;
    uint8_t* groupIfName;
    uint32_t groupIfNameLen;
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* psk;
    uint32_t pskLen;
    uint8_t* passphrase;
    uint32_t passphraseLen;
    uint8_t* goDeviceAddress;
    uint32_t goDeviceAddressLen;
};

struct HdiP2pGroupRemovedParam {
    int32_t isGo;
    uint8_t* groupIfName;
    uint32_t groupIfNameLen;
};

struct HdiP2pProvisionDiscoveryCompletedParam {
    int32_t isRequest;
    int32_t provDiscStatusCode;
    int32_t configMethods;
    uint8_t* p2pDeviceAddress;
    uint32_t p2pDeviceAddressLen;
    uint8_t* generatedPin;
    uint32_t generatedPinLen;
};

struct HdiP2pServDiscReqInfoParam {
    int32_t freq;
    int32_t dialogToken;
    int32_t updateIndic;
    uint8_t* mac;
    uint32_t macLen;
    uint8_t* tlvs;
    uint32_t tlvsLen;
};

struct HdiP2pServDiscRespParam {
    int32_t updateIndicator;
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    uint8_t* tlvs;
    uint32_t tlvsLen;
};

struct HdiP2pStaConnectStateParam {
    int32_t state;
    uint8_t* srcAddress;
    uint32_t srcAddressLen;
    uint8_t* p2pDeviceAddress;
    uint32_t p2pDeviceAddressLen;
};

struct HdiP2pIfaceCreatedParam {
    int32_t isGo;
} __attribute__ ((aligned(8)));

struct HdiWpaAuthRejectParam {
    uint8_t* bssid;
    uint32_t bssidLen;
    uint16_t authType;
    uint16_t authTransaction;
    uint16_t statusCode;
};

struct WpaVendorInfo {
    int32_t type;
    int32_t freq;
    int32_t width;
    int32_t id;
    int32_t status;
    int32_t reason;
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* psk;
    uint32_t pskLen;
    uint8_t* devAddr;
    uint32_t devAddrLen;
    uint8_t* data;
    uint32_t dataLen;
};

struct HdiP2pGroupInfoStartedParam {
    int32_t isGo;
    int32_t isPersistent;
    int32_t frequency;
    uint8_t* groupIfName;
    uint32_t groupIfNameLen;
    uint8_t* ssid;
    uint32_t ssidLen;
    uint8_t* psk;
    uint32_t pskLen;
    uint8_t* passphrase;
    uint32_t passphraseLen;
    uint8_t* goDeviceAddress;
    uint32_t goDeviceAddressLen;
    uint8_t* goRandomDeviceAddress;
    uint32_t goRandomDeviceAddressLen;
};

bool HdiFeatureInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiFeatureInfo *dataBlock);

bool HdiFeatureInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiFeatureInfo *dataBlock);

void HdiFeatureInfoFree(struct HdiFeatureInfo *dataBlock, bool freeSelf);

bool HdiWifiStatusBlockMarshalling(struct HdfSBuf *data, const struct HdiWifiStatus *dataBlock);

bool HdiWifiStatusBlockUnmarshalling(struct HdfSBuf *data, struct HdiWifiStatus *dataBlock);

void HdiWifiStatusFree(struct HdiWifiStatus *dataBlock, bool freeSelf);

bool HdiWifiWpaNetworkInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiWifiWpaNetworkInfo *dataBlock);

bool HdiWifiWpaNetworkInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiWifiWpaNetworkInfo *dataBlock);

void HdiWifiWpaNetworkInfoFree(struct HdiWifiWpaNetworkInfo *dataBlock, bool freeSelf);

bool HdiWifiWpsParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWifiWpsParam *dataBlock);

bool HdiWifiWpsParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWifiWpsParam *dataBlock);

void HdiWifiWpsParamFree(struct HdiWifiWpsParam *dataBlock, bool freeSelf);

bool HdiWpaCmdStatusBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaCmdStatus *dataBlock);

bool HdiWpaCmdStatusBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaCmdStatus *dataBlock);

void HdiWpaCmdStatusFree(struct HdiWpaCmdStatus *dataBlock, bool freeSelf);

bool HdiWpaDisconnectParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaDisconnectParam *dataBlock);

bool HdiWpaDisconnectParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaDisconnectParam *dataBlock);

void HdiWpaDisconnectParamFree(struct HdiWpaDisconnectParam *dataBlock, bool freeSelf);

bool HdiWpaConnectParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaConnectParam *dataBlock);

bool HdiWpaConnectParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaConnectParam *dataBlock);

void HdiWpaConnectParamFree(struct HdiWpaConnectParam *dataBlock, bool freeSelf);

bool HdiWpaBssidChangedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaBssidChangedParam *dataBlock);

bool HdiWpaBssidChangedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaBssidChangedParam *dataBlock);

void HdiWpaBssidChangedParamFree(struct HdiWpaBssidChangedParam *dataBlock, bool freeSelf);

bool HdiWpaStateChangedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaStateChangedParam *dataBlock);

bool HdiWpaStateChangedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaStateChangedParam *dataBlock);

void HdiWpaStateChangedParamFree(struct HdiWpaStateChangedParam *dataBlock, bool freeSelf);

bool HdiWpaTempDisabledParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaTempDisabledParam *dataBlock);

bool HdiWpaTempDisabledParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaTempDisabledParam *dataBlock);

void HdiWpaTempDisabledParamFree(struct HdiWpaTempDisabledParam *dataBlock, bool freeSelf);

bool HdiWpaAssociateRejectParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaAssociateRejectParam *dataBlock);

bool HdiWpaAssociateRejectParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaAssociateRejectParam *dataBlock);

void HdiWpaAssociateRejectParamFree(struct HdiWpaAssociateRejectParam *dataBlock, bool freeSelf);

bool HdiWpaRecvScanResultParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaRecvScanResultParam *dataBlock);

bool HdiWpaRecvScanResultParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaRecvScanResultParam *dataBlock);

void HdiWpaRecvScanResultParamFree(struct HdiWpaRecvScanResultParam *dataBlock, bool freeSelf);

bool ConnectionCapabilitiesBlockMarshalling(struct HdfSBuf *data, const struct ConnectionCapabilities *dataBlock);

bool ConnectionCapabilitiesBlockUnmarshalling(struct HdfSBuf *data, struct ConnectionCapabilities *dataBlock);

void ConnectionCapabilitiesFree(struct ConnectionCapabilities *dataBlock, bool freeSelf);

bool HdiP2pNetworkInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pNetworkInfo *dataBlock);

bool HdiP2pNetworkInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pNetworkInfo *dataBlock);

void HdiP2pNetworkInfoFree(struct HdiP2pNetworkInfo *dataBlock, bool freeSelf);

bool HdiP2pNetworkListBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pNetworkList *dataBlock);

bool HdiP2pNetworkListBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pNetworkList *dataBlock);

void HdiP2pNetworkListFree(struct HdiP2pNetworkList *dataBlock, bool freeSelf);

bool HdiP2pDeviceInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pDeviceInfo *dataBlock);

bool HdiP2pDeviceInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pDeviceInfo *dataBlock);

void HdiP2pDeviceInfoFree(struct HdiP2pDeviceInfo *dataBlock, bool freeSelf);

bool HdiP2pServiceInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pServiceInfo *dataBlock);

bool HdiP2pServiceInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pServiceInfo *dataBlock);

void HdiP2pServiceInfoFree(struct HdiP2pServiceInfo *dataBlock, bool freeSelf);

bool HdiP2pReqServiceBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pReqService *dataBlock);

bool HdiP2pReqServiceBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pReqService *dataBlock);

void HdiP2pReqServiceFree(struct HdiP2pReqService *dataBlock, bool freeSelf);

bool HdiP2pServDiscReqInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pServDiscReqInfo *dataBlock);

bool HdiP2pServDiscReqInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pServDiscReqInfo *dataBlock);

void HdiP2pServDiscReqInfoFree(struct HdiP2pServDiscReqInfo *dataBlock, bool freeSelf);

bool HdiHid2dConnectInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiHid2dConnectInfo *dataBlock);

bool HdiHid2dConnectInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiHid2dConnectInfo *dataBlock);

void HdiHid2dConnectInfoFree(struct HdiHid2dConnectInfo *dataBlock, bool freeSelf);

bool HdiP2pConnectInfoBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pConnectInfo *dataBlock);

bool HdiP2pConnectInfoBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pConnectInfo *dataBlock);

void HdiP2pConnectInfoFree(struct HdiP2pConnectInfo *dataBlock, bool freeSelf);

bool HdiP2pDeviceInfoParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pDeviceInfoParam *dataBlock);

bool HdiP2pDeviceInfoParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pDeviceInfoParam *dataBlock);

void HdiP2pDeviceInfoParamFree(struct HdiP2pDeviceInfoParam *dataBlock, bool freeSelf);

bool HdiP2pDeviceLostParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pDeviceLostParam *dataBlock);

bool HdiP2pDeviceLostParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pDeviceLostParam *dataBlock);

void HdiP2pDeviceLostParamFree(struct HdiP2pDeviceLostParam *dataBlock, bool freeSelf);

bool HdiP2pGoNegotiationRequestParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pGoNegotiationRequestParam *dataBlock);

bool HdiP2pGoNegotiationRequestParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pGoNegotiationRequestParam *dataBlock);

void HdiP2pGoNegotiationRequestParamFree(struct HdiP2pGoNegotiationRequestParam *dataBlock, bool freeSelf);

bool HdiP2pGoNegotiationCompletedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pGoNegotiationCompletedParam *dataBlock);

bool HdiP2pGoNegotiationCompletedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pGoNegotiationCompletedParam *dataBlock);

void HdiP2pGoNegotiationCompletedParamFree(struct HdiP2pGoNegotiationCompletedParam *dataBlock, bool freeSelf);

bool HdiP2pInvitationReceivedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pInvitationReceivedParam *dataBlock);

bool HdiP2pInvitationReceivedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pInvitationReceivedParam *dataBlock);

void HdiP2pInvitationReceivedParamFree(struct HdiP2pInvitationReceivedParam *dataBlock, bool freeSelf);

bool HdiP2pInvitationResultParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pInvitationResultParam *dataBlock);

bool HdiP2pInvitationResultParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pInvitationResultParam *dataBlock);

void HdiP2pInvitationResultParamFree(struct HdiP2pInvitationResultParam *dataBlock, bool freeSelf);

bool HdiP2pGroupStartedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pGroupStartedParam *dataBlock);

bool HdiP2pGroupStartedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pGroupStartedParam *dataBlock);

void HdiP2pGroupStartedParamFree(struct HdiP2pGroupStartedParam *dataBlock, bool freeSelf);

bool HdiP2pGroupRemovedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pGroupRemovedParam *dataBlock);

bool HdiP2pGroupRemovedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pGroupRemovedParam *dataBlock);

void HdiP2pGroupRemovedParamFree(struct HdiP2pGroupRemovedParam *dataBlock, bool freeSelf);

bool HdiP2pProvisionDiscoveryCompletedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pProvisionDiscoveryCompletedParam *dataBlock);

bool HdiP2pProvisionDiscoveryCompletedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pProvisionDiscoveryCompletedParam *dataBlock);

void HdiP2pProvisionDiscoveryCompletedParamFree(struct HdiP2pProvisionDiscoveryCompletedParam *dataBlock, bool freeSelf);

bool HdiP2pServDiscReqInfoParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pServDiscReqInfoParam *dataBlock);

bool HdiP2pServDiscReqInfoParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pServDiscReqInfoParam *dataBlock);

void HdiP2pServDiscReqInfoParamFree(struct HdiP2pServDiscReqInfoParam *dataBlock, bool freeSelf);

bool HdiP2pServDiscRespParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pServDiscRespParam *dataBlock);

bool HdiP2pServDiscRespParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pServDiscRespParam *dataBlock);

void HdiP2pServDiscRespParamFree(struct HdiP2pServDiscRespParam *dataBlock, bool freeSelf);

bool HdiP2pStaConnectStateParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pStaConnectStateParam *dataBlock);

bool HdiP2pStaConnectStateParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pStaConnectStateParam *dataBlock);

void HdiP2pStaConnectStateParamFree(struct HdiP2pStaConnectStateParam *dataBlock, bool freeSelf);

bool HdiP2pIfaceCreatedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pIfaceCreatedParam *dataBlock);

bool HdiP2pIfaceCreatedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pIfaceCreatedParam *dataBlock);

void HdiP2pIfaceCreatedParamFree(struct HdiP2pIfaceCreatedParam *dataBlock, bool freeSelf);

bool HdiWpaAuthRejectParamBlockMarshalling(struct HdfSBuf *data, const struct HdiWpaAuthRejectParam *dataBlock);

bool HdiWpaAuthRejectParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiWpaAuthRejectParam *dataBlock);

void HdiWpaAuthRejectParamFree(struct HdiWpaAuthRejectParam *dataBlock, bool freeSelf);

bool WpaVendorInfoBlockMarshalling(struct HdfSBuf *data, const struct WpaVendorInfo *dataBlock);

bool WpaVendorInfoBlockUnmarshalling(struct HdfSBuf *data, struct WpaVendorInfo *dataBlock);

void WpaVendorInfoFree(struct WpaVendorInfo *dataBlock, bool freeSelf);

bool HdiP2pGroupInfoStartedParamBlockMarshalling(struct HdfSBuf *data, const struct HdiP2pGroupInfoStartedParam *dataBlock);

bool HdiP2pGroupInfoStartedParamBlockUnmarshalling(struct HdfSBuf *data, struct HdiP2pGroupInfoStartedParam *dataBlock);

void HdiP2pGroupInfoStartedParamFree(struct HdiP2pGroupInfoStartedParam *dataBlock, bool freeSelf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // WPATYPES_H