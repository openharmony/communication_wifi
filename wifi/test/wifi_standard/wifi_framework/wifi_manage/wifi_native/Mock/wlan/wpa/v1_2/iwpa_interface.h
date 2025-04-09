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

#ifndef OHOS_HDI_WLAN_WPA_V1_2_IWPAINTERFACE_H
#define OHOS_HDI_WLAN_WPA_V1_2_IWPAINTERFACE_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>
#include "wlan/wpa/v2_0/iwpa_callback.h"
#include "wlan/wpa/v2_0/wpa_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfRemoteService;

#define IWPAINTERFACE_INTERFACE_DESC "ohos.hdi.wlan.wpa.v2_0.IWpaInterface"

#define IWPA_INTERFACE_MAJOR_VERSION 1
#define IWPA_INTERFACE_MINOR_VERSION 2

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

enum {
    CMD_WPA_INTERFACE_GET_VERSION = 0,
    CMD_WPA_INTERFACE_START = 1,
    CMD_WPA_INTERFACE_STOP = 2,
    CMD_WPA_INTERFACE_ADD_WPA_IFACE = 3,
    CMD_WPA_INTERFACE_REMOVE_WPA_IFACE = 4,
    CMD_WPA_INTERFACE_SCAN = 5,
    CMD_WPA_INTERFACE_SCAN_RESULT = 6,
    CMD_WPA_INTERFACE_ADD_NETWORK = 7,
    CMD_WPA_INTERFACE_REMOVE_NETWORK = 8,
    CMD_WPA_INTERFACE_DISABLE_NETWORK = 9,
    CMD_WPA_INTERFACE_SET_NETWORK = 10,
    CMD_WPA_INTERFACE_LIST_NETWORKS = 11,
    CMD_WPA_INTERFACE_SELECT_NETWORK = 12,
    CMD_WPA_INTERFACE_ENABLE_NETWORK = 13,
    CMD_WPA_INTERFACE_RECONNECT = 14,
    CMD_WPA_INTERFACE_DISCONNECT = 15,
    CMD_WPA_INTERFACE_SAVE_CONFIG = 16,
    CMD_WPA_INTERFACE_SET_POWER_SAVE = 17,
    CMD_WPA_INTERFACE_AUTO_CONNECT = 18,
    CMD_WPA_INTERFACE_WIFI_STATUS = 19,
    CMD_WPA_INTERFACE_WPS_PBC_MODE = 20,
    CMD_WPA_INTERFACE_WPS_PIN_MODE = 21,
    CMD_WPA_INTERFACE_WPS_CANCEL = 22,
    CMD_WPA_INTERFACE_GET_COUNTRY_CODE = 23,
    CMD_WPA_INTERFACE_GET_NETWORK = 24,
    CMD_WPA_INTERFACE_BLOCKLIST_CLEAR = 25,
    CMD_WPA_INTERFACE_SET_SUSPEND_MODE = 26,
    CMD_WPA_INTERFACE_REGISTER_EVENT_CALLBACK = 27,
    CMD_WPA_INTERFACE_UNREGISTER_EVENT_CALLBACK = 28,
    CMD_WPA_INTERFACE_GET_CONNECTION_CAPABILITIES = 29,
    CMD_WPA_INTERFACE_GET_SCAN_SSID = 30,
    CMD_WPA_INTERFACE_GET_PSK_PASSPHRASE = 31,
    CMD_WPA_INTERFACE_GET_PSK = 32,
    CMD_WPA_INTERFACE_GET_WEP_KEY = 33,
    CMD_WPA_INTERFACE_GET_WEP_TX_KEY_IDX = 34,
    CMD_WPA_INTERFACE_GET_REQUIRE_PMF = 35,
    CMD_WPA_INTERFACE_SET_COUNTRY_CODE = 36,
    CMD_WPA_INTERFACE_P2P_SET_SSID_POSTFIX_NAME = 37,
    CMD_WPA_INTERFACE_P2P_SET_WPS_DEVICE_TYPE = 38,
    CMD_WPA_INTERFACE_P2P_SET_WPS_CONFIG_METHODS = 39,
    CMD_WPA_INTERFACE_P2P_SET_GROUP_MAX_IDLE = 40,
    CMD_WPA_INTERFACE_P2P_SET_WFD_ENABLE = 41,
    CMD_WPA_INTERFACE_P2P_SET_PERSISTENT_RECONNECT = 42,
    CMD_WPA_INTERFACE_P2P_SET_WPS_SECONDARY_DEVICE_TYPE = 43,
    CMD_WPA_INTERFACE_P2P_SETUP_WPS_PBC = 44,
    CMD_WPA_INTERFACE_P2P_SETUP_WPS_PIN = 45,
    CMD_WPA_INTERFACE_P2P_SET_POWER_SAVE = 46,
    CMD_WPA_INTERFACE_P2P_SET_DEVICE_NAME = 47,
    CMD_WPA_INTERFACE_P2P_SET_WFD_DEVICE_CONFIG = 48,
    CMD_WPA_INTERFACE_P2P_SET_RANDOM_MAC = 49,
    CMD_WPA_INTERFACE_P2P_START_FIND = 50,
    CMD_WPA_INTERFACE_P2P_SET_EXT_LISTEN = 51,
    CMD_WPA_INTERFACE_P2P_SET_LISTEN_CHANNEL = 52,
    CMD_WPA_INTERFACE_P2P_PROVISION_DISCOVERY = 53,
    CMD_WPA_INTERFACE_P2P_ADD_GROUP = 54,
    CMD_WPA_INTERFACE_P2P_ADD_SERVICE = 55,
    CMD_WPA_INTERFACE_P2P_REMOVE_SERVICE = 56,
    CMD_WPA_INTERFACE_P2P_STOP_FIND = 57,
    CMD_WPA_INTERFACE_P2P_FLUSH = 58,
    CMD_WPA_INTERFACE_P2P_FLUSH_SERVICE = 59,
    CMD_WPA_INTERFACE_P2P_REMOVE_NETWORK = 60,
    CMD_WPA_INTERFACE_P2P_SET_GROUP_CONFIG = 61,
    CMD_WPA_INTERFACE_P2P_INVITE = 62,
    CMD_WPA_INTERFACE_P2P_REINVOKE = 63,
    CMD_WPA_INTERFACE_P2P_GET_DEVICE_ADDRESS = 64,
    CMD_WPA_INTERFACE_P2P_REQ_SERVICE_DISCOVERY = 65,
    CMD_WPA_INTERFACE_P2P_CANCEL_SERVICE_DISCOVERY = 66,
    CMD_WPA_INTERFACE_P2P_RESP_SERVER_DISCOVERY = 67,
    CMD_WPA_INTERFACE_P2P_CONNECT = 68,
    CMD_WPA_INTERFACE_P2P_HID2D_CONNECT = 69,
    CMD_WPA_INTERFACE_P2P_SET_SERV_DISC_EXTERNAL = 70,
    CMD_WPA_INTERFACE_P2P_REMOVE_GROUP = 71,
    CMD_WPA_INTERFACE_P2P_CANCEL_CONNECT = 72,
    CMD_WPA_INTERFACE_P2P_GET_GROUP_CONFIG = 73,
    CMD_WPA_INTERFACE_P2P_ADD_NETWORK = 74,
    CMD_WPA_INTERFACE_P2P_GET_PEER = 75,
    CMD_WPA_INTERFACE_P2P_GET_GROUP_CAPABILITY = 76,
    CMD_WPA_INTERFACE_P2P_LIST_NETWORKS = 77,
    CMD_WPA_INTERFACE_P2P_SAVE_CONFIG = 78,
    CMD_WPA_INTERFACE_REASSOCIATE = 79,
    CMD_WPA_INTERFACE_STA_SHELL_CMD = 80,
    CMD_WPA_INTERFACE_VENDOR_PROCESS_CMD = 81,
    CMD_WPA_INTERFACE_DELIVER_P2P_DATA = 82,
    CMD_WPA_INTERFACE_REGISTER_WPA_EVENT_CALLBACK = 83,
    CMD_WPA_INTERFACE_UNREGISTER_WPA_EVENT_CALLBACK = 84,
    CMD_WPA_INTERFACE_GET_WPA_STA_DATA = 85,
};

struct IWpaInterface {
    int32_t (*Start)(struct IWpaInterface *self);

    int32_t (*Stop)(struct IWpaInterface *self);

    int32_t (*AddWpaIface)(struct IWpaInterface *self, const char* ifName, const char* confName);

    int32_t (*RemoveWpaIface)(struct IWpaInterface *self, const char* ifName);

    int32_t (*Scan)(struct IWpaInterface *self, const char* ifName);

    int32_t (*ScanResult)(struct IWpaInterface *self, const char* ifName, uint8_t* resultBuf, uint32_t* resultBufLen);

    int32_t (*AddNetwork)(struct IWpaInterface *self, const char* ifName, int32_t* networkId);

    int32_t (*RemoveNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*DisableNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*SetNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* name,
         const char* value);

    int32_t (*ListNetworks)(struct IWpaInterface *self, const char* ifName, struct HdiWifiWpaNetworkInfo* networkInfo,
         uint32_t* networkInfoLen);

    int32_t (*SelectNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*EnableNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*Reconnect)(struct IWpaInterface *self, const char* ifName);

    int32_t (*Disconnect)(struct IWpaInterface *self, const char* ifName);

    int32_t (*SaveConfig)(struct IWpaInterface *self, const char* ifName);

    int32_t (*SetPowerSave)(struct IWpaInterface *self, const char* ifName, int32_t enable);

    int32_t (*AutoConnect)(struct IWpaInterface *self, const char* ifName, int32_t enable);

    int32_t (*WifiStatus)(struct IWpaInterface *self, const char* ifName, struct HdiWpaCmdStatus* wifiStatus);

    int32_t (*WpsPbcMode)(struct IWpaInterface *self, const char* ifName, const struct HdiWifiWpsParam* wpsParam);

    int32_t (*WpsPinMode)(struct IWpaInterface *self, const char* ifName, const struct HdiWifiWpsParam* wpsParam,
         int32_t* pinCode);

    int32_t (*WpsCancel)(struct IWpaInterface *self, const char* ifName);

    int32_t (*GetCountryCode)(struct IWpaInterface *self, const char* ifName, char* countrycode,
         uint32_t countrycodeLen);

    int32_t (*GetNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* param,
         char* value, uint32_t valueLen);

    int32_t (*BlocklistClear)(struct IWpaInterface *self, const char* ifName);

    int32_t (*SetSuspendMode)(struct IWpaInterface *self, const char* ifName, int32_t mode);

    int32_t (*RegisterEventCallback)(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName);

    int32_t (*UnregisterEventCallback)(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName);

    int32_t (*GetConnectionCapabilities)(struct IWpaInterface *self, const char* ifName,
         struct ConnectionCapabilities* connectionCap);

    int32_t (*GetScanSsid)(struct IWpaInterface *self, const char* ifName, int32_t* enable);

    int32_t (*GetPskPassphrase)(struct IWpaInterface *self, const char* ifName, char* psk, uint32_t pskLen);

    int32_t (*GetPsk)(struct IWpaInterface *self, const char* ifName, uint8_t* psk, uint32_t* pskLen);

    int32_t (*GetWepKey)(struct IWpaInterface *self, const char* ifName, int32_t keyIdx, uint8_t* wepKey,
         uint32_t* wepKeyLen);

    int32_t (*GetWepTxKeyIdx)(struct IWpaInterface *self, const char* ifName, int32_t* keyIdx);

    int32_t (*GetRequirePmf)(struct IWpaInterface *self, const char* ifName, int32_t* enable);

    int32_t (*SetCountryCode)(struct IWpaInterface *self, const char* ifName, const char* countrycode);

    int32_t (*P2pSetSsidPostfixName)(struct IWpaInterface *self, const char* ifName, const char* name);

    int32_t (*P2pSetWpsDeviceType)(struct IWpaInterface *self, const char* ifName, const char* type);

    int32_t (*P2pSetWpsConfigMethods)(struct IWpaInterface *self, const char* ifName, const char* methods);

    int32_t (*P2pSetGroupMaxIdle)(struct IWpaInterface *self, const char* ifName, int32_t time);

    int32_t (*P2pSetWfdEnable)(struct IWpaInterface *self, const char* ifName, int32_t enable);

    int32_t (*P2pSetPersistentReconnect)(struct IWpaInterface *self, const char* ifName, int32_t status);

    int32_t (*P2pSetWpsSecondaryDeviceType)(struct IWpaInterface *self, const char* ifName, const char* type);

    int32_t (*P2pSetupWpsPbc)(struct IWpaInterface *self, const char* ifName, const char* address);

    int32_t (*P2pSetupWpsPin)(struct IWpaInterface *self, const char* ifName, const char* address, const char* pin,
         char* result, uint32_t resultLen);

    int32_t (*P2pSetPowerSave)(struct IWpaInterface *self, const char* ifName, int32_t enable);

    int32_t (*P2pSetDeviceName)(struct IWpaInterface *self, const char* ifName, const char* name);

    int32_t (*P2pSetWfdDeviceConfig)(struct IWpaInterface *self, const char* ifName, const char* config);

    int32_t (*P2pSetRandomMac)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*P2pStartFind)(struct IWpaInterface *self, const char* ifName, int32_t timeout);

    int32_t (*P2pSetExtListen)(struct IWpaInterface *self, const char* ifName, int32_t enable, int32_t period,
         int32_t interval);

    int32_t (*P2pSetListenChannel)(struct IWpaInterface *self, const char* ifName, int32_t channel, int32_t regClass);

    int32_t (*P2pProvisionDiscovery)(struct IWpaInterface *self, const char* ifName, const char* peerBssid,
         int32_t mode);

    int32_t (*P2pAddGroup)(struct IWpaInterface *self, const char* ifName, int32_t isPersistent, int32_t networkId,
         int32_t freq);

    int32_t (*P2pAddService)(struct IWpaInterface *self, const char* ifName, const struct HdiP2pServiceInfo* info);

    int32_t (*P2pRemoveService)(struct IWpaInterface *self, const char* ifName, const struct HdiP2pServiceInfo* info);

    int32_t (*P2pStopFind)(struct IWpaInterface *self, const char* ifName);

    int32_t (*P2pFlush)(struct IWpaInterface *self, const char* ifName);

    int32_t (*P2pFlushService)(struct IWpaInterface *self, const char* ifName);

    int32_t (*P2pRemoveNetwork)(struct IWpaInterface *self, const char* ifName, int32_t networkId);

    int32_t (*P2pSetGroupConfig)(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* name,
         const char* value);

    int32_t (*P2pInvite)(struct IWpaInterface *self, const char* ifName, const char* peerBssid, const char* goBssid);

    int32_t (*P2pReinvoke)(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* bssid);

    int32_t (*P2pGetDeviceAddress)(struct IWpaInterface *self, const char* ifName, char* deviceAddress,
         uint32_t deviceAddressLen);

    int32_t (*P2pReqServiceDiscovery)(struct IWpaInterface *self, const char* ifName,
         const struct HdiP2pReqService* reqService, char* replyDisc, uint32_t replyDiscLen);

    int32_t (*P2pCancelServiceDiscovery)(struct IWpaInterface *self, const char* ifName, const char* id);

    int32_t (*P2pRespServerDiscovery)(struct IWpaInterface *self, const char* ifName,
         const struct HdiP2pServDiscReqInfo* info);

    int32_t (*P2pConnect)(struct IWpaInterface *self, const char* ifName, const struct HdiP2pConnectInfo* info,
         char* replyPin, uint32_t replyPinLen);

    int32_t (*P2pHid2dConnect)(struct IWpaInterface *self, const char* ifName, const struct HdiHid2dConnectInfo* info);

    int32_t (*P2pSetServDiscExternal)(struct IWpaInterface *self, const char* ifName, int32_t mode);

    int32_t (*P2pRemoveGroup)(struct IWpaInterface *self, const char* ifName, const char* groupName);

    int32_t (*P2pCancelConnect)(struct IWpaInterface *self, const char* ifName);

    int32_t (*P2pGetGroupConfig)(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* param,
         char* value, uint32_t valueLen);

    int32_t (*P2pAddNetwork)(struct IWpaInterface *self, const char* ifName, int32_t* networkId);

    int32_t (*P2pGetPeer)(struct IWpaInterface *self, const char* ifName, const char* bssid,
         struct HdiP2pDeviceInfo* info);

    int32_t (*P2pGetGroupCapability)(struct IWpaInterface *self, const char* ifName, const char* bssid, int32_t* cap);

    int32_t (*P2pListNetworks)(struct IWpaInterface *self, const char* ifName, struct HdiP2pNetworkList* infoList);

    int32_t (*P2pSaveConfig)(struct IWpaInterface *self, const char* ifName);

    int32_t (*Reassociate)(struct IWpaInterface *self, const char* ifName);

    int32_t (*StaShellCmd)(struct IWpaInterface *self, const char* ifName, const char* cmd);

    int32_t (*VendorProcessCmd)(struct IWpaInterface *self, const char* ifname, const char* cmd);

    int32_t (*DeliverP2pData)(struct IWpaInterface *self, const char* ifName, int32_t cmdType, int32_t dataType,
         const char* carryData);

    int32_t (*RegisterWpaEventCallback)(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName);

    int32_t (*UnregisterWpaEventCallback)(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName);

    int32_t (*GetWpaStaData)(struct IWpaInterface *self, const char* ifName, const char* staParam, char* staData,
        uint32_t staDataLen);

    int32_t (*GetVersion)(struct IWpaInterface *self, uint32_t* majorVer, uint32_t* minorVer);

    struct HdfRemoteService* (*AsObject)(struct IWpaInterface *self);
};

// external method used to create client object, it support ipc and passthrought mode
struct IWpaInterface *IWpaInterfaceGet(bool isStub);
struct IWpaInterface *IWpaInterfaceGetInstance(const char *serviceName, bool isStub);

// external method used to create release object, it support ipc and passthrought mode
void IWpaInterfaceRelease(struct IWpaInterface *instance, bool isStub);
void IWpaInterfaceReleaseInstance(const char *serviceName, struct IWpaInterface *instance, bool isStub);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_WLAN_WPA_V1_2_IWPAINTERFACE_H