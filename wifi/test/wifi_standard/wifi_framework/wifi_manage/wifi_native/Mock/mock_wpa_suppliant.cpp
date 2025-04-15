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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "securec.h"
#include "v1_0/ihostapd_interface.h"
#include "v1_0/ihostapd_callback.h"
#include "v2_0/iwpa_interface.h"
#include "v2_0/iwpa_callback.h"
#include "v2_0/wpa_types.h"

static const int ETH_ADDR_LEN = 6;
#define WIFI_P2P_DEVICE_TYPE_LENGTH 64
#define WIFI_P2P_DEVICE_NAME_LENGTH 128
#define WIFI_P2P_WFD_DEVICE_INFO_LENGTH 128

struct HdfRemoteService;
int32_t StartAp(struct IHostapdInterface *self)
{
    return 0;
}

int32_t StartApWithCmd(struct IHostapdInterface *self, const char* ifName, int32_t id)
{
    return 0;
}

int32_t StopAp(struct IHostapdInterface *self)
{
    return 0;
}

int32_t EnableAp(struct IHostapdInterface *self, const char* ifName, int32_t id)
{
    return 0;
}

int32_t DisableAp(struct IHostapdInterface *self, const char* ifName, int32_t id)
{
    return 0;
}

int32_t SetApPasswd(struct IHostapdInterface *self, const char* ifName, const char* pass, int32_t id)
{
    return 0;
}

int32_t SetApName(struct IHostapdInterface *self, const char* ifName, const char* name, int32_t id)
{
    return 0;
}

int32_t SetApWpaValue(struct IHostapdInterface *self, const char* ifName, int32_t securityType, int32_t id)
{
    return 0;
}

int32_t SetApBand(struct IHostapdInterface *self, const char* ifName, int32_t band, int32_t id)
{
    return 0;
}

int32_t SetAp80211n(struct IHostapdInterface *self, const char* ifName, int32_t value, int32_t id)
{
    return 0;
}

int32_t SetApWmm(struct IHostapdInterface *self, const char* ifName, int32_t value, int32_t id)
{
    return 0;
}

int32_t SetApChannel(struct IHostapdInterface *self, const char* ifName, int32_t channel, int32_t id)
{
    return 0;
}

int32_t SetApMaxConn(struct IHostapdInterface *self, const char* ifName, int32_t maxConn, int32_t id)
{
    return 0;
}

int32_t ReloadApConfigInfo(struct IHostapdInterface *self, const char* ifName, int32_t id)
{
    return 0;
}

int32_t SetMacFilter(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id)
{
    return 0;
}

int32_t DelMacFilter(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id)
{
    return 0;
}

int32_t GetStaInfos(struct IHostapdInterface *self, const char* ifName, char* buf, uint32_t bufLen, int32_t size,
    int32_t id)
{
    return 0;
}

int32_t DisassociateSta(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id)
{
    return 0;
}

int32_t RegisterEventCallback(struct IHostapdInterface *self, struct IHostapdCallback* cbFunc, const char* ifName)
{
    return 0;
}

int32_t UnregisterEventCallback(struct IHostapdInterface *self, struct IHostapdCallback* cbFunc, const char* ifName)
{
    return 0;
}

int32_t HostApdShellCmd(struct IHostapdInterface *self, const char* ifName, const char* cmd)
{
    return 0;
}

int32_t GetVersion(struct IHostapdInterface *self, uint32_t* majorVer, uint32_t* minorVer)
{
    return 0;
}

struct HdfRemoteService* AsObject(struct IHostapdInterface *self)
{
    return nullptr;
}

int32_t Start(struct IWpaInterface *self)
{
    return 0;
}

int32_t Stop(struct IWpaInterface *self)
{
    return 0;
}

int32_t AddWpaIface(struct IWpaInterface *self, const char* ifName, const char* confName)
{
    return 0;
}

int32_t RemoveWpaIface(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t Scan(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t ScanResult(struct IWpaInterface *self, const char* ifName, uint8_t* resultBuf, uint32_t* resultBufLen)
{
    return 0;
}

int32_t AddNetwork(struct IWpaInterface *self, const char* ifName, int32_t* networkId)
{
    return 0;
}

int32_t RemoveNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t DisableNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t SetNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* name,
    const char* value)
{
    return 0;
}

int32_t ListNetworks(struct IWpaInterface *self, const char* ifName, struct HdiWifiWpaNetworkInfo* networkInfo,
    uint32_t* networkInfoLen)
{
    return 0;
}

int32_t SelectNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t EnableNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t Reconnect(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t Disconnect(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t SaveConfig(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t SetPowerSave(struct IWpaInterface *self, const char* ifName, int32_t enable)
{
    return 0;
}

int32_t AutoConnect(struct IWpaInterface *self, const char* ifName, int32_t enable)
{
    return 0;
}

int32_t WifiStatus(struct IWpaInterface *self, const char* ifName, struct HdiWpaCmdStatus* wifiStatus)
{
    return 0;
}

int32_t WpsPbcMode(struct IWpaInterface *self, const char* ifName, const struct HdiWifiWpsParam* wpsParam)
{
    return 0;
}

int32_t WpsPinMode(struct IWpaInterface *self, const char* ifName, const struct HdiWifiWpsParam* wpsParam,
    int32_t* pinCode)
{
    return 0;
}

int32_t WpsCancel(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t GetCountryCode(struct IWpaInterface *self, const char* ifName, char* countrycode,
    uint32_t countrycodeLen)
{
    return 0;
}

int32_t GetNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* param,
    char* value, uint32_t valueLen)
{
    return 0;
}

int32_t BlocklistClear(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t SetSuspendMode(struct IWpaInterface *self, const char* ifName, int32_t mode)
{
    return 0;
}

int32_t RegisterEventCallback(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName)
{
    return 0;
}

int32_t UnregisterEventCallback(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName)
{
    return 0;
}

int32_t GetConnectionCapabilities(struct IWpaInterface *self, const char* ifName,
    struct ConnectionCapabilities* connectionCap)
{
    return 0;
}

int32_t GetScanSsid(struct IWpaInterface *self, const char* ifName, int32_t* enable)
{
    return 0;
}

int32_t GetPskPassphrase(struct IWpaInterface *self, const char* ifName, char* psk, uint32_t pskLen)
{
    return 0;
}

int32_t GetPsk(struct IWpaInterface *self, const char* ifName, uint8_t* psk, uint32_t* pskLen)
{
    return 0;
}

int32_t  GetWepKey(struct IWpaInterface *self, const char* ifName, int32_t keyIdx, uint8_t* wepKey,
    uint32_t* wepKeyLen)
{
    return 0;
}

int32_t GetWepTxKeyIdx(struct IWpaInterface *self, const char* ifName, int32_t* keyIdx)
{
    return 0;
}

int32_t GetRequirePmf(struct IWpaInterface *self, const char* ifName, int32_t* enable)
{
    return 0;
}

int32_t SetCountryCode(struct IWpaInterface *self, const char* ifName, const char* countrycode)
{
    return 0;
}

int32_t P2pSetSsidPostfixName(struct IWpaInterface *self, const char* ifName, const char* name)
{
    return 0;
}

int32_t P2pSetWpsDeviceType(struct IWpaInterface *self, const char* ifName, const char* type)
{
    return 0;
}

int32_t P2pSetWpsConfigMethods(struct IWpaInterface *self, const char* ifName, const char* methods)
{
    return 0;
}

int32_t P2pSetGroupMaxIdle(struct IWpaInterface *self, const char* ifName, int32_t time)
{
    return 0;
}

int32_t P2pSetWfdEnable(struct IWpaInterface *self, const char* ifName, int32_t enable)
{
    return 0;
}

int32_t P2pSetPersistentReconnect(struct IWpaInterface *self, const char* ifName, int32_t status)
{
    return 0;
}

int32_t P2pSetWpsSecondaryDeviceType(struct IWpaInterface *self, const char* ifName, const char* type)
{
    return 0;
}

int32_t P2pSetupWpsPbc(struct IWpaInterface *self, const char* ifName, const char* address)
{
    return 0;
}

int32_t P2pSetupWpsPin(struct IWpaInterface *self, const char* ifName, const char* address, const char* pin,
    char* result, uint32_t resultLen)
{
    return 0;
}

int32_t P2pSetPowerSave(struct IWpaInterface *self, const char* ifName, int32_t enable)
{
    return 0;
}

int32_t P2pSetDeviceName(struct IWpaInterface *self, const char* ifName, const char* name)
{
    return 0;
}

int32_t P2pSetWfdDeviceConfig(struct IWpaInterface *self, const char* ifName, const char* config)
{
    return 0;
}

int32_t P2pSetRandomMac(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t P2pStartFind(struct IWpaInterface *self, const char* ifName, int32_t timeout)
{
    return 0;
}

int32_t P2pSetExtListen(struct IWpaInterface *self, const char* ifName, int32_t enable, int32_t period,
    int32_t interval)
{
    return 0;
}

int32_t P2pSetListenChannel(struct IWpaInterface *self, const char* ifName, int32_t channel, int32_t regClass)
{
    return 0;
}

int32_t P2pProvisionDiscovery(struct IWpaInterface *self, const char* ifName, const char* peerBssid,
    int32_t mode)
{
    return 0;
}

int32_t P2pAddGroup(struct IWpaInterface *self, const char* ifName, int32_t isPersistent, int32_t networkId,
    int32_t freq)
{
    return 0;
}

int32_t P2pAddService(struct IWpaInterface *self, const char* ifName, const struct HdiP2pServiceInfo* info)
{
    return 0;
}

int32_t P2pRemoveService(struct IWpaInterface *self, const char* ifName, const struct HdiP2pServiceInfo* info)
{
    return 0;
}

int32_t P2pStopFind(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t P2pFlush(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t P2pFlushService(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t P2pRemoveNetwork(struct IWpaInterface *self, const char* ifName, int32_t networkId)
{
    return 0;
}

int32_t P2pSetGroupConfig(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* name,
    const char* value)
{
    return 0;
}

int32_t P2pInvite(struct IWpaInterface *self, const char* ifName, const char* peerBssid, const char* goBssid)
{
    return 0;
}

int32_t P2pReinvoke(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* bssid)
{
    return 0;
}

int32_t P2pGetDeviceAddress(struct IWpaInterface *self, const char* ifName, char* deviceAddress,
    uint32_t deviceAddressLen)
{
    return 0;
}

int32_t P2pReqServiceDiscovery(struct IWpaInterface *self, const char* ifName,
    const struct HdiP2pReqService* reqService, char* replyDisc, uint32_t replyDiscLen)
{
    return 0;
}

int32_t P2pCancelServiceDiscovery(struct IWpaInterface *self, const char* ifName, const char* id)
{
    return 0;
}

int32_t P2pRespServerDiscovery(struct IWpaInterface *self, const char* ifName,
    const struct HdiP2pServDiscReqInfo* info)
{
    return 0;
}

int32_t P2pConnect(struct IWpaInterface *self, const char* ifName, const struct HdiP2pConnectInfo* info,
    char* replyPin, uint32_t replyPinLen)
{
    return 0;
}

int32_t P2pHid2dConnect(struct IWpaInterface *self, const char* ifName, const struct HdiHid2dConnectInfo* info)
{
    return 0;
}

int32_t P2pSetServDiscExternal(struct IWpaInterface *self, const char* ifName, int32_t mode)
{
    return 0;
}

int32_t P2pRemoveGroup(struct IWpaInterface *self, const char* ifName, const char* groupName)
{
    return 0;
}

int32_t P2pCancelConnect(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t P2pGetGroupConfig(struct IWpaInterface *self, const char* ifName, int32_t networkId, const char* param,
    char* value, uint32_t valueLen)
{
    return 0;
}

int32_t P2pAddNetwork(struct IWpaInterface *self, const char* ifName, int32_t* networkId)
{
    return 0;
}

int32_t P2pGetPeer(struct IWpaInterface *self, const char* ifName, const char* bssid,
    struct HdiP2pDeviceInfo* info)
{
    if (ifName == nullptr || info == nullptr || bssid == nullptr) {
        return -1;
    }
    
    info->srcAddress = (uint8_t *)malloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->srcAddress == nullptr) {
        return HDF_FAILURE;
    }
    info->p2pDeviceAddress = (uint8_t *)malloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->p2pDeviceAddress == nullptr) {
        return HDF_FAILURE;
    }
    info->primaryDeviceType = (uint8_t *)malloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_TYPE_LENGTH);
    if (info->primaryDeviceType == nullptr) {
        return HDF_FAILURE;
    }
    info->deviceName = (uint8_t *)malloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->deviceName == nullptr) {
        return HDF_FAILURE;
    }
    info->wfdDeviceInfo = (uint8_t *)malloc(sizeof(uint8_t) * WIFI_P2P_WFD_DEVICE_INFO_LENGTH);
    if (info->wfdDeviceInfo == nullptr) {
        return HDF_FAILURE;
    }
    info->operSsid = (uint8_t *)malloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->operSsid == nullptr) {
        return HDF_FAILURE;
    }
    memcpy_s(info->p2pDeviceAddress, sizeof(info->p2pDeviceAddress), "12:33", strlen("12:33"));
    memcpy_s(info->deviceName, sizeof(info->deviceName), "11", strlen("11"));
    memcpy_s(info->primaryDeviceType, sizeof(info->deviceName), "1", strlen("1"));
    info->configMethods = 1;
    info->deviceCapabilities = 1;
    info->groupCapabilities = 1;
    memcpy_s(info->operSsid, sizeof(info->operSsid), "123", strlen("123"));
    return 0;
}

int32_t P2pGetGroupCapability(struct IWpaInterface *self, const char* ifName, const char* bssid, int32_t* cap)
{
    return 0;
}

int32_t P2pListNetworks(struct IWpaInterface *self, const char* ifName, struct HdiP2pNetworkList* infoList)
{
    return 0;
}

int32_t P2pSaveConfig(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t Reassociate(struct IWpaInterface *self, const char* ifName)
{
    return 0;
}

int32_t StaShellCmd(struct IWpaInterface *self, const char* ifName, const char* cmd)
{
    return 0;
}

int32_t  GetVersion(struct IWpaInterface *self, uint32_t* majorVer, uint32_t* minorVer)
{
    return 0;
}

int32_t DeliverP2pData(struct IWpaInterface *self, const char* ifName, int cmdType,
    int dataType, const char* carryData)
{
    return 0;
}

int32_t RegisterWpaEventCallback(struct IWpaInterface *self, struct IWpaCallback* cbFunc,  const char* ifName)
{
    return 0;
}
 
int32_t UnregisterWpaEventCallback(struct IWpaInterface *self, struct IWpaCallback* cbFunc, const char* ifName)
{
    return 0;
}

int32_t GetWpaStaData(struct IWpaInterface *self, const char* ifName, const char* staParam,
    char* staData, uint32_t staDataLen)
{
    return 0;
}

struct HdfRemoteService*  AsWapObject(struct IWpaInterface *self)
{
    return nullptr;
}

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// external method used to create client object, it support ipc and passthrought mode
struct IHostapdInterface *IHostapdInterfaceGet(bool isStub)
{
    static IHostapdInterface g_IHostapdInterface;
    g_IHostapdInterface.StartAp = StartAp;
    g_IHostapdInterface.StartApWithCmd = StartApWithCmd;
    g_IHostapdInterface.StopAp = StopAp;
    g_IHostapdInterface.EnableAp = EnableAp;
    g_IHostapdInterface.DisableAp = DisableAp;
    g_IHostapdInterface.SetApPasswd = SetApPasswd;
    g_IHostapdInterface.SetApName = SetApName;
    g_IHostapdInterface.SetApWpaValue = SetApWpaValue;
    g_IHostapdInterface.SetApBand = SetApBand;
    g_IHostapdInterface.SetAp80211n = SetAp80211n;
    g_IHostapdInterface.SetApWmm = SetApWmm;
    g_IHostapdInterface.SetApChannel = SetApChannel;
    g_IHostapdInterface.SetApMaxConn = SetApMaxConn;
    g_IHostapdInterface.ReloadApConfigInfo = ReloadApConfigInfo;
    g_IHostapdInterface.SetMacFilter = SetMacFilter;
    g_IHostapdInterface.DelMacFilter = DelMacFilter;
    g_IHostapdInterface.GetStaInfos = GetStaInfos;
    g_IHostapdInterface.DisassociateSta = DisassociateSta;
    g_IHostapdInterface.RegisterEventCallback = RegisterEventCallback;
    g_IHostapdInterface.UnregisterEventCallback = UnregisterEventCallback;
    g_IHostapdInterface.HostApdShellCmd = HostApdShellCmd;
    g_IHostapdInterface.GetVersion = GetVersion;
    g_IHostapdInterface.AsObject = AsObject;
    return &g_IHostapdInterface;
}

struct IHostapdInterface *IHostapdInterfaceGetInstance(const char *serviceName, bool isStub)
{
    return IHostapdInterfaceGet(false);
}

// external method used to create release object, it support ipc and passthrought mode
void IHostapdInterfaceRelease(struct IHostapdInterface *instance, bool isStub)
{
}

void IHostapdInterfaceReleaseInstance(const char *serviceName, struct IHostapdInterface *instance, bool isStub)
{
}

struct IWpaInterface *IWpaInterfaceGet(bool isStub)
{
    static IWpaInterface g_IWpaInterface;
    g_IWpaInterface.Start = Start;
    g_IWpaInterface.Stop = Stop;
    g_IWpaInterface.AddWpaIface = AddWpaIface;
    g_IWpaInterface.RemoveWpaIface = RemoveWpaIface;
    g_IWpaInterface.Scan= Scan;
    g_IWpaInterface.ScanResult = ScanResult;
    g_IWpaInterface.AddNetwork = AddNetwork;
    g_IWpaInterface.RemoveNetwork = RemoveNetwork;
    g_IWpaInterface.DisableNetwork = DisableNetwork;
    g_IWpaInterface.SetNetwork = SetNetwork;
    g_IWpaInterface.ListNetworks = ListNetworks;
    g_IWpaInterface.SelectNetwork = SelectNetwork;
    g_IWpaInterface.EnableNetwork = EnableNetwork;
    g_IWpaInterface.Reconnect = Reconnect;
    g_IWpaInterface.Disconnect = Disconnect;
    g_IWpaInterface.SaveConfig = SaveConfig;
    g_IWpaInterface.SetPowerSave = SetPowerSave;
    g_IWpaInterface.AutoConnect = AutoConnect;
    g_IWpaInterface.WifiStatus = WifiStatus;
    g_IWpaInterface.WpsPbcMode = WpsPbcMode;
    g_IWpaInterface.WpsPinMode = WpsPinMode;
    g_IWpaInterface.WpsCancel = WpsCancel;
    g_IWpaInterface.GetCountryCode = GetCountryCode;
    g_IWpaInterface.GetNetwork = GetNetwork;
    g_IWpaInterface.BlocklistClear = BlocklistClear;
    g_IWpaInterface.SetSuspendMode = SetSuspendMode;
    g_IWpaInterface.RegisterEventCallback = RegisterEventCallback;
    g_IWpaInterface.UnregisterEventCallback=UnregisterEventCallback;
    g_IWpaInterface.GetConnectionCapabilities = GetConnectionCapabilities;
    g_IWpaInterface.GetScanSsid = GetScanSsid;
    g_IWpaInterface.GetPskPassphrase = GetPskPassphrase;
    g_IWpaInterface.GetPsk = GetPsk;
    g_IWpaInterface.GetWepKey = GetWepKey;
    g_IWpaInterface.GetWepTxKeyIdx = GetWepTxKeyIdx;
    g_IWpaInterface.GetRequirePmf = GetRequirePmf;
    g_IWpaInterface.SetCountryCode = SetCountryCode;
    g_IWpaInterface.P2pSetSsidPostfixName = P2pSetSsidPostfixName;
    g_IWpaInterface.P2pSetWpsDeviceType = P2pSetWpsDeviceType;
    g_IWpaInterface.P2pSetWpsConfigMethods = P2pSetWpsConfigMethods;
    g_IWpaInterface.P2pSetGroupMaxIdle = P2pSetGroupMaxIdle;
    g_IWpaInterface.P2pSetWfdEnable = P2pSetWfdEnable;
    g_IWpaInterface.P2pSetPersistentReconnect = P2pSetPersistentReconnect;
    g_IWpaInterface.P2pSetWpsSecondaryDeviceType = P2pSetWpsSecondaryDeviceType;
    g_IWpaInterface.P2pSetupWpsPbc = P2pSetupWpsPbc;
    g_IWpaInterface.P2pSetupWpsPin = P2pSetupWpsPin;
    g_IWpaInterface.P2pSetPowerSave = P2pSetPowerSave;
    g_IWpaInterface.P2pSetDeviceName = P2pSetDeviceName;
    g_IWpaInterface.P2pSetWfdDeviceConfig = P2pSetWfdDeviceConfig;
    g_IWpaInterface.P2pSetRandomMac = P2pSetRandomMac;
    g_IWpaInterface.P2pStartFind = P2pStartFind;
    g_IWpaInterface.P2pSetExtListen = P2pSetExtListen;
    g_IWpaInterface.P2pSetListenChannel = P2pSetListenChannel;
    g_IWpaInterface.P2pProvisionDiscovery = P2pProvisionDiscovery;
    g_IWpaInterface.P2pAddGroup = P2pAddGroup;
    g_IWpaInterface.P2pAddService = P2pAddService;
    g_IWpaInterface.P2pRemoveService = P2pRemoveService;
    g_IWpaInterface.P2pStopFind = P2pStopFind;
    g_IWpaInterface.P2pFlush = P2pFlush;
    g_IWpaInterface.P2pFlushService = P2pFlushService;
    g_IWpaInterface.P2pRemoveNetwork = P2pRemoveNetwork;
    g_IWpaInterface.P2pSetGroupConfig = P2pSetGroupConfig;
    g_IWpaInterface.P2pInvite = P2pInvite;
    g_IWpaInterface.P2pReinvoke = P2pReinvoke;
    g_IWpaInterface.P2pGetDeviceAddress = P2pGetDeviceAddress;
    g_IWpaInterface.P2pReqServiceDiscovery = P2pReqServiceDiscovery;
    g_IWpaInterface.P2pCancelServiceDiscovery = P2pCancelServiceDiscovery;
    g_IWpaInterface.P2pRespServerDiscovery = P2pRespServerDiscovery;
    g_IWpaInterface.P2pConnect = P2pConnect;
    g_IWpaInterface.P2pHid2dConnect = P2pHid2dConnect;
    g_IWpaInterface.P2pSetServDiscExternal = P2pSetServDiscExternal;
    g_IWpaInterface.P2pRemoveGroup = P2pRemoveGroup;
    g_IWpaInterface.P2pCancelConnect = P2pCancelConnect;
    g_IWpaInterface.P2pGetGroupConfig = P2pGetGroupConfig;
    g_IWpaInterface.P2pAddNetwork = P2pAddNetwork;
    g_IWpaInterface.P2pGetPeer = P2pGetPeer;
    g_IWpaInterface.P2pGetGroupCapability = P2pGetGroupCapability;
    g_IWpaInterface.P2pListNetworks = P2pListNetworks;
    g_IWpaInterface.P2pSaveConfig = P2pSaveConfig;
    g_IWpaInterface.Reassociate = Reassociate;
    g_IWpaInterface.StaShellCmd = StaShellCmd;
    g_IWpaInterface.GetVersion = GetVersion;
    g_IWpaInterface.AsObject = AsWapObject;
    g_IWpaInterface.DeliverP2pData = DeliverP2pData;
    g_IWpaInterface.RegisterWpaEventCallback = RegisterWpaEventCallback;
    g_IWpaInterface.UnregisterWpaEventCallback = UnregisterWpaEventCallback;
    g_IWpaInterface.GetWpaStaData = GetWpaStaData;
    return &g_IWpaInterface;
}

struct IWpaInterface *IWpaInterfaceGetInstance(const char *serviceName, bool isStub)
{
    return IWpaInterfaceGet(false);
}

// external method used to create release object, it support ipc and passthrought mode
void IWpaInterfaceRelease(struct IWpaInterface *instance, bool isStub)
{
}
void IWpaInterfaceReleaseInstance(const char *serviceName, struct IWpaInterface *instance, bool isStub)
{
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
