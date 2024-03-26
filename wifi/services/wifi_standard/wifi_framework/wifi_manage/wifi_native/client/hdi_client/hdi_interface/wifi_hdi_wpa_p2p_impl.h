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

#ifndef OHOS_WIFI_HDI_WPA_P2P_IMPL_H
#define OHOS_WIFI_HDI_WPA_P2P_IMPL_H

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_proxy.h"
#include "i_wifi_struct.h"
#include "wifi_idl_define.h"

#ifdef __cplusplus
extern "C" {
#endif

WifiErrorNo HdiWpaP2pStart(const char *ifaceName);

WifiErrorNo HdiWpaP2pStop();

WifiErrorNo RegisterHdiWpaP2pEventCallback(struct IWpaCallback *callback);

WifiErrorNo HdiP2pSetSsidPostfixName(const char *name);

WifiErrorNo HdiP2pSetWpsDeviceType(const char *type);

WifiErrorNo HdiP2pSetWpsConfigMethods(const char *methods);

WifiErrorNo HdiP2pSetGroupMaxIdle(const char *groupIfc, int time);

WifiErrorNo HdiP2pSetWfdEnable(int enable);

WifiErrorNo HdiP2pSetPersistentReconnect(int status);

WifiErrorNo HdiP2pSetWpsSecondaryDeviceType(const char *type);

WifiErrorNo HdiP2pSetupWpsPbc(const char *groupIfc, const char *address);

WifiErrorNo HdiP2pSetupWpsPin(const char *groupIfc, const char *address, const char *pin, char *result);

WifiErrorNo HdiP2pSetPowerSave(const char *groupIfc, int enable);

WifiErrorNo HdiP2pSetDeviceName(const char *name);

WifiErrorNo HdiP2pSetWfdDeviceConfig(const char *config);

WifiErrorNo HdiP2pSetRandomMac(int enable);

WifiErrorNo HdiP2pStartFind(int timeout);

WifiErrorNo HdiP2pSetExtListen(int enable, int period, int interval);

WifiErrorNo HdiP2pSetListenChannel(int channel, int regClass);

WifiErrorNo HdiP2pProvisionDiscovery(const char *peerBssid, int mode);

WifiErrorNo HdiP2pAddGroup(int isPersistent, int networkId, int freq);

WifiErrorNo HdiP2pAddService(struct HdiP2pServiceInfo *info);

WifiErrorNo HdiP2pRemoveService(struct HdiP2pServiceInfo *info);

WifiErrorNo HdiP2pStopFind();

WifiErrorNo HdiP2pFlush();

WifiErrorNo HdiP2pFlushService();

WifiErrorNo HdiP2pRemoveNetwork(int networkId);

WifiErrorNo HdiP2pSetGroupConfig(int networkId, P2pGroupConfig *pConfig, int size);

WifiErrorNo HdiP2pInvite(const char *peerBssid, const char *goBssid, const char *ifname);

WifiErrorNo HdiP2pReinvoke(int networkId, const char *bssid);

WifiErrorNo HdiP2pGetDeviceAddress(char *deviceAddress);

WifiErrorNo HdiP2pReqServiceDiscovery(struct HdiP2pReqService *reqService, char *replyDisc);

WifiErrorNo HdiP2pCancelServiceDiscovery(const char *id);

WifiErrorNo HdiP2pRespServerDiscovery(struct HdiP2pServDiscReqInfo *info);

WifiErrorNo HdiP2pConnect(P2pConnectInfo *info, char *replyPin);

WifiErrorNo HdiP2pHid2dConnect(struct Hid2dConnectInfo *info);

WifiErrorNo HdiP2pSetServDiscExternal(int mode);

WifiErrorNo HdiP2pRemoveGroup(const char *groupName);

WifiErrorNo HdiP2pCancelConnect();

WifiErrorNo HdiP2pGetGroupConfig(int networkId, char *param, char *value);

WifiErrorNo HdiP2pAddNetwork(int *networkId);

WifiErrorNo HdiP2pGetPeer(const char *bssid, struct HdiP2pDeviceInfo *info);

WifiErrorNo HdiP2pGetGroupCapability(const char *bssid, int cap);

WifiErrorNo HdiP2pListNetworks(struct HdiP2pNetworkList *infoList);

WifiErrorNo HdiP2pSaveConfig();

#ifdef __cplusplus
}
#endif
#endif
#endif