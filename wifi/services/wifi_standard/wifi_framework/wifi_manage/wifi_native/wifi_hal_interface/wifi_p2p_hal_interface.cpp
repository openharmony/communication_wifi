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

#include "wifi_p2p_hal_interface.h"
#include "wifi_log.h"
#include <mutex>

#undef LOG_TAG
#define LOG_TAG "WifiP2PHalInterface"

namespace OHOS {
namespace Wifi {
WifiP2PHalInterface &WifiP2PHalInterface::GetInstance(void)
{
    static WifiP2PHalInterface inst;
    static int initFlag = 0;
    static std::mutex initMutex;
    if (initFlag == 0) {
        std::unique_lock<std::mutex> lock(initMutex);
        if (initFlag == 0) {
#ifdef HDI_WPA_INTERFACE_SUPPORT
            if (inst.InitHdiWpaClient()) {
                initFlag = 1;
            }
#else
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiP2PHalInterface::StartP2p(const std::string &ifaceName) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStart(ifaceName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pStart();
#endif
}

WifiErrorNo WifiP2PHalInterface::StopP2p(void) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStop();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pStop();
#endif
}

WifiErrorNo WifiP2PHalInterface::RegisterP2pCallback(const P2pHalCallback &callbacks)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mHdiWpaClient->ReqP2pRegisterCallback(callbacks);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->ReqP2pRegisterCallback(callbacks);
#endif
    if (err == WIFI_IDL_OPT_OK || callbacks.onConnectSupplicant == nullptr) {
        mP2pCallback = callbacks;
    }
    return err;
}

WifiErrorNo WifiP2PHalInterface::StartWpsPbc(const std::string &groupInterface, const std::string &bssid) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetupWpsPbc(groupInterface, bssid);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetupWpsPbc(groupInterface, bssid);
#endif
}

WifiErrorNo WifiP2PHalInterface::StartWpsPin(
    const std::string &groupInterface, const std::string &address, const std::string &pin, std::string &result) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetupWpsPin(groupInterface, address, pin, result);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetupWpsPin(groupInterface, address, pin, result);
#endif
}

WifiErrorNo WifiP2PHalInterface::RemoveNetwork(int networkId) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveNetwork(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pRemoveNetwork(networkId);
#endif
}

WifiErrorNo WifiP2PHalInterface::ListNetworks(std::map<int, WifiP2pGroupInfo> &mapGroups) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pListNetworks(mapGroups);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pListNetworks(mapGroups);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pDeviceName(const std::string &name) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetDeviceName(name);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetDeviceName(name);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pDeviceType(const std::string &type) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsDeviceType(type);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetWpsDeviceType(type);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pSecondaryDeviceType(const std::string &type)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsSecondaryDeviceType(type);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetWpsSecondaryDeviceType(type);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pConfigMethods(const std::string &methods) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsConfigMethods(methods);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetWpsConfigMethods(methods);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pSsidPostfix(const std::string &postfixName) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetSsidPostfixName(postfixName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetSsidPostfixName(postfixName);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pGroupIdle(const std::string &groupInterface, size_t time) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetGroupMaxIdle(groupInterface, time);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetGroupMaxIdle(groupInterface, time);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetP2pPowerSave(const std::string &groupInterface, bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetPowerSave(groupInterface, enable);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetPowerSave(groupInterface, enable);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetWfdEnable(bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWfdEnable(enable);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetWfdEnable(enable);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetWfdDeviceConfig(const std::string &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWfdDeviceConfig(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetWfdDeviceConfig(config);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pFind(size_t timeout) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStartFind(timeout);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pStartFind(timeout);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pStopFind() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStopFind();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pStopFind();
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pConfigureListen(bool enable, size_t period, size_t interval) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetExtListen(enable, period, interval);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetListenChannel(size_t channel, unsigned char regClass) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetListenChannel(channel, regClass);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetListenChannel(channel, regClass);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pFlush() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pFlush();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pFlush();
#endif
}

WifiErrorNo WifiP2PHalInterface::Connect(const WifiP2pConfigInternal &config, bool isJoinExistingGroup,
    std::string &pin) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pConnect(config, isJoinExistingGroup, pin);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pConnect(config, isJoinExistingGroup, pin);
#endif
}

WifiErrorNo WifiP2PHalInterface::CancelConnect() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pCancelConnect();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pCancelConnect();
#endif
}

WifiErrorNo WifiP2PHalInterface::ProvisionDiscovery(const WifiP2pConfigInternal &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pProvisionDiscovery(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pProvisionDiscovery(config);
#endif
}

WifiErrorNo WifiP2PHalInterface::GroupAdd(bool isPersistent, int networkId, int freq) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddGroup(isPersistent, networkId, freq);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pAddGroup(isPersistent, networkId, freq);
#endif
}

WifiErrorNo WifiP2PHalInterface::GroupRemove(const std::string &groupInterface) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveGroup(groupInterface);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pRemoveGroup(groupInterface);
#endif
}

WifiErrorNo WifiP2PHalInterface::GroupClientRemove(const std::string &deviceMac) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveGroupClient(deviceMac);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pRemoveGroupClient(deviceMac);
#endif
}

WifiErrorNo WifiP2PHalInterface::Invite(const WifiP2pGroupInfo &group, const std::string &deviceAddr) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pInvite(group, deviceAddr);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pInvite(group, deviceAddr);
#endif
}

WifiErrorNo WifiP2PHalInterface::Reinvoke(int networkId, const std::string &deviceAddr) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pReinvoke(networkId, deviceAddr);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pReinvoke(networkId, deviceAddr);
#endif
}

WifiErrorNo WifiP2PHalInterface::GetDeviceAddress(std::string &deviceAddress) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetDeviceAddress(deviceAddress);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pGetDeviceAddress(deviceAddress);
#endif
}

WifiErrorNo WifiP2PHalInterface::GetGroupCapability(const std::string &deviceAddress, uint32_t &cap) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetGroupCapability(deviceAddress, cap);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pGetGroupCapability(deviceAddress, cap);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pServiceAdd(const WifiP2pServiceInfo &info) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddService(info);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pAddService(info);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pServiceRemove(const WifiP2pServiceInfo &info) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveService(info);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pRemoveService(info);
#endif
}

WifiErrorNo WifiP2PHalInterface::FlushService() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pFlushService();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pFlushService();
#endif
}

WifiErrorNo WifiP2PHalInterface::SaveConfig() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSaveConfig();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSaveConfig();
#endif
}

WifiErrorNo WifiP2PHalInterface::ReqServiceDiscovery(
    const std::string &deviceAddress, const std::vector<unsigned char> &tlvs, std::string &reqID) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
#endif
}

WifiErrorNo WifiP2PHalInterface::CancelReqServiceDiscovery(const std::string &id) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pCancelServiceDiscovery(id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pCancelServiceDiscovery(id);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetRandomMacAddr(bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetRandomMac(enable);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetRandomMac(enable);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetMiracastMode(int type) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetMiracastType(type);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetMiracastType(type);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetPersistentReconnect(int mode) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqSetPersistentReconnect(mode);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPersistentReconnect(mode);
#endif
}

WifiErrorNo WifiP2PHalInterface::RespServiceDiscovery(
    const WifiP2pDevice &device, int frequency, int dialogToken, const std::vector<unsigned char> &tlvs) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
#endif
}

WifiErrorNo WifiP2PHalInterface::SetServiceDiscoveryExternal(bool isExternalProcess) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqSetServiceDiscoveryExternal(isExternalProcess);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetServiceDiscoveryExternal(isExternalProcess);
#endif
}

WifiErrorNo WifiP2PHalInterface::GetP2pPeer(const std::string &deviceAddress, WifiP2pDevice &device) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqGetP2pPeer(deviceAddress, device);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetP2pPeer(deviceAddress, device);
#endif
}

WifiErrorNo WifiP2PHalInterface::GetChba0Freq(int &chba0Freq) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiP2PHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pGetChba0Freq(chba0Freq);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pGetSupportFrequenciesByBand(int band, std::vector<int> &frequencies) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetSupportFrequencies(band, frequencies);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pGetSupportFrequencies(band, frequencies);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pSetGroupConfig(int networkId, const IdlP2pGroupConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetGroupConfig(networkId, config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pSetGroupConfig(networkId, config);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pGetGroupConfig(int networkId, IdlP2pGroupConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetGroupConfig(networkId, config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pGetGroupConfig(networkId, config);
#endif
}

WifiErrorNo WifiP2PHalInterface::P2pAddNetwork(int &networkId) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddNetwork(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pAddNetwork(networkId);
#endif
}

const P2pHalCallback &WifiP2PHalInterface::GetP2pCallbackInst(void) const
{
    return mP2pCallback;
}

WifiErrorNo WifiP2PHalInterface::Hid2dConnect(const Hid2dConnectConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pHid2dConnect(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqP2pHid2dConnect(config);
#endif
}

}  // namespace Wifi
}  // namespace OHOS