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
#include "hal_device_manage.h"
#include <mutex>
#include "wifi_config_center.h"

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
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiP2PHalInterface::StartP2p(const std::string &ifaceName, const bool hasPersisentGroup) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStart(ifaceName, hasPersisentGroup);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::StopP2p(void) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStop();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::RegisterP2pCallback(const P2pHalCallback &callbacks)
{
    WifiErrorNo err = WIFI_HAL_OPT_FAILED;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    err = mHdiWpaClient->ReqP2pRegisterCallback(callbacks);
#endif
    if (err == WIFI_HAL_OPT_OK || callbacks.onConnectSupplicant == nullptr) {
        mP2pCallback = callbacks;
    }
    return err;
}

WifiErrorNo WifiP2PHalInterface::StartWpsPbc(const std::string &groupInterface, const std::string &bssid) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetupWpsPbc(groupInterface, bssid);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::StartWpsPin(
    const std::string &groupInterface, const std::string &address, const std::string &pin, std::string &result) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetupWpsPin(groupInterface, address, pin, result);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::RemoveNetwork(int networkId) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveNetwork(networkId);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::ListNetworks(std::map<int, WifiP2pGroupInfo> &mapGroups) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pListNetworks(mapGroups);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pDeviceName(const std::string &name) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetDeviceName(name);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pDeviceType(const std::string &type) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsDeviceType(type);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pSecondaryDeviceType(const std::string &type)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsSecondaryDeviceType(type);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pConfigMethods(const std::string &methods) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWpsConfigMethods(methods);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pSsidPostfix(const std::string &postfixName) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetSsidPostfixName(postfixName);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pGroupIdle(const std::string &groupInterface, size_t time) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetGroupMaxIdle(groupInterface, time);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetP2pPowerSave(const std::string &groupInterface, bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetPowerSave(groupInterface, enable);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetWfdEnable(bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWfdEnable(enable);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetWfdDeviceConfig(const std::string &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetWfdDeviceConfig(config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pFind(size_t timeout) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStartFind(timeout);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pStopFind() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pStopFind();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pConfigureListen(bool enable, size_t period, size_t interval) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetListenChannel(size_t channel, unsigned char regClass) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetListenChannel(channel, regClass);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pFlush() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pFlush();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::Connect(const WifiP2pConfigInternal &config, bool isJoinExistingGroup,
    std::string &pin) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pConnect(config, isJoinExistingGroup, pin);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::CancelConnect() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pCancelConnect();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::ProvisionDiscovery(const WifiP2pConfigInternal &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pProvisionDiscovery(config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GroupAdd(bool isPersistent, int networkId, int freq) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddGroup(isPersistent, networkId, freq);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GroupRemove(const std::string &groupInterface) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveGroup(groupInterface);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GroupClientRemove(const std::string &deviceMac) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    std::string ifName = WifiConfigCenter::GetInstance().GetP2pIfaceName();
    return mHdiWpaClient->ReqP2pRemoveGroupClient(deviceMac, ifName);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::Invite(const WifiP2pGroupInfo &group, const std::string &deviceAddr) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pInvite(group, deviceAddr);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::Reinvoke(int networkId, const std::string &deviceAddr) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pReinvoke(networkId, deviceAddr);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GetDeviceAddress(std::string &deviceAddress) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetDeviceAddress(deviceAddress);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GetGroupCapability(const std::string &deviceAddress, uint32_t &cap) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetGroupCapability(deviceAddress, cap);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pServiceAdd(const WifiP2pServiceInfo &info) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddService(info);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pServiceRemove(const WifiP2pServiceInfo &info) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pRemoveService(info);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::FlushService() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pFlushService();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SaveConfig() const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSaveConfig();
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::ReqServiceDiscovery(
    const std::string &deviceAddress, const std::vector<unsigned char> &tlvs, std::string &reqID) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::CancelReqServiceDiscovery(const std::string &id) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pCancelServiceDiscovery(id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetRandomMacAddr(bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetRandomMac(enable);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetMiracastMode(int type) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetMiracastType(type);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetPersistentReconnect(int mode) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqSetPersistentReconnect(mode);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::RespServiceDiscovery(
    const WifiP2pDevice &device, int frequency, int dialogToken, const std::vector<unsigned char> &tlvs) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetServiceDiscoveryExternal(bool isExternalProcess) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqSetServiceDiscoveryExternal(isExternalProcess);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GetP2pPeer(const std::string &deviceAddress, WifiP2pDevice &device) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqGetP2pPeer(deviceAddress, device);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::GetChba0Freq(int &chba0Freq) const
{
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pGetSupportFrequenciesByBand(const std::string &ifaceName, int band,
    std::vector<int> &frequencies) const
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, frequencies)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pSetSingleConfig(int networkId,
    const std::string &key, const std::string &value) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetSingleConfig(networkId, key, value);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pSetGroupConfig(int networkId, const HalP2pGroupConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pSetGroupConfig(networkId, config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pGetGroupConfig(int networkId, HalP2pGroupConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pGetGroupConfig(networkId, config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pAddNetwork(int &networkId) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pAddNetwork(networkId);
#endif
    return WIFI_HAL_OPT_FAILED;
}

const P2pHalCallback &WifiP2PHalInterface::GetP2pCallbackInst(void) const
{
    return mP2pCallback;
}

WifiErrorNo WifiP2PHalInterface::Hid2dConnect(const Hid2dConnectConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqP2pHid2dConnect(config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::DeliverP2pData(int32_t cmdType, int32_t dataType, const std::string& carryData) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->DeliverP2pData(cmdType, dataType, carryData.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetRptBlockList(const std::string &ifaceName, const std::string &interfaceName,
    const std::vector<std::string> &blockList)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetBlockList(ifaceName, interfaceName, blockList)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::DisAssociateSta(const std::string &ifaceName, const std::string &interfaceName,
    const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().DisAssociateSta(ifaceName, interfaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pReject(const std::string &mac)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->P2pReject(mac);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::SetMiracastSinkConfig(const std::string& config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetMiracastSinkConfig(config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::P2pSetTempConfig(int networkId, const HalP2pGroupConfig &config) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->P2pSetTempConfig(networkId, config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiP2PHalInterface::TempGroupAdd(int freq)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->P2pTempGroupAdd(freq);
#endif
    return WIFI_HAL_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS