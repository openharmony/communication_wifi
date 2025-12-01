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

#include "wifip2pserver_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "define.h"
#include "wifi_log.h"
#include "p2p_interface.h"
#include "wifi_internal_msg.h"
#include "wifi_p2p_service.h"
#include "wifi_p2p_group_manager.h"
#include "wifi_p2p_service.h"
#include "p2p_inviting_state.h"
#include <mutex>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr int THREE = 3;
constexpr int TWO = 2;
constexpr int U32_AT_SIZE_ZERO = 4;
static const int32_t NUM_BYTES = 1;
static bool g_isInsted = false;
static std::unique_ptr<P2pInterface> pP2pInterface = nullptr;
static std::unique_ptr<WifiP2pGroupManager> pWifiP2pGroupManager = nullptr;
static std::unique_ptr<WifiP2pService> pWifiP2pService = nullptr;
static std::unique_ptr<P2pInvitingState> pP2pInvitingState = nullptr;
IP2pServiceCallbacks mP2pCallback;

void MyExit()
{
    pP2pInterface.reset();
    pWifiP2pGroupManager.reset();
    sleep(THREE);
    printf("exiting\n");
}

void InitParam()
{
    if (!g_isInsted) {
        pP2pInterface = std::make_unique<P2pInterface>();
        pWifiP2pGroupManager = std::make_unique<WifiP2pGroupManager>();
        if (pP2pInterface == nullptr) {
            return;
        }
        atexit(MyExit);
        g_isInsted = true;
    }
    return;
}

class WifiP2pManager {
public:
    WifiP2pManager()
    {
        InitP2pCallback();
    }
    ~WifiP2pManager() {}
    void DealP2pStateChanged(P2pState bState) {}
    void DealP2pPeersChanged(const std::vector<WifiP2pDevice> &vPeers) {}
    void DealP2pServiceChanged(const std::vector<WifiP2pServiceInfo> &vServices) {}
    void DealP2pConnectionChanged(const WifiP2pLinkedInfo &info) {}
    void DealP2pThisDeviceChanged(const WifiP2pDevice &info) {}
    void DealP2pDiscoveryChanged(bool bState) {}
    void DealP2pGroupsChanged(void) {}
    void DealP2pActionResult(P2pActionCallback action, ErrCode code) {}
    void DealConfigChanged(CfgType type, char* data, int dataLen) {}
    void DealP2pPrivatePeersChanged(const std::string &privateInfo) {}
    IP2pServiceCallbacks& GetP2pCallback(void)
    {
        return mP2pCallback;
    }

    void InitP2pCallback(void)
    {
        using namespace std::placeholders;
        mP2pCallback.callbackModuleName = "P2pManager";
        mP2pCallback.OnP2pStateChangedEvent = std::bind(&WifiP2pManager::DealP2pStateChanged, this, _1);
        mP2pCallback.OnP2pPeersChangedEvent = std::bind(&WifiP2pManager::DealP2pPeersChanged, this, _1);
        mP2pCallback.OnP2pServicesChangedEvent = std::bind(&WifiP2pManager::DealP2pServiceChanged, this, _1);
        mP2pCallback.OnP2pConnectionChangedEvent = std::bind(&WifiP2pManager::DealP2pConnectionChanged, this, _1);
        mP2pCallback.OnP2pThisDeviceChangedEvent = std::bind(&WifiP2pManager::DealP2pThisDeviceChanged, this, _1);
        mP2pCallback.OnP2pDiscoveryChangedEvent = std::bind(&WifiP2pManager::DealP2pDiscoveryChanged, this, _1);
        mP2pCallback.OnP2pGroupsChangedEvent = std::bind(&WifiP2pManager::DealP2pGroupsChanged, this);
        mP2pCallback.OnP2pActionResultEvent = std::bind(&WifiP2pManager::DealP2pActionResult, this, _1, _2);
        mP2pCallback.OnConfigChangedEvent = std::bind(&WifiP2pManager::DealConfigChanged, this, _1, _2, _3);
        mP2pCallback.OnP2pPrivatePeersChangedEvent = std::bind(&WifiP2pManager::DealP2pPrivatePeersChanged, this, _1);
        return;
    }
};

void P2pServerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int32_t randomInt = FDP.ConsumeIntegral<int32_t>();
    WifiP2pDevice device;
    WifiP2pServiceRequest request;
    if (size >= THREE) {
        std::string deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string networkName = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string primaryDeviceType = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string secondaryDeviceType = FDP.ConsumeBytesAsString(NUM_BYTES);
        unsigned int supportWpsConfigMethods = FDP.ConsumeIntegral<unsigned int>();
        int deviceCapabilitys = FDP.ConsumeIntegral<int>();
        int groupCapabilitys = FDP.ConsumeIntegral<int>();
        device.SetDeviceName(deviceName);
        device.SetNetworkName(networkName);
        device.SetDeviceAddress(mDeviceAddress);
        device.SetPrimaryDeviceType(primaryDeviceType);
        device.SetSecondaryDeviceType(secondaryDeviceType);
        device.SetWpsConfigMethod(supportWpsConfigMethods);
        device.SetDeviceCapabilitys(deviceCapabilitys);
        device.SetGroupCapabilitys(groupCapabilitys);
    }

    WifiP2pConfig config;
    if (size >= THREE) {
        std::string mDeviceAddress01 = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string passphrase01 = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string groupName01 = FDP.ConsumeBytesAsString(NUM_BYTES);
        int groupOwnerIntent01 = FDP.ConsumeIntegral<int>();
        int deviceAddressType01 = FDP.ConsumeIntegral<int>();
        int netId = FDP.ConsumeIntegral<int>();
        config.SetDeviceAddress(mDeviceAddress01);
        config.SetDeviceAddressType(deviceAddressType01);
        config.SetNetId(netId);
        config.SetPassphrase(passphrase01);
        config.SetGroupOwnerIntent(groupOwnerIntent01);
        config.SetGroupName(groupName01);
    }

    WifiP2pGroupInfo group;
    if (size >= THREE) {
        std::string passphrase02 = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string interface02 = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string groupName02 = FDP.ConsumeBytesAsString(NUM_BYTES);
        int frequency = FDP.ConsumeIntegral<int>();

        group.SetPassphrase(passphrase02);
        group.SetInterface(interface02);
        group.SetGroupName(groupName02);
        group.SetFrequency(frequency);
    }

    WifiP2pWfdInfo wfdInfo;
    if (size >= THREE) {
        bool wfdEnabled = FDP.ConsumeBool();
        int deviceInfo = FDP.ConsumeIntegral<int>();
        int ctrlPort = FDP.ConsumeIntegral<int>();
        int maxThroughput =  FDP.ConsumeIntegral<int>();
        wfdInfo.SetWfdEnabled(wfdEnabled);
        wfdInfo.SetDeviceInfo(deviceInfo);
        wfdInfo.SetCtrlPort(ctrlPort);
        wfdInfo.SetMaxThroughput(maxThroughput);
    }

    WifiP2pServiceInfo srvInfo;
    std::string serviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string mDeviceAddress02 = FDP.ConsumeBytesAsString(NUM_BYTES);
    srvInfo.SetServiceName(serviceName);
    srvInfo.SetDeviceAddress(mDeviceAddress02);
    WifiP2pLinkedInfo linkedInfo;
    bool isP2pGroupOwner = FDP.ConsumeBool();
    std::string groupOwnerAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
    linkedInfo.SetIsGroupOwner(isP2pGroupOwner);
    linkedInfo.SetIsGroupOwnerAddress(groupOwnerAddress);
    int period = FDP.ConsumeIntegral<int>();
    int interval = FDP.ConsumeIntegral<int>();
    FreqType scanType = static_cast<FreqType>(randomInt % TWO);
    DhcpMode dhcpMode = static_cast<DhcpMode>(randomInt % THREE);
    Hid2dConnectConfig hidConfig;
    hidConfig.SetDhcpMode(dhcpMode);
    hidConfig.SetFrequency(interval);
    hidConfig.SetPreSharedKey(serviceName);
    hidConfig.SetBssid(groupOwnerAddress);
    hidConfig.SetSsid(mDeviceAddress02);

    pP2pInterface->DiscoverDevices();
    pP2pInterface->StopDiscoverDevices();
    pP2pInterface->DiscoverServices();
    pP2pInterface->StopDiscoverServices();
    pP2pInterface->PutLocalP2pService(srvInfo);
    pP2pInterface->DeleteLocalP2pService(srvInfo);
    pP2pInterface->RequestService(device, request);
    pP2pInterface->StartP2pListen(period, interval);
    pP2pInterface->StopP2pListen();
    pP2pInterface->CreateGroup(config);
    pP2pInterface->RemoveGroup();
    pP2pInterface->DeleteGroup(group);
    pP2pInterface->P2pConnect(config);
    pP2pInterface->P2pCancelConnect();
    pP2pInterface->SetP2pDeviceName(serviceName);
    pP2pInterface->SetP2pWfdInfo(wfdInfo);
    pP2pInterface->QueryP2pLinkedInfo(linkedInfo);
    pP2pInterface->GetCurrentGroup(group);
    pP2pInterface->GetP2pEnableStatus(period);
    pP2pInterface->GetP2pDiscoverStatus(interval);
    pP2pInterface->GetP2pConnectedStatus(period);
    pP2pInterface->QueryP2pLocalDevice(device);
    std::vector<WifiP2pServiceInfo> services;
    pP2pInterface->QueryP2pServices(services);
    std::vector<WifiP2pGroupInfo> groups;
    pP2pInterface->QueryP2pGroups(groups);
    std::vector<WifiP2pDevice> devices;
    pP2pInterface->QueryP2pDevices(devices);
    pP2pInterface->DisableRandomMac(period);
    pP2pInterface->MonitorCfgChange();
    pP2pInterface->GetP2pRecommendChannel();
    pP2pInterface->DecreaseSharedLink(interval);
    pP2pInterface->IncreaseSharedLink(interval);
    int channelid = FDP.ConsumeIntegral<int>();
    Hid2dUpperScene scene;
    GroupLiveType liveType = static_cast<GroupLiveType>(FDP.ConsumeIntegral<int>() % TWO);
    pP2pInterface->RegisterP2pServiceCallbacks(mP2pCallback);
    pP2pInterface->UnRegisterP2pServiceCallbacks(mP2pCallback);
    pP2pInterface->Hid2dCreateGroup(period, scanType);
    pP2pInterface->Hid2dConnect(hidConfig);
    pP2pInterface->Hid2dRequestGcIp(groupOwnerAddress, serviceName);
    pP2pInterface->DiscoverPeers(channelid);
    pP2pInterface->Hid2dSetUpperScene(serviceName, scene);
    pP2pInterface->Hid2dSetGroupType(liveType);
    pP2pInterface->HandleBusinessSAException(period);
    pWifiP2pGroupManager->UpdateWpaGroup(group);
    pWifiP2pGroupManager->ClearAll();
    pWifiP2pGroupManager->RemoveGroup(group);
    pWifiP2pGroupManager->RemoveClientFromGroup(interval, mDeviceAddress02);
    pWifiP2pGroupManager->GetNetworkIdFromClients(device);
    pWifiP2pGroupManager->GetGroupNetworkId(device);
    pWifiP2pGroupManager->GetGroupNetworkId(device, mDeviceAddress02);
    pWifiP2pGroupManager->GetGroupOwnerAddr(interval);
    pWifiP2pGroupManager->IsInclude(interval);
    pWifiP2pGroupManager->RefreshCurrentGroupFromGroups();
    pWifiP2pGroupManager->SaveP2pInfo(linkedInfo);
    std::map<int, WifiP2pGroupInfo> wpaGroups;
    wpaGroups.insert(std::make_pair(interval, group));
    pWifiP2pGroupManager->UpdateGroupsNetwork(wpaGroups);
    WifiMacAddrInfoType type = static_cast<WifiMacAddrInfoType>(randomInt % U32_AT_SIZE_ZERO);
    pWifiP2pGroupManager->AddMacAddrPairInfo(type, group);
    pWifiP2pGroupManager->SetCurrentGroup(type, group);
    pWifiP2pGroupManager->RemoveMacAddrPairInfo(type, group);
}

void P2pServerFuzzTest01(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    if (pWifiP2pService == nullptr) {
        return;
    }
    bool isAccept = FDP.ConsumeBool();
    bool isEnable = FDP.ConsumeBool();
    int uid = FDP.ConsumeIntegral<int>();
    std::vector<StationInfo> result;
    std::string config1;
    std::string config2;
    IpAddrInfo ipInfo;
    WifiP2pConfig config;
    if (size >= THREE) {
        std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string passphrase = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string groupName = FDP.ConsumeBytesAsString(NUM_BYTES);
        int groupOwnerIntent = FDP.ConsumeIntegral<int>();
        int deviceAddressType = FDP.ConsumeIntegral<int>();
        int netId = FDP.ConsumeIntegral<int>();

        config.SetDeviceAddress(mDeviceAddress);
        config.SetDeviceAddressType(deviceAddressType);
        config.SetNetId(netId);
        config.SetPassphrase(passphrase);
        config.SetGroupOwnerIntent(groupOwnerIntent);
        config.SetGroupName(groupName);
    }
    pWifiP2pService->CreateRptGroup(config);
    pWifiP2pService->GetRptStationsList(result);
    pWifiP2pService->SetGcIpAddress(ipInfo);
    pWifiP2pService->NotifyWscDialogConfirmResult(isAccept, config2);
    pWifiP2pService->NotifyWscDisplayConfirmResult();
    pWifiP2pService->SetMiracastSinkConfig(config1);
    pWifiP2pService->NotifyRemoteDie(uid);
    pWifiP2pService->SetP2pHighPerf(isEnable);
}

void WifiP2pGroupManagerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo group;
    if (size >= THREE) {
        std::string passphrase = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string interface = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string groupName = FDP.ConsumeBytesAsString(NUM_BYTES);
        int frequency = FDP.ConsumeIntegral<int>();
        group.SetPassphrase(passphrase);
        group.SetInterface(interface);
        group.SetGroupName(groupName);
        group.SetFrequency(frequency);
    }
    pWifiP2pGroupManager->AddOrUpdateGroup(group);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::InitParam();
    OHOS::Wifi::P2pServerFuzzTest(data, size);
    OHOS::Wifi::P2pServerFuzzTest01(data, size);
    OHOS::Wifi::WifiP2pGroupManagerFuzzTest(data, size);
    return 0;
}
}
}
