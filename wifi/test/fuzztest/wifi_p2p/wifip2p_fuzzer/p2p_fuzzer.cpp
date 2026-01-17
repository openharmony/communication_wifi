/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "p2p_fuzzer.h"
#include "wifi_p2p_group_manager.h"
#include "wifi_p2p_device_manager.h"
#include "wifi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
static const int32_t NUM_BYTES = 1;

/* Group Manager */
void RemoveGroupFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.RemoveGroup(pGroupInfo);
}

void UpdateWpaGroupFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());
    pGroupInfo.SetGroupName("p2p0");

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.UpdateWpaGroup(pGroupInfo);
}

void RemoveClientFromGroupFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());
    std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    int netId = FDP.ConsumeIntegral<int>();
    pGroupManager.RemoveClientFromGroup(netId, mDeviceAddress);
}

void GetNetworkIdFromClientsFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    std::vector<WifiP2pDevice> devices;
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    devices.push_back(device);
    pGroupInfo.SetClientDevices(devices);

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.GetNetworkIdFromClients(device);
}

void GetGroupNetworkIdFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());
    WifiP2pDevice device;

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.GetGroupNetworkId(device);
}

void GetGroupNetworkIdFuzzerTest1(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());
    pGroupInfo.SetGroupName(FDP.ConsumeBytesAsString(NUM_BYTES));
    WifiP2pDevice device;
    device.SetDeviceAddress(FDP.ConsumeBytesAsString(NUM_BYTES));
    std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.GetGroupNetworkId(device, mDeviceAddress);
}

void GetGroupOwnerAddrFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    int netId = FDP.ConsumeIntegral<int>();
    pGroupManager.GetGroupOwnerAddr(netId);
}

void IsIncludeFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    int netId = FDP.ConsumeIntegral<int>();
    pGroupManager.IsInclude(netId);
}

void RefreshGroupsFromCurrentGroupFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());
    WifiP2pGroupInfoProxy currentGroup;

    WifiP2pGroupManager pGroupManager;
    WifiMacAddrInfoType type = static_cast<WifiMacAddrInfoType>(0);
    pGroupManager.SetCurrentGroup(type, pGroupInfo);
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.RefreshGroupsFromCurrentGroup();
}

void RefreshCurrentGroupFromGroupsFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    WifiMacAddrInfoType type = static_cast<WifiMacAddrInfoType>(1);
    pGroupManager.SetCurrentGroup(type, pGroupInfo);
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.RefreshCurrentGroupFromGroups();
}

void UpdateGroupsNetworkFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    std::map<int, WifiP2pGroupInfo> wpaGroups;
    wpaGroups.insert(std::make_pair(1, pGroupInfo));
    pGroupManager.UpdateGroupsNetwork(wpaGroups);
}

void UpdateGroupsNetworkFuzzerTest1(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    std::map<int, WifiP2pGroupInfo> wpaGroups;
    pGroupManager.UpdateGroupsNetwork(wpaGroups);
}

void AddMacAddrPairInfoFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    WifiMacAddrInfoType type = static_cast<WifiMacAddrInfoType>(4);

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.AddMacAddrPairInfo(type, pGroupInfo);
}

void RemoveMacAddrPairInfoFuzzerTest(FuzzedDataProvider& FDP)
{
    WifiP2pGroupInfo pGroupInfo;
    pGroupInfo.SetNetworkId(FDP.ConsumeIntegral<int>());

    std::vector<WifiP2pDevice> devices;
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    devices.push_back(device);
    pGroupInfo.SetClientDevices(devices);

    WifiMacAddrInfoType type = static_cast<WifiMacAddrInfoType>(1);

    WifiP2pGroupManager pGroupManager;
    pGroupManager.AddGroup(pGroupInfo);
    pGroupManager.RemoveMacAddrPairInfo(type, pGroupInfo);
}

/* Device Manager */
void InitializeFuzzerTest()
{
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.Initialize();
}

void AddDeviceFuzzerTest()
{
    WifiP2pDevice device;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
}

void UpdateDeviceFuzzerTest()
{
    WifiP2pDevice device;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDevice(device);
}

void UpdateDeviceFuzzerTest1(FuzzedDataProvider& FDP)
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string deviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.UpdateDevice(device);
}

void UpdateDeviceSupplicantInfFuzzerTest()
{
    WifiP2pDevice device;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDeviceSupplicantInf(device);
}

void UpdateDeviceSupplicantInfFuzzerTest1(FuzzedDataProvider& FDP)
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string deviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.UpdateDeviceSupplicantInf(device);
}

void UpdateDeviceGroupCapFuzzerTest(FuzzedDataProvider& FDP)
{
    std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
    uint32_t cap = 1;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDeviceGroupCap("", cap);
}

void UpdateDeviceGroupCapFuzzerTest1()
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string mDeviceAddress = "0x11:0x22:0x33:0x44:0x55";
    uint32_t cap = 1;

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.UpdateDeviceGroupCap(mDeviceAddress, cap);
}

void UpdateDeviceGroupCapFuzzerTest2()
{
    WifiP2pDevice device;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDeviceGroupCap(device);
}

void UpdateDeviceStatusFuzzerTest()
{
    P2pDeviceStatus status = static_cast<P2pDeviceStatus>(0);
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDeviceStatus("", status);
}

void UpdateDeviceStatusFuzzerTest1()
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string mDeviceAddress = "0x11:0x22:0x33:0x44:0x55";
    P2pDeviceStatus status = static_cast<P2pDeviceStatus>(0);

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.UpdateDeviceStatus(mDeviceAddress, status);
}

void UpdateDeviceStatusFuzzerTest2()
{
    WifiP2pDevice device;
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.UpdateDeviceStatus(device);
}

void UpdateAllDeviceStatusFuzzerTest()
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string mDeviceAddress = "0x11:0x22:0x33:0x44:0x55";
    P2pDeviceStatus status = static_cast<P2pDeviceStatus>(0);

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.UpdateAllDeviceStatus(status);
}

void GetDevicesFuzzerTest()
{
    WifiP2pDevice device;
    device.SetDeviceAddress("0x11:0x22:0x33:0x44:0x55");
    std::string mDeviceAddress = "0x11:0x22:0x33:0x44:0x55";

    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.AddDevice(device);
    pDeviceManager.GetDevices(mDeviceAddress);
}

void GetDeviceNameFuzzerTest(FuzzedDataProvider& FDP)
{
    std::string deviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
    WifiP2pDeviceManager pDeviceManager;
    pDeviceManager.GetDeviceName(deviceAddress);
}

void WifiP2pGroupManagerFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    RemoveGroupFuzzerTest(FDP);
    UpdateWpaGroupFuzzerTest(FDP);
    RemoveClientFromGroupFuzzerTest(data, size);
    GetNetworkIdFromClientsFuzzerTest(FDP);
    GetGroupNetworkIdFuzzerTest(FDP);
    GetGroupOwnerAddrFuzzerTest(data, size);
    IsIncludeFuzzerTest(data, size);
    RefreshGroupsFromCurrentGroupFuzzerTest(FDP);
    RefreshCurrentGroupFromGroupsFuzzerTest(FDP);
    UpdateDeviceGroupCapFuzzerTest(FDP);

    UpdateGroupsNetworkFuzzerTest(FDP);
    UpdateGroupsNetworkFuzzerTest1(FDP);
    AddMacAddrPairInfoFuzzerTest(FDP);
    RemoveMacAddrPairInfoFuzzerTest(FDP);
    GetDeviceNameFuzzerTest(FDP);
    UpdateDeviceSupplicantInfFuzzerTest1(FDP);
    UpdateDeviceFuzzerTest1(FDP);
}

void WifiP2pDeviceManagerFuzzerTest()
{
    InitializeFuzzerTest();
    AddDeviceFuzzerTest();
    UpdateDeviceFuzzerTest();
    UpdateDeviceSupplicantInfFuzzerTest();
    UpdateDeviceGroupCapFuzzerTest1();
    UpdateDeviceGroupCapFuzzerTest2();
    UpdateDeviceStatusFuzzerTest();
    UpdateDeviceStatusFuzzerTest1();
    UpdateDeviceStatusFuzzerTest2();
    UpdateAllDeviceStatusFuzzerTest();
    GetDevicesFuzzerTest();
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    GetGroupNetworkIdFuzzerTest1(FDP);
    OHOS::Wifi::WifiP2pGroupManagerFuzzerTest(data, size);
    OHOS::Wifi::WifiP2pDeviceManagerFuzzerTest();
    return 0;
}
}
}