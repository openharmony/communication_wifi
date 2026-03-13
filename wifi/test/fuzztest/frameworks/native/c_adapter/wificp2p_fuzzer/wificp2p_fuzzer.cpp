/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "securec.h"
#include "wificp2p_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include "kits/c/wifi_p2p.h"
#include <fuzzer/FuzzedDataProvider.h>

static void GetP2pEnableStatusTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    P2pState state = P2P_STATE_NONE;
    if (size > 0) {
        int temp = FDP.ConsumeIntegral<int>() % P2P_STATE_CLOSED;
        state = static_cast<P2pState>(temp);
    }
    (void)GetP2pEnableStatus(&state);
}

static void GStartP2pListenTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int index = 0;
    int period = 0;
    int interval = 0;

    if (index >= TWO) {
        period = FDP.ConsumeIntegral<int>();
        interval = FDP.ConsumeIntegral<int>();
    }
    (void)StartP2pListen(period, interval);
}

static void CreateGroupTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pConfig config;
    if (size > sizeof(WifiP2pConfig)) {
        if (memcpy_s(config.devAddr, COMMON_MAC_LEN, data, COMMON_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(config.passphrase, PASSPHRASE_LENGTH, data, PASSPHRASE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(config.groupName, P2P_NAME_LENGTH, data + COMMON_MAC_LEN, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }
        config.netId = FDP.ConsumeIntegral<int>();
        config.groupOwnerIntent = FDP.ConsumeIntegral<int>();
        config.goBand = GO_BAND_AUTO;
    }
    (void)CreateGroup(&config);
}

static void DeleteGroupTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo group;

    if (size > sizeof(WifiP2pGroupInfo)) {
        if (memcpy_s(group.passphrase, PASSPHRASE_LENGTH, data, PASSPHRASE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(group.interface, INTERFACE_LENGTH, data, INTERFACE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(group.groupName, P2P_NAME_LENGTH, data, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(group.goIpAddress, IP_ADDR_STR_LEN, data, IP_ADDR_STR_LEN - 1) != EOK) {
            return;
        }
        group.isP2pGroupOwner = FDP.ConsumeIntegral<int>();
        group.networkId = FDP.ConsumeIntegral<int>();
        group.frequency = FDP.ConsumeIntegral<int>();
        group.isP2pPersistent = FDP.ConsumeIntegral<int>();
        group.clientDevicesSize = FDP.ConsumeIntegral<int>();
    }
    (void)DeleteGroup(&group);
}

static void P2pConnectTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pConfig config;
    if (size > sizeof(WifiP2pConfig)) {
        if (memcpy_s(config.devAddr, COMMON_MAC_LEN, data, COMMON_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(config.passphrase, PASSPHRASE_LENGTH, data, PASSPHRASE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(config.groupName, P2P_NAME_LENGTH, data + COMMON_MAC_LEN, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }
        config.netId = FDP.ConsumeIntegral<int>();
        config.groupOwnerIntent = FDP.ConsumeIntegral<int>();
        config.goBand = GO_BAND_AUTO;
    }
    (void)P2pConnect(&config);
}

static void GetCurrentGroupTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo groupInfo;

    if (size > sizeof(WifiP2pGroupInfo)) {
        if (memcpy_s(groupInfo.passphrase, PASSPHRASE_LENGTH, data, PASSPHRASE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.interface, INTERFACE_LENGTH, data, INTERFACE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.groupName, P2P_NAME_LENGTH, data, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.goIpAddress, IP_ADDR_STR_LEN, data, IP_ADDR_STR_LEN - 1) != EOK) {
            return;
        }
        groupInfo.isP2pGroupOwner = FDP.ConsumeIntegral<int>();
        groupInfo.networkId = FDP.ConsumeIntegral<int>();
        groupInfo.frequency = FDP.ConsumeIntegral<int>();
        groupInfo.isP2pPersistent = FDP.ConsumeIntegral<int>();
        groupInfo.clientDevicesSize = FDP.ConsumeIntegral<int>();
    }
    (void)GetCurrentGroup(&groupInfo);
}

static void GetP2pConnectedStatusTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int status = FDP.ConsumeIntegral<int>();
    (void)GetP2pConnectedStatus(&status);
}

static void QueryP2pLocalDeviceTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pDevice deviceInfo;
    if (size >= sizeof(WifiP2pDevice)) {
        if (memcpy_s(deviceInfo.deviceName, P2P_NAME_LENGTH, data, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(deviceInfo.devAddr, COMMON_MAC_LEN, data + P2P_NAME_LENGTH, COMMON_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(deviceInfo.primaryDeviceType, DEVICE_TYPE_LENGTH, data, DEVICE_TYPE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(deviceInfo.primaryDeviceType, DEVICE_TYPE_LENGTH, data, DEVICE_TYPE_LENGTH - 1) != EOK) {
            return;
        }
        deviceInfo.status = static_cast<P2pDeviceStatus>(FDP.ConsumeIntegral<int>() % PDS_UNAVAILABLE);
        deviceInfo.wfdInfo.wfdEnabled = FDP.ConsumeIntegral<int>();
        deviceInfo.wfdInfo.deviceInfo = FDP.ConsumeIntegral<int>();
        deviceInfo.wfdInfo.ctrlPort = FDP.ConsumeIntegral<int>();
        deviceInfo.wfdInfo.maxThroughput = FDP.ConsumeIntegral<int>();
        deviceInfo.supportWpsConfigMethods = FDP.ConsumeIntegral<unsigned int>();
        deviceInfo.deviceCapabilitys = FDP.ConsumeIntegral<int>();
        deviceInfo.groupCapabilitys = FDP.ConsumeIntegral<int>();
    }
    (void)QueryP2pLocalDevice(&deviceInfo);
}

static void QueryP2pDevicesTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pDevice clientDevices;
    int retSize = 0;
    int msize = 0;
    if (size >= sizeof(WifiP2pDevice)) {
        if (memcpy_s(clientDevices.deviceName, P2P_NAME_LENGTH, data, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(clientDevices.devAddr, COMMON_MAC_LEN, data + P2P_NAME_LENGTH, COMMON_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(clientDevices.primaryDeviceType, DEVICE_TYPE_LENGTH, data, DEVICE_TYPE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(clientDevices.primaryDeviceType, DEVICE_TYPE_LENGTH, data, DEVICE_TYPE_LENGTH - 1) != EOK) {
            return;
        }
        clientDevices.status = static_cast<P2pDeviceStatus>(FDP.ConsumeIntegral<int>() % PDS_UNAVAILABLE);
        clientDevices.wfdInfo.wfdEnabled = FDP.ConsumeIntegral<int>();
        clientDevices.wfdInfo.deviceInfo = FDP.ConsumeIntegral<int>();
        clientDevices.wfdInfo.ctrlPort = FDP.ConsumeIntegral<int>();
        clientDevices.wfdInfo.maxThroughput = FDP.ConsumeIntegral<int>();
        clientDevices.supportWpsConfigMethods = FDP.ConsumeIntegral<unsigned int>();
        clientDevices.deviceCapabilitys = FDP.ConsumeIntegral<int>();
        clientDevices.groupCapabilitys = FDP.ConsumeIntegral<int>();
        msize = FDP.ConsumeIntegral<int>();
    }
    (void)QueryP2pDevices(&clientDevices, msize, &retSize);
}

static void QueryP2pGroupsTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    WifiP2pGroupInfo groupInfo;
    int msize = 0;

    if (size > sizeof(WifiP2pGroupInfo)) {
        if (memcpy_s(groupInfo.passphrase, PASSPHRASE_LENGTH, data, PASSPHRASE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.interface, INTERFACE_LENGTH, data, INTERFACE_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.groupName, P2P_NAME_LENGTH, data, P2P_NAME_LENGTH - 1) != EOK) {
            return;
        }

        if (memcpy_s(groupInfo.goIpAddress, IP_ADDR_STR_LEN, data, IP_ADDR_STR_LEN - 1) != EOK) {
            return;
        }
        groupInfo.isP2pGroupOwner =  FDP.ConsumeIntegral<int>();
        groupInfo.networkId =  FDP.ConsumeIntegral<int>();
        groupInfo.frequency =  FDP.ConsumeIntegral<int>();
        groupInfo.isP2pPersistent =  FDP.ConsumeIntegral<int>();
        groupInfo.clientDevicesSize =  FDP.ConsumeIntegral<int>();
        msize = FDP.ConsumeIntegral<int>();
    }
    (void)QueryP2pGroups(&groupInfo, msize);
}

namespace OHOS {
namespace Wifi {
    bool WifiCP2PFuzzerTest(const uint8_t* data, size_t size)
    {
        (void)CheckCanUseP2p();
        (void)EnableP2p();
        (void)DisableP2p();
        (void)DiscoverDevices();
        (void)StopDiscoverDevices();
        (void)DiscoverServices();
        (void)StopDiscoverServices();
        (void)StopP2pListen();
        (void)RemoveGroup();
        (void)P2pCancelConnect();
        GetP2pEnableStatusTest(data, size);
        GStartP2pListenTest(data, size);
        CreateGroupTest(data, size);
        DeleteGroupTest(data, size);
        P2pConnectTest(data, size);
        GetCurrentGroupTest(data, size);
        GetP2pConnectedStatusTest(data, size);
        QueryP2pLocalDeviceTest(data, size);
        QueryP2pDevicesTest(data, size);
        QueryP2pGroupsTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCP2PFuzzerTest(data, size);
    return 0;
}

