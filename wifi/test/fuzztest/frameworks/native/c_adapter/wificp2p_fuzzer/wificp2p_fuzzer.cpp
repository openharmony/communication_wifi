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
#include "../../../../../../interfaces/kits/c/wifi_p2p.h"

static void GetP2pEnableStatusTest(const uint8_t* data, size_t size)
{
    P2pState state = P2P_STATE_NONE;
    if (size > 0) {
        int temp = static_cast<int>(data[0]) % P2P_STATE_CLOSED;
        state = static_cast<P2pState>(temp);
    }
    (void)GetP2pEnableStatus(&state);
}

static void GStartP2pListenTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int period = 0;
    int interval = 0;

    if (index >= TWO) {
        period = static_cast<int>(data[index++]);
        interval = static_cast<int>(data[index++]);
    }
    (void)StartP2pListen(period, interval);
}

static void CreateGroupTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        config.netId = static_cast<int>(OHOS::Wifi::U32_AT(data));
        config.groupOwnerIntent = static_cast<int>(data[index++]);
        config.goBand = GO_BAND_AUTO;
    }
    (void)CreateGroup(&config);
}

static void DeleteGroupTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        group.isP2pGroupOwner = static_cast<int>(data[index++]);
        group.networkId = static_cast<int>(data[index++]);
        group.frequency = static_cast<int>(data[index++]);
        group.isP2pPersistent = static_cast<int>(data[index++]);
        group.clientDevicesSize = static_cast<int>(data[index++]);
    }
    (void)DeleteGroup(&group);
}

static void P2pConnectTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        config.netId = static_cast<int>(OHOS::Wifi::U32_AT(data));
        config.groupOwnerIntent = static_cast<int>(data[index++]);
        config.goBand = GO_BAND_AUTO;
    }
    (void)P2pConnect(&config);
}

static void GetCurrentGroupTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        groupInfo.isP2pGroupOwner = static_cast<int>(data[index++]);
        groupInfo.networkId = static_cast<int>(data[index++]);
        groupInfo.frequency = static_cast<int>(data[index++]);
        groupInfo.isP2pPersistent = static_cast<int>(data[index++]);
        groupInfo.clientDevicesSize = static_cast<int>(data[index++]);
    }
    (void)GetCurrentGroup(&groupInfo);
}

static void GetP2pConnectedStatusTest(const uint8_t* data, size_t size)
{
    int status = static_cast<int>(data[0]);
    (void)GetP2pConnectedStatus(&status);
}

static void QueryP2pLocalDeviceTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        deviceInfo.status = static_cast<P2pDeviceStatus>(static_cast<int>(data[index++]) % PDS_UNAVAILABLE);
        deviceInfo.wfdInfo.wfdEnabled = static_cast<int>(data[index++]);
        deviceInfo.wfdInfo.deviceInfo = static_cast<int>(data[index++]);
        deviceInfo.wfdInfo.ctrlPort = static_cast<int>(data[index++]);
        deviceInfo.wfdInfo.maxThroughput = static_cast<int>(data[index++]);
        deviceInfo.supportWpsConfigMethods = static_cast<unsigned int>(data[index++]);
        deviceInfo.deviceCapabilitys = static_cast<int>(data[index++]);
        deviceInfo.groupCapabilitys = static_cast<int>(data[index++]);
    }
    (void)QueryP2pLocalDevice(&deviceInfo);
}

static void QueryP2pDevicesTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        clientDevices.status = static_cast<P2pDeviceStatus>(static_cast<int>(data[index++]) % PDS_UNAVAILABLE);
        clientDevices.wfdInfo.wfdEnabled = static_cast<int>(data[index++]);
        clientDevices.wfdInfo.deviceInfo = static_cast<int>(data[index++]);
        clientDevices.wfdInfo.ctrlPort = static_cast<int>(data[index++]);
        clientDevices.wfdInfo.maxThroughput = static_cast<int>(data[index++]);
        clientDevices.supportWpsConfigMethods = static_cast<unsigned int>(data[index++]);
        clientDevices.deviceCapabilitys = static_cast<int>(data[index++]);
        clientDevices.groupCapabilitys = static_cast<int>(data[index++]);
        msize = static_cast<int>(data[index++]);
    }
    (void)QueryP2pDevices(&clientDevices, msize, &retSize);
}

static void QueryP2pGroupsTest(const uint8_t* data, size_t size)
{
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
        int index = 0;
        groupInfo.isP2pGroupOwner =  static_cast<int>(data[index++]);
        groupInfo.networkId =  static_cast<int>(data[index++]);
        groupInfo.frequency =  static_cast<int>(data[index++]);
        groupInfo.isP2pPersistent =  static_cast<int>(data[index++]);
        groupInfo.clientDevicesSize =  static_cast<int>(data[index++]);
        msize = static_cast<int>(data[0]);
    }
    (void)QueryP2pGroups(&groupInfo, msize);
}


namespace OHOS {
namespace Wifi {
    bool WifiCP2PFuzzerTest(const uint8_t* data, size_t size)
    {
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

