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

#include "wifiidlclient_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>

#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "i_wifi.h"
#include "i_wifi_chip.h"
#include "i_wifi_p2p_iface.h"
#include "i_wifi_sta_iface.h"
#include "i_wifi_supplicant_iface.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
void OnSupportedTest_IWifi(const uint8_t* data, size_t size)
{
    Start();
    Stop();
    NotifyClear();
}

void OnSupportedTest_IWifiChip(const uint8_t* data, size_t size)
{
    bool isSupport;
    IsChipSupportDbdc(&isSupport);
    IsChipSupportCsa(&isSupport);
    IsChipSupportRadarDetect(&isSupport);
    IsChipSupportDfsChannel(&isSupport);
    IsChipSupportIndoorChannel(&isSupport);

    int32_t id;
    GetChipId(&id);
    GetComboModes(&id);
}

void OnSupportedTest_IWifiP2pIface(const uint8_t* data, size_t size)
{
    P2pStart();
    P2pStop();
    P2pFlush();
    P2pFlushService();
    P2pSaveConfig();
    P2pStopFind();
    P2pCancelConnect();

    int datas = 0;
    P2pSetRandomMac(datas);
    P2pRemoveNetwork(datas);
    P2pSetWfdEnable(datas);
    P2pStartFind(datas);
    P2pSetMiracastType(datas);
    P2pSetPersistentReconnect(datas);
    P2pSetServDiscExternal(datas);

    const char* chardata;
    P2pSetDeviceName(chardata);
    P2pSetSsidPostfixName(chardata);
    P2pSetWpaDeviceType(chardata);
    P2pSetWpsSecondaryDeviceType(chardata);
    P2pSetWpaConfigMethods(chardata);
    P2pSetWfdDeviceConfig(chardata);
    P2pRemoveGroup(chardata);
    P2pCancelServiceDiscovery(chardata);

    P2pSetGroupMaxIdle(chardata, datas);
    P2pSetPowerSave(chardata, datas);
    P2pProvisionDiscovery(chardata, datas);

    P2pReinvoke(datas, chardata);
}

void OnSupportedTest_IWifiStaIface(const uint8_t* data, size_t size)
{
    SaveNetworkConfig();
    StopPnoScan();
    StopWps();
    WpaBlocklistClear();
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    StartSupplicant();
    StopSupplicant();
    ConnectSupplicant();
    DisconnectSupplicant();
    Reconnect();
    Reassociate();
    Disconnect();

    OnSupportedTest_IWifi(data, size);
    OnSupportedTest_IWifiChip(data, size);
    OnSupportedTest_IWifiP2pIface(data, size);
    OnSupportedTest_IWifiStaIface(data, size);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
}