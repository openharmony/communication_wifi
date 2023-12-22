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
#include "i_wifi_iface.h"
#include "i_wifi_p2p_iface.h"
#include "i_wifi_sta_iface.h"
#include "i_wifi_supplicant_iface.h"
#include "i_wifi_hotspot_iface.h"
#include "wifi_idl_client.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
void OnIWifiTest(const uint8_t* data, size_t size)
{
    Start();
    Stop();
    NotifyClear();
}

void OnIWifiChipTest(const uint8_t* data, size_t size)
{
    bool isSupport = true;
    IsChipSupportDbdc(&isSupport);
    IsChipSupportCsa(&isSupport);
    IsChipSupportRadarDetect(&isSupport);
    IsChipSupportDfsChannel(&isSupport);
    IsChipSupportIndoorChannel(&isSupport);

    int32_t id = 1;
    GetChipId(&id);
    ConfigComboModes(id);
    GetComboModes(&id);
}

void OnIWifiIfaceTest(const uint8_t* data, size_t size)
{
    char ifname[] = "OHOS_wifi";
    int32_t datas = 0;
    GetName(ifname, datas);

    int32_t type = 0;
    GetType(&type);
}

void OnIWifiP2pIfaceTest(const uint8_t* data, size_t size)
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
    P2pAddNetwork(&datas);

    const char* chardata;
    P2pSetDeviceName(chardata);
    P2pSetSsidPostfixName(chardata);
    P2pSetWpsDeviceType(chardata);
    P2pSetWpsSecondaryDeviceType(chardata);
    P2pSetWpsConfigMethods(chardata);
    P2pSetWfdDeviceConfig(chardata);
    P2pRemoveGroup(chardata);
    P2pCancelServiceDiscovery(chardata);

    P2pSetGroupMaxIdle(chardata, datas);
    P2pSetPowerSave(chardata, datas);
    P2pProvisionDiscovery(chardata, datas);

    const char address[] = {0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    P2pSetupWpsPbc(chardata, address);

    char deviceAddress[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    P2pGetDeviceAddress(deviceAddress, datas);

    int data1 = 1;
    int data2 = 2;
    P2pSetExtListen(datas, data1, data2);
    P2pSetListenChannel(data1, data2);
    P2pAddGroup(datas, data1, data2);

    P2pReinvoke(datas, chardata);
}

void OnIWifiStaIfaceTest(const uint8_t* data, size_t size)
{
    SaveNetworkConfig();
    StopPnoScan();
    StopWps();
    WpaBlocklistClear();

    bool mode = false;
    SetSuspendMode(mode);
    SetPowerMode(mode);

    int networkId = 0;
    RemoveNetwork(networkId);
    AddNetwork(&networkId);
    EnableNetwork(networkId);
    DisableNetwork(networkId);
    WpaAutoConnect(networkId);
    GetScanInfos(&networkId);

    unsigned char mac[] = {0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    int lenmac = 6;
    GetDeviceMacAddress(mac, &lenmac);
    SetScanningMacAddress(mac, lenmac);
    DeauthLastRoamingBssid(mac, lenmac);

    const int porttype = 1;
    SetAssocMacAddr(mac, lenmac, porttype);
}

void OnIWifiSupplicantIfaceTest(const uint8_t* data, size_t size)
{
    StartSupplicant();
    StopSupplicant();
    ConnectSupplicant();
    DisconnectSupplicant();
    Reconnect();
    Reassociate();
    Disconnect();

    int networkId = 1;
    Connect(networkId);

    int enable = 1;
    SetPowerSave(enable);
}

void OnIWifiHotSpotIfaceTest(const uint8_t* data, size_t size)
{
    int id = 0;
    char ifaceName[] = "p2p0";
    StartSoftAp(id, ifaceName);
    StopSoftAp(id);

    int model = 1;
    WpaSetPowerModel(model, id);
    WpaGetPowerModel(&model, id);

    const char *code = "CN";
    SetCountryCode(code, id);

    unsigned char mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    int lenmac = 6;
    SetMacFilter(mac, lenmac, id);
    DelMacFilter(mac, lenmac, id);
    DisassociateSta(mac, lenmac, id);
}

void OnWifiIdlClientTest(const uint8_t* data, size_t size)
{
    WifiIdlClient wifiClient;
    wifiClient.ExitAllClient();
    wifiClient.StartWifi();
    wifiClient.StopWifi();
    wifiClient.ReqReconnect();
    wifiClient.ReqReassociate();
    wifiClient.ReqDisconnect();
    wifiClient.ReqStopPnoScan();
    wifiClient.ClearDeviceConfig();
    wifiClient.SaveDeviceConfig();
    wifiClient.ReqStopWps();
    wifiClient.ReqStartSupplicant();
    wifiClient.ReqStopSupplicant();
    wifiClient.ReqConnectSupplicant();
    wifiClient.ReqDisconnectSupplicant();
    wifiClient.ReqUnRegisterSupplicantEventCallback();
    wifiClient.ReqWpaBlocklistClear();
    wifiClient.ReqP2pStart();
    wifiClient.ReqP2pStop();
    wifiClient.ReqP2pStopFind();
    wifiClient.ReqP2pFlush();
    wifiClient.ReqP2pCancelConnect();
    wifiClient.ReqP2pFlushService();
    wifiClient.ReqP2pSaveConfig();

    int networkId = 1;
    wifiClient.ReqConnect(networkId);
    wifiClient.RemoveDevice(networkId);
    wifiClient.ReqEnableNetwork(networkId);
    wifiClient.ReqDisableNetwork(networkId);
    wifiClient.ReqP2pRemoveNetwork(networkId);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    OnIWifiTest(data, size);
    OnIWifiChipTest(data, size);
    OnIWifiIfaceTest(data, size);
    OnIWifiP2pIfaceTest(data, size);
    OnIWifiStaIfaceTest(data, size);
    OnIWifiSupplicantIfaceTest(data, size);
    OnIWifiHotSpotIfaceTest(data, size);
    OnWifiIdlClientTest(data, size);
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