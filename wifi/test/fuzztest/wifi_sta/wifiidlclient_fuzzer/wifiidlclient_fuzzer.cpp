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
#include "i_wifi_sta_iface.h"
#include "i_wifi_supplicant_iface.h"
#include "wifi_idl_client.h"
#include "wifi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
void OnIWifiTest()
{
    Start();
    Stop();
    NotifyClear();
}

void OnIWifiChipTest(FuzzedDataProvider& FDP)
{
    bool isSupport = FDP.ConsumeBool();
    IsChipSupportDbdc(&isSupport);
    IsChipSupportCsa(&isSupport);
    IsChipSupportRadarDetect(&isSupport);
    IsChipSupportDfsChannel(&isSupport);
    IsChipSupportIndoorChannel(&isSupport);

    int32_t id = FDP.ConsumeIntegral<int32_t>();
    GetChipId(&id);
    ConfigComboModes(id);
    GetComboModes(&id);
}

void OnIWifiIfaceTest(FuzzedDataProvider& FDP)
{
    char ifname[] = "OHOS_wifi";
    int32_t datas = FDP.ConsumeIntegral<int32_t>();
    GetName(ifname, datas);

    int32_t type =FDP.ConsumeIntegral<int32_t>();
    GetType(&type);
}

void OnIWifiP2pIfaceTest(FuzzedDataProvider& FDP)
{
    P2pStart();
    P2pStop();
    P2pFlush();
    P2pFlushService();
    P2pSaveConfig();
    P2pStopFind();
    P2pCancelConnect();

    int datas = FDP.ConsumeIntegral<int>();
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

    int data1 = FDP.ConsumeIntegral<int>();
    int data2 = FDP.ConsumeIntegral<int>();
    P2pSetExtListen(datas, data1, data2);
    P2pSetListenChannel(data1, data2);
    P2pAddGroup(datas, data1, data2);

    P2pReinvoke(datas, chardata);
}

void OnIWifiStaIfaceTest(FuzzedDataProvider& FDP)
{
    SaveNetworkConfig();
    StopPnoScan();
    StopWps();
    WpaBlocklistClear();

    bool mode = FDP.ConsumeBool();
    SetSuspendMode(mode);
    SetPowerMode(mode);

    int networkId = FDP.ConsumeIntegral<int>();
    RemoveNetwork(networkId);
    AddNetwork(&networkId);
    EnableNetwork(networkId);
    DisableNetwork(networkId);
    WpaAutoConnect(networkId);
    GetScanInfos(&networkId);

    unsigned char mac[] = {0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    int lenmac = FDP.ConsumeIntegral<int>();
    GetDeviceMacAddress(mac, &lenmac);
    SetScanningMacAddress(mac, lenmac);
    DeauthLastRoamingBssid(mac, lenmac);

    const int porttype = FDP.ConsumeIntegral<int>();
    SetAssocMacAddr(mac, lenmac, porttype);
}

void OnIWifiSupplicantIfaceTest(FuzzedDataProvider& FDP)
{
    StartSupplicant();
    StopSupplicant();
    ConnectSupplicant();
    DisconnectSupplicant();
    Reconnect();
    Reassociate();
    Disconnect();

    int networkId = FDP.ConsumeIntegral<int>();
    Connect(networkId);

    int enable = FDP.ConsumeIntegral<int>();
    SetPowerSave(enable);
}

void OnIWifiHotSpotIfaceTest(FuzzedDataProvider& FDP)
{
    int id = FDP.ConsumeIntegral<int>();
    char ifaceName[] = "p2p0";
    StartSoftAp(id, ifaceName);
    StopSoftAp(id);

    int model = FDP.ConsumeIntegral<int>();
    WpaSetPowerModel(model, id);
    WpaGetPowerModel(&model, id);

    const char *code = "CN";
    SetCountryCode(code, id);

    unsigned char mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    int lenmac = FDP.ConsumeIntegral<int>(); 
    SetMacFilter(mac, lenmac, id);
    DelMacFilter(mac, lenmac, id);
    DisassociateSta(mac, lenmac, id);
}

void OnWifiIdlClientTest(FuzzedDataProvider& FDP)
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

    int networkId = FDP.ConsumeIntegral<int>();
    wifiClient.ReqConnect(networkId);
    wifiClient.RemoveDevice(networkId);
    wifiClient.ReqEnableNetwork(networkId);
    wifiClient.ReqDisableNetwork(networkId);
    wifiClient.ReqP2pRemoveNetwork(networkId);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider& FDP)
{
    FuzzedDataProvider FDP(data, size);
    OnIWifiTest();
    OnIWifiChipTest(FDP);
    OnIWifiIfaceTest(FDP);
    OnIWifiP2pIfaceTest(FDP);
    OnIWifiStaIfaceTest(FDP);
    OnIWifiSupplicantIfaceTest(FDP);
    OnIWifiHotSpotIfaceTest(FDP);
    OnWifiIdlClientTest(FDP);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(FDP);
    return 0;
}
}
}