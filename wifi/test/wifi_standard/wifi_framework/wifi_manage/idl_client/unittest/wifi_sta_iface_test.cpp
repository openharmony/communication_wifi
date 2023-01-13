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
#include "../../../services/wifi_standard/wifi_framework/wifi_manage/idl_client/idl_interface/i_wifi_sta_iface.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define CAPABILITIES 1
#define LENMAC 5
#define BANDSIZE 5
#define SIZE 5
#define FREQUENCIES 5
#define LONGNUM 10
#define CMDID 1
#define POWER 1
#define NETWORK 1
#define EVENTS 1
#define PINCODE 5
#define NUM 1

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiStaIfaceTest : public testing::Test{
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};
	
    void GetStaCapabilitiesTest()
    {
        int32_t capabilities = CAPABILITIES;
        GetStaCapabilities(capabilities);
    }

    void GetDeviceMacAddressTest()
    {
        char* reulat;
        int lenMac = LENMAC;
        if (strcpy_s(reulat, sizeof(reulat), "GetDeviceMacAddress") != EOK) {
            return;
        }
        GetDeviceMacAddress((unsigned char *)reulat, lenMac);
    }

    void GetFrequenciesTest()
    {
        int32_t band = BANDSIZE;
        int32_t size = SIZE;
        int* frequencies = FREQUENCIES;
        GetFrequencies(band, size, frequencies);
    }

    void SetAssocMacAddrTest()
    {
        char* reulat;
        int lenMac = LENMAC;
        if (strcpy_s(reulat, sizeof(reulat), "SetAssocMacAddr") != EOK) {
            return;
        }
        SetAssocMacAddr((unsigned char *)reulat, lenMac);
    }

    void SetScanningMacAddressTest()
    {
        char* reulat;
        int lenMac = LENMAC;
        if (strcpy_s(reulat, sizeof(reulat), "SetScanningMacAddress") != EOK) {
            return;
        }
        SetScanningMacAddress((unsigned char *)reulat, lenMac)
    }

    void DeauthLastRoamingBssidTest()
    {
        char* reulat;
        int lenMac = LENMAC;
        if (strcpy_s(reulat, sizeof(reulat), "DeauthLastRoamingBssid") != EOK) {
            return;
        }
        DeauthLastRoamingBssid((unsigned char *)reulat, lenMac);
    }

    void GetSupportFeatureTest()
    {
        long* feature = LONGNUM;
        GetSupportFeature(feature);
    }

    void RunCmdTest()
    {
        char *ifname;
        int32_t cmdId = CMDID;
        char * buf;
        int32_t bufSize = BANDSIZE;
        if (strcpy_s(ifname, sizeof(ifname), "RunCmd") != EOK) {
            return;
        }
        if (strcpy_s(buf, sizeof(buf), "RunCmd") != EOK) {
            return;
        }
        RunCmd(ifname, cmdId, (unsigned char *)buf, bufSize);
    }

    void SetWifiTxPowerTest()
    {
        int32_t power = POWER;
        SetWifiTxPower(power);
    }

    void RemoveNetworkTest()
    {
        int networkId = NETWORK;
        RemoveNetwork(networkId);
    }

    void AddNetworkTest()
    {
        int* networkId = NETWORK;
        AddNetwork(networkId);
    }
	
    void EnableNetworkTest()
    {
        int networkId = NETWORK;
        EnableNetwork(networkId);
    }
		
    void DisableNetworkTest()
    {
        int networkId = NETWORK;
        DisableNetwork(networkId);
    }

    void SetNetworkTest()
    {
        int networkId = NETWORK;
        SetNetworkConfig *confs;
        if (strcpy_s(confs->cfgValue, sizeof(confs->cfgValue), "SetNetwork") != EOK) {
            return;
        }
        int size = SIZE;
        SetNetwork(networkId, confs, size);
    }

    void WpaGetNetworkTest()
    {
        GetNetworkConfig *confs;
        confs->networkId = NETWORK;
        if (strcpy_s(confs->param, sizeof(confs->param), "WpaGetNetwork") != EOK) {
            return;
        }
        if (strcpy_s(confs->value, sizeof(confs->value), "WpaGetNetwork") != EOK) {
            return;
        }

        WpaGetNetwork(confs);
    }

    void SaveNetworkConfigTest()
    {
        SaveNetworkConfig()
    }

    void StartScanTest()
    {
        ScanSettings *settings;
        settings->freqs = NUM;
        settings->freqSize = SIZE;
        settings->hiddenSsidSize = SIZE;
        StartScan(settings);
    }

    void GetNetworkListTest()
    {
        int *size = SIZE;
        WifiNetworkInfo *infos;
        infos->id = NUM;
        if (strcpy_s(infos->ssid, sizeof(infos->ssid), "GetNetworkList") != EOK) {
            return;
        }
        if (strcpy_s(infos->bssid, sizeof(infos->bssid), "GetNetworkList") != EOK) {
            return;
        }
        if (strcpy_s(infos->flags, sizeof(infos->flags), "GetNetworkList") != EOK) {
            return;
        }

        GetNetworkList(infos, size);
    }

    void GetScanInfoElemsTest()
    {
        Context *context;
        ScanInfo* scanInfo;
        context->fd = NUM;
        context->rBegin = NUM;
        context->nPos = NUM;
        context->nSize = SIZE;
        scanInfo->freq = NUM;
        scanInfo->antValue = NUM;
        scanInfo->associated = NUM;
        scanInfo->centerFrequency0 = NUM;
        if (strcpy_s(context->szRead, sizeof(context->szRead), "GetScanInfoElems") != EOK) {
            return;
        }
        if (strcpy_s(scanInfo->ssid, sizeof(scanInfo->ssid), "GetScanInfoElems") != EOK) {
            return;
        }
        if (strcpy_s(scanInfo->bssid, sizeof(scanInfo->bssid), "GetScanInfoElems") != EOK) {
            return;
        }

        GetScanInfoElems(context. scanInfo);
    }

    void GetScanInfosTest()
    {
        int* size = SIZE;
        GetScanInfos(size);
    }

    VOID StartPnoScanTest()
    {
        PnoScanSettings *settings;
        settings->freqSize = NUM;
        settings->freqs = nullptr;
        settings->hiddenSsidSize = NUM;
        settings->minRssi5Ghz = NUM;
        settings->minRssi2Dot4Ghz = NUM;
        if (strcpy_s(settings->hiddenSsid, sizeof(settings->hiddenSsid), "StartPnoScan") != EOK) {
            return;
        }
        StartPnoScan(settings);
    }

    void StopPnoScanTest()
    {
        StopPnoScan();
    }

    void CheckRegisterEventTest()
    {
        int *events = EVENTS;
        int size = SIZE;
        CheckRegisterEvent(events, size);
    }

    void RegisterStaEventCallbackTest()
    {
        IWifiEventCallback callback;
        if (strcpy_s(callback, sizeof(callback), "RegisterStaEventCallback") != EOK) {
            return;
        }
       RegisterStaEventCallback(callback);
    }

    void StartWpsPbcModeTest()
    {
        WifiWpsParam *param;
        param->anyFlag = NUM;
        param->multiAp = NUM;
        if (strcpy_s(param->bssid, sizeof(param->bssid), "StartWpsPinMode") != EOK) {
            return;
        }
        if (strcpy_s(param->pinCode, sizeof(param->bssid), "StartWpsPinMode") != EOK) {
            return;
        }
        StartWpsPbcMode(param);
    }

    void StartWpsPinModeTest()
    {
        WifiWpsParam *param;
        param->anyFlag = NUM;
        param->multiAp = NUM;
        if (strcpy_s(param->bssid, sizeof(param->bssid), "StartWpsPinMode") != EOK) {
            return;
        }
        if (strcpy_s(param->pinCode, sizeof(param->bssid), "StartWpsPinMode") != EOK) {
            return;
        }
		int *pinCode = PINCODE;
        StartWpsPinMode(param, pinCode);
    }

    void StopWpsTest()
    {
        StopWps();
    }

    void GetRoamingCapabilitiesTest()
    {
        WifiRoamCapability *capability ;
        capability->maxBlocklistSize = SIZE;
        capability->maxTrustlistSize = SIZE;
        GetRoamingCapabilities(capability);
    }

    void SetRoamConfigTest()
    {
        char *one = nullptr;
        one = "123456";
        char *blocklist = &one;
        int blocksize = SIZE;
        char *trustlist = &one;
        int trustsize = SIZE;
        SetRoamConfig(blocklist, blocksize, trustlist, trustsize);
    }

    void WpaAutoConnectTest()
    {
        int enable = NUM;
        WpaAutoConnect(enable);
    }

    void WpaBlocklistClearTest()
    {
        WpaBlocklistClear()
    }

    void GetConnectSignalInfoTest()
    {
        char* endBssid;
        WpaSignalInfo *info;
        if (strcpy_s(endBssid, sizeof(endBssid), "StartWpsPinMode") != EOK) {
            return;
        }
        info->frequency = NUM;
        info->noise = NUM;
        info->rxrate= NUM;
        info->signal = NUM;
        info->txrate = NUM;
        GetConnectSignalInfo(endBssid, info);
    }

    void SetSuspendModeTest()
    {
        bool mode = true;
        SetSuspendMode(mode);
    }
};

HWTEST_F(WifiStaIfaceTest, GetStaCapabilitiesTest, TestSize.Level1)
{
    GetStaCapabilitiesTest();
}

HWTEST_F(WifiStaIfaceTest, GetDeviceMacAddressTest, TestSize.Level1)
{
    GetDeviceMacAddressTest();
}

HWTEST_F(WifiStaIfaceTest, GetFrequenciesTest, TestSize.Level1)
{
    GetFrequenciesTest();
}

HWTEST_F(WifiStaIfaceTest, SetAssocMacAddrTest, TestSize.Level1)
{
    SetAssocMacAddrTest();
}

HWTEST_F(WifiStaIfaceTest, SetScanningMacAddressTest, TestSize.Level1)
{
    SetScanningMacAddressTest();
}

HWTEST_F(WifiStaIfaceTest, DeauthLastRoamingBssidTest, TestSize.Level1)
{
    DeauthLastRoamingBssidTest();
}

HWTEST_F(WifiStaIfaceTest, GetSupportFeatureTest, TestSize.Level1)
{
    GetSupportFeatureTest();
}

HWTEST_F(WifiStaIfaceTest, RunCmdTest, TestSize.Level1)
{
    RunCmdTest();
}

HWTEST_F(WifiStaIfaceTest, SetWifiTxPowerTest, TestSize.Level1)
{
    SetWifiTxPowerTest();
}

HWTEST_F(WifiStaIfaceTest, RemoveNetworkTest, TestSize.Level1)
{
    RemoveNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, AddNetworkTest, TestSize.Level1)
{
    AddNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, EnableNetworkTest, TestSize.Level1)
{
    EnableNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, DisableNetworkTest, TestSize.Level1)
{
    DisableNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, SetNetworkTest, TestSize.Level1)
{
    SetNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, WpaGetNetworkTest, TestSize.Level1)
{
    WpaGetNetworkTest();
}

HWTEST_F(WifiStaIfaceTest, SaveNetworkConfigTest, TestSize.Level1)
{
    SaveNetworkConfigTest();
}

HWTEST_F(WifiStaIfaceTest, StartScanTest, TestSize.Level1)
{
    StartScanTest();
}

HWTEST_F(WifiStaIfaceTest, GetNetworkListTest, TestSize.Level1)
{
    GetNetworkListTest();
}

HWTEST_F(WifiStaIfaceTest, GetScanInfoElemsTest, TestSize.Level1)
{
    GetScanInfoElemsTest();
}

HWTEST_F(WifiStaIfaceTest, GetScanInfosTest, TestSize.Level1)
{
    GetScanInfosTest();
}

HWTEST_F(WifiStaIfaceTest, StartPnoScanTest, TestSize.Level1)
{
    StartPnoScanTest();
}

HWTEST_F(WifiStaIfaceTest, StopPnoScanTest, TestSize.Level1)
{
    StopPnoScanTest();
}

HWTEST_F(WifiStaIfaceTest, CheckRegisterEventTest, TestSize.Level1)
{
    CheckRegisterEventTest();
}

HWTEST_F(WifiStaIfaceTest, RegisterStaEventCallbackTest, TestSize.Level1)
{
    RegisterStaEventCallbackTest();
}

HWTEST_F(WifiStaIfaceTest, StartWpsPbcModeTest, TestSize.Level1)
{
    StartWpsPbcModeTest();
}

HWTEST_F(WifiStaIfaceTest, StartWpsPinModeTest, TestSize.Level1)
{
    StartWpsPinModeTest();
}

HWTEST_F(WifiStaIfaceTest, StopWpsTest, TestSize.Level1)
{
    StopWpsTest();
}

HWTEST_F(WifiStaIfaceTest, GetRoamingCapabilitiesTest, TestSize.Level1)
{
    GetRoamingCapabilitiesTest();
}

HWTEST_F(WifiStaIfaceTest, SetRoamConfigTest, TestSize.Level1)
{
    SetRoamConfigTest();
}

HWTEST_F(WifiStaIfaceTest, WpaAutoConnectTest, TestSize.Level1)
{
    WpaAutoConnectTest();
}

HWTEST_F(WifiStaIfaceTest, WpaBlocklistClearTest, TestSize.Level1)
{
    WpaBlocklistClearTest();
}

HWTEST_F(WifiStaIfaceTest, GetConnectSignalInfoTest, TestSize.Level1)
{
    GetConnectSignalInfoTest();
}

HWTEST_F(WifiStaIfaceTest, SetSuspendModeTest, TestSize.Level1)
{
    SetSuspendModeTest();
}


}  // namespace Wifi
}  // namespace OHOS
