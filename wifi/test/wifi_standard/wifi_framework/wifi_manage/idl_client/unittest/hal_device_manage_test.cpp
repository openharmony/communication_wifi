/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage_test.h"
#include "hal_device_manage.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
void WifiHalDeviceManagerTest::DestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    return;
}

HWTEST_F(WifiHalDeviceManagerTest, StartChipHdiTest, TestSize.Level1)
{
    DelayedSingleton<HalDeviceManager>::GetInstance()->StartChipHdi();
}

HWTEST_F(WifiHalDeviceManagerTest, StopChipHdiTest, TestSize.Level1)
{
    DelayedSingleton<HalDeviceManager>::GetInstance()->StopChipHdi();
}

HWTEST_F(WifiHalDeviceManagerTest, CreateStaIfaceTest, TestSize.Level1)
{
    std::string ifaceName;
    DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(WifiHalDeviceManagerTest::DestoryCallback, std::placeholders::_1, std::placeholders::_2), ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, CreateApIfaceTest, TestSize.Level1)
{
    std::string ifaceName;
    DelayedSingleton<HalDeviceManager>::GetInstance()->CreateApIface(
        std::bind(WifiHalDeviceManagerTest::DestoryCallback, std::placeholders::_1, std::placeholders::_2), ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, CreateP2pIfaceTest, TestSize.Level1)
{
    std::string ifaceName;
    DelayedSingleton<HalDeviceManager>::GetInstance()->CreateP2pIface(
        std::bind(WifiHalDeviceManagerTest::DestoryCallback, std::placeholders::_1, std::placeholders::_2), ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, RemoveStaIfaceTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveStaIface(ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, RemoveApIfaceTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveApIface(ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, RemoveP2pIfaceTest, TestSize.Level1)
{
    std::string ifaceName{"p2p0"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveP2pIface(ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, ScanTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    ScanParams scanParams;
    DelayedSingleton<HalDeviceManager>::GetInstance()->Scan(ifaceName, scanParams);
}

HWTEST_F(WifiHalDeviceManagerTest, StartPnoScanTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    PnoScanParams pnoScanParams;
    DelayedSingleton<HalDeviceManager>::GetInstance()->StartPnoScan(ifaceName, pnoScanParams);
}

HWTEST_F(WifiHalDeviceManagerTest, StopPnoScanTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->StopPnoScan(ifaceName);
}

HWTEST_F(WifiHalDeviceManagerTest, GetScanInfosTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    std::vector<ScanResultsInfo> scanResultsInfo;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetScanInfos(ifaceName, scanResultsInfo);
}

HWTEST_F(WifiHalDeviceManagerTest, GetConnectSignalInfoTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    SignalPollResult signalPollResult;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetConnectSignalInfo(ifaceName, signalPollResult);
}

HWTEST_F(WifiHalDeviceManagerTest, SetPmModeTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int mode = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetPmMode(ifaceName, mode);
}

HWTEST_F(WifiHalDeviceManagerTest, SetDpiMarkRuleTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int uid = 0;
    int protocol = 0;
    int enable = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetDpiMarkRule(ifaceName, uid, protocol, enable);
}

HWTEST_F(WifiHalDeviceManagerTest, SetStaMacAddressTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    std::string mac{"12:34:56:78:90"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetStaMacAddress(ifaceName, mac);
}

HWTEST_F(WifiHalDeviceManagerTest, SetNetworkUpDownTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    bool upDown = true;
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetNetworkUpDown(ifaceName, upDown);
}

HWTEST_F(WifiHalDeviceManagerTest, GetChipsetCategoryTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int chipsetCategory = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetChipsetCategory(ifaceName, chipsetCategory);
}

HWTEST_F(WifiHalDeviceManagerTest, GetChipsetWifiFeatrureCapabilityTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int chipsetFeatrureCapability = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetChipsetWifiFeatrureCapability(
        ifaceName, chipsetFeatrureCapability);
}

HWTEST_F(WifiHalDeviceManagerTest, GetFrequenciesByBandTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int32_t band = 0;
    std::vector<int> frequencies;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetFrequenciesByBand(ifaceName, band, frequencies);
}

HWTEST_F(WifiHalDeviceManagerTest, SetPowerModelTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int model = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetPowerModel(ifaceName, model);
}

HWTEST_F(WifiHalDeviceManagerTest, GetPowerModelTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    int model = 0;
    DelayedSingleton<HalDeviceManager>::GetInstance()->GetPowerModel(ifaceName, model);
}

HWTEST_F(WifiHalDeviceManagerTest, SetWifiCountryCodeTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    std::string code{"ZH"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetWifiCountryCode(ifaceName, code);
}

HWTEST_F(WifiHalDeviceManagerTest, SetApMacAddressTest, TestSize.Level1)
{
    std::string ifaceName{"wlan0"};
    std::string mac{"12:34:56:78:90"};
    DelayedSingleton<HalDeviceManager>::GetInstance()->SetApMacAddress(ifaceName, mac);
}

}  // namespace Wifi
}  // namespace OHOS
#endif