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

}  // namespace Wifi
}  // namespace OHOS
#endif