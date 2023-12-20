/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_HAL_ADAPTER_TEST_H
#define OHOS_WIFI_HAL_ADAPTER_TEST_H

#include <gtest/gtest.h>
#include "wifi_hal_adapter.h"
#include "wifi_hal_vendor_interface.h"
#include "securec.h"
#include "wifi_common_def.h"
#include "wifi_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
class WifiHalAdapterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};
HWTEST_F(WifiHalAdapterTest, ReleaseWifiHalVendorInterfaceTest, TestSize.Level1)
{
    ReleaseWifiHalVendorInterface();
    WifiHalVendorInterface *g_wifiHalVendorInterface = GetWifiHalVendorInterface();
    ReleaseWifiHalVendorInterface();
    EXPECT_TRUE(g_wifiHalVendorInterface != NULL);
}
}  // namespace Wifi
}  // namespace OHOS
#endif