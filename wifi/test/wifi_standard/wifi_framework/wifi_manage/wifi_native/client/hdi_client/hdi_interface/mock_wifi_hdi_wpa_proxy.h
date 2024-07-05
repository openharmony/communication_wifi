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

#ifndef MOCK_WIFI_HDI_WPA_PROXY_H
#define MOCK_WIFI_HDI_WPA_PROXY_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_hdi_wpa_proxy.h"
#include "wifi_hdi_wpa_sta_impl.h"

namespace OHOS {
namespace Wifi {
class MockWifiHdiWpaProxy {
public:
    MOCK_METHOD1(HdiApStop, WifiErrorNo(int id));
    MOCK_METHOD0(IsHdiApStopped, WifiErrorNo());

    static MockWifiHdiWpaProxy &GetInstance(void);
    static void SetMockFlag(bool flag);
    static bool GetMockFlag(void);

private:
    MockWifiHdiWpaProxy();
    ~MockWifiHdiWpaProxy() {}
};
} // namespace OHOS
} // namespace Wifi

extern "C" {}

#endif // MOCK_WIFI_HDI_WPA_PROXY_H