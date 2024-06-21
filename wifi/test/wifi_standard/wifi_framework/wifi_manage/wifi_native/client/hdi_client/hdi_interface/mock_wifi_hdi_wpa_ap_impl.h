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

#ifndef MOCK_WIFI_HDI_WPA_AP_IMPL_H
#define MOCK_WIFI_HDI_WPA_AP_IMPL_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_hdi_wpa_ap_impl.h"

namespace OHOS {
namespace Wifi {
class MockWifiHdiWpaApImpl {
public:
    MOCK_METHOD2(HdiSetApPasswd, WifiErrorNo(const char *pass, int id));
    MOCK_METHOD2(HdiSetApName, WifiErrorNo(const char *name, int id));
    MOCK_METHOD2(HdiSetApWpaValue, WifiErrorNo(int securityType, int id));
    MOCK_METHOD2(HdiSetApBand, WifiErrorNo(int band, int id));
    MOCK_METHOD2(HdiSetApChannel, WifiErrorNo(int channel, int id));
    MOCK_METHOD2(HdiSetApMaxConn, WifiErrorNo(int maxConn, int id));
    MOCK_METHOD2(HdiSetAp80211n, WifiErrorNo(int value, int id));
    MOCK_METHOD2(HdiSetApWmm, WifiErrorNo(int value, int id));
    MOCK_METHOD1(HdiReloadApConfigInfo, WifiErrorNo(int id));
    MOCK_METHOD1(HdiDisableAp, WifiErrorNo(int id));

    static MockWifiHdiWpaApImpl &GetInstance(void);
    static void SetMockFlag(bool flag);
    static bool GetMockFlag(void);

private:
    MockWifiHdiWpaApImpl();
    ~MockWifiHdiWpaApImpl() {}
};
} // namespace OHOS
} // namespace Wifi

extern "C" {}

#endif // MOCK_WIFI_HDI_WPA_AP_IMPL_H