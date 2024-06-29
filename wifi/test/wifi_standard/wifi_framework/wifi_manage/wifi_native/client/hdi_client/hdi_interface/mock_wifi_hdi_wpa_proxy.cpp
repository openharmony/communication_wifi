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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "wifi_error_no.h"
#include "mock_wifi_hdi_wpa_proxy.h"

using namespace OHOS::Wifi;
static bool g_mockTag = false;
MockWifiHdiWpaProxy &MockWifiHdiWpaProxy::GetInstance()
{
    static MockWifiHdiWpaProxy gMockWifiHdiWpaProxy;
    return gMockWifiHdiWpaProxy;
};

MockWifiHdiWpaProxy::MockWifiHdiWpaProxy() {}

void MockWifiHdiWpaProxy::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool MockWifiHdiWpaProxy::GetMockFlag(void)
{
    return g_mockTag;
}


#ifdef __cplusplus
extern "C" {
#endif
int __real_IsHdiApStopped();
int __wrap_IsHdiApStopped()
{
    if (g_mockTag) {
        return MockWifiHdiWpaProxy::GetInstance().IsHdiApStopped();
    } else {
        return __real_IsHdiApStopped();
    }
}

int __real_HdiApStop(int id);
int __wrap_HdiApStop(int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaProxy::GetInstance().HdiApStop(id);
    } else {
        return __real_HdiApStop(id);
    }
}

#ifdef __cplusplus
}
#endif