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
#include "mock_wifi_hdi_wpa_ap_impl.h"

using namespace OHOS::Wifi;
static bool g_mockTag = false;
MockWifiHdiWpaApImpl &MockWifiHdiWpaApImpl::GetInstance()
{
    static MockWifiHdiWpaApImpl gMockWifiHdiWpaApImpl;
    return gMockWifiHdiWpaApImpl;
};

MockWifiHdiWpaApImpl::MockWifiHdiWpaApImpl() {}

void MockWifiHdiWpaApImpl::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool MockWifiHdiWpaApImpl::GetMockFlag(void)
{
    return g_mockTag;
}


#ifdef __cplusplus
extern "C" {
#endif
int __real_HdiSetApPasswd(const char *pass, int id);
int __wrap_HdiSetApPasswd(const char *pass, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApPasswd(pass, id);
    } else {
        return __real_HdiSetApPasswd(pass, id);
    }
}

int __real_HdiSetApName(const char *name, int id);
int __wrap_HdiSetApName(const char *name, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApName(name, id);
    } else {
        return __real_HdiSetApName(name, id);
    }
}

int __real_HdiSetApWpaValue(int securityType, int id);
int __wrap_HdiSetApWpaValue(int securityType, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApWpaValue(securityType, id);
    } else {
        return __real_HdiSetApWpaValue(securityType, id);
    }
}

int __real_HdiSetApBand(int band, int id);
int __wrap_HdiSetApBand(int band, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApBand(band, id);
    } else {
        return __real_HdiSetApBand(band, id);
    }
}

int __real_HdiSetApChannel(int channel, int id);
int __wrap_HdiSetApChannel(int channel, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApChannel(channel, id);
    } else {
        return __real_HdiSetApChannel(channel, id);
    }
}

int __real_HdiSetApMaxConn(int maxConn, int id);
int __wrap_HdiSetApMaxConn(int maxConn, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApMaxConn(maxConn, id);
    } else {
        return __real_HdiSetApMaxConn(maxConn, id);
    }
}

int __real_HdiSetAp80211n(int value, int id);
int __wrap_HdiSetAp80211n(int value, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetAp80211n(value, id);
    } else {
        return __real_HdiSetAp80211n(value, id);
    }
}

int __real_HdiSetApWmm(int value, int id);
int __wrap_HdiSetApWmm(int value, int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiSetApWmm(value, id);
    } else {
        return __real_HdiSetApWmm(value, id);
    }
}

int __real_HdiReloadApConfigInfo(int id);
int __wrap_HdiReloadApConfigInfo(int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiReloadApConfigInfo(id);
    } else {
        return __real_HdiReloadApConfigInfo(id);
    }
}

int __real_HdiDisableAp(int id);
int __wrap_HdiDisableAp(int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiDisableAp(id);
    } else {
        return __real_HdiDisableAp(id);
    }
}

int __real_HdiEnableAp(int id);
int __wrap_HdiEnableAp(int id)
{
    if (g_mockTag) {
        return MockWifiHdiWpaApImpl::GetInstance().HdiEnableAp(id);
    } else {
        return __real_HdiEnableAp(id);
    }
}
#ifdef __cplusplus
}
#endif