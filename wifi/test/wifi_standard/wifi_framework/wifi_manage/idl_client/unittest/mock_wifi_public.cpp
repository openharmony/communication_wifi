/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mock_wifi_public.h"

using namespace OHOS::Wifi;

static bool g_mockTag = false;

MockWifiPublic &MockWifiPublic::GetInstance()
{
    static MockWifiPublic gMockWifiPublic;
    return gMockWifiPublic;
};

MockWifiPublic::MockWifiPublic()
{}

void MockWifiPublic::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool MockWifiPublic::GetMockFlag(void)
{
    return g_mockTag;
}

#ifdef __cplusplus
extern "C" {
#endif
int __real_RemoteCall(RpcClient *client);
int __wrap_RemoteCall(RpcClient *client)
{
    if (g_mockTag) {
        return MockWifiPublic::GetInstance().RemoteCall(client);
    } else {
        return __real_RemoteCall(client);
    }
}
#ifdef __cplusplus
}
#endif
