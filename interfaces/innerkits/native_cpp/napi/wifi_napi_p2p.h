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

#ifndef WIFI_NAPI_P2P_H_
#define WIFI_NAPI_P2P_H_

#include "wifi_napi_utils.h"
#include "wifi_p2p.h"

namespace OHOS {
namespace Wifi {
napi_value EnableP2p(napi_env env, napi_callback_info info);
napi_value DisableP2p(napi_env env, napi_callback_info info);
napi_value GetP2pLinkedInfo(napi_env env, napi_callback_info info);
napi_value GetCurrentGroup(napi_env env, napi_callback_info info);
napi_value GetP2pDevices(napi_env env, napi_callback_info info);
napi_value CreateGroup(napi_env env, napi_callback_info info);
napi_value RemoveGroup(napi_env env, napi_callback_info info);
napi_value P2pConnect(napi_env env, napi_callback_info info);
napi_value P2pDisConnect(napi_env env, napi_callback_info info);
napi_value StartDiscoverDevices(napi_env env, napi_callback_info info);
napi_value StopDiscoverDevices(napi_env env, napi_callback_info info);
napi_value StartP2pListen(napi_env env, napi_callback_info info);
napi_value StopP2pListen(napi_env env, napi_callback_info info);
napi_value DeletePersistentGroup(napi_env env, napi_callback_info info);
napi_value SetP2pDeviceName(napi_env env, napi_callback_info info);

class QueryP2pDeviceAsyncContext : public AsyncContext {
public:
    std::vector<WifiP2pDevice> vecP2pDevices;

    QueryP2pDeviceAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    QueryP2pDeviceAsyncContext() = delete;

    ~QueryP2pDeviceAsyncContext() override {}
};

class P2pLinkedInfoAsyncContext : public AsyncContext {
public:
    WifiP2pLinkedInfo linkedInfo;

    P2pLinkedInfoAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    P2pLinkedInfoAsyncContext() = delete;

    ~P2pLinkedInfoAsyncContext() override {}
};

class P2pGroupInfoAsyncContext : public AsyncContext {
public:
    WifiP2pGroupInfo groupInfo;

    P2pGroupInfoAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    P2pGroupInfoAsyncContext() = delete;

    ~P2pGroupInfoAsyncContext() override {}
};
}  // namespace Wifi
}  // namespace OHOS

#endif
