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

#ifndef WIFI_NET_OBSERVER_H
#define WIFI_NET_OBSERVER_H

#include <memory>
#include <string>
#include <vector>

#include "wifi_log.h"
#include "net_conn_callback_stub.h"
#include "net_handle.h"
#include "net_all_capabilities.h"
#include "sta_define.h"
namespace OHOS {
namespace Wifi {
class NetStateObserver : public NetManagerStandard::NetConnCallbackStub {
public:
    NetStateObserver();

    ~NetStateObserver();

    static NetStateObserver &GetInstance();

    void StartNetStateObserver();

    void StopNetStateObserver();

    void SetNetStateCallback(std::function<void(SystemNetWorkState)> callback);

    int32_t NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
        const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap) override;

    SystemNetWorkState GetCellNetState();
    
    int32_t GetWifiNetId();
public:
    std::function<void(SystemNetWorkState)> m_Callback;
};
} // namespace Wifi
} // namespace OHOS
#endif // CELLULAR_DATA_NET_AGENT_H
