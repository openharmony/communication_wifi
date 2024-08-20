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
#include "net_detection_callback_stub.h"
#include "net_handle.h"
#include "net_all_capabilities.h"
#include "net_conn_client.h"
#include "sta_define.h"
namespace OHOS {
namespace Wifi {
class NetStateObserver : public NetManagerStandard::NetDetectionCallbackStub {
public:
    NetStateObserver();

    ~NetStateObserver();

    static NetStateObserver &GetInstance();

    void StartNetStateObserver();

    void StopNetStateObserver();
 
    void SetNetStateCallback(std::function<void(SystemNetWorkState, std::string)> callback);
 
    int32_t OnNetDetectionResultChanged(
        NetManagerStandard::NetDetectionResultCode detectionResult, const std::string &urlRedirect) override;

    int32_t GetWifiNetId();

    int32_t StartWifiDetection();
private:
    sptr<NetManagerStandard::NetHandle> GetWifiNetworkHandle();
public:
    std::function<void(SystemNetWorkState, std::string)> m_Callback;
};
} // namespace Wifi
} // namespace OHOS
#endif // CELLULAR_DATA_NET_AGENT_H