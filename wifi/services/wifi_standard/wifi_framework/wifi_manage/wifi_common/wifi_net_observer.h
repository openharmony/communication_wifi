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
    /**
     * @Description Construct of NetStateObserver
     */
    NetStateObserver();

    /**
     * @Description Destructor function
     */
    ~NetStateObserver();

    /**
     * @Description registering a Network Detection Callback Listener
     *
     * @param netStateObserverPtr - netStateObserver ptr
     */
    void StartNetStateObserver(sptr<NetStateObserver> &netStateObserverPtr);

    /**
     * @Description unregistering a Network Detection Callback Listener
     *
     * @param netStateObserverPtr - netStateObserver ptr
     */
    void StopNetStateObserver(sptr<NetStateObserver> &netStateObserverPtr);

    /**
     * @Description registers the callback function of the Wi-Fi state machine.
     *
     * @param callback - callback func
     */
    void SetNetStateCallback(const std::function<void(SystemNetWorkState, std::string)> &callback);

    /**
     * @Description callback function used to notify the detection result after the NetConnManager detection ends
     *
     * @param detectionResult - detection result
     * @param urlRedirect - portal network redirection address
     * @return detect if successful, 0 indicates success, others indicate failure error codes
     */
    int32_t OnNetDetectionResultChanged(
        NetManagerStandard::NetDetectionResultCode detectionResult, const std::string &urlRedirect) override;

    /**
     * @Description get network ID
     *
     * @return network ID
     */
    int32_t GetWifiNetId();

    /**
     * @Description start wifi detection
     *
     * @return 0 is success, 1 is fail
     */
    int32_t StartWifiDetection();
private:
    sptr<NetManagerStandard::NetHandle> GetWifiNetworkHandle();
public:
    std::function<void(SystemNetWorkState, std::string)> m_callback;
};
}
}
#endif
