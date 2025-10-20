/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_NET_EAP_OBSERVER_H
#define WIFI_NET_EAP_OBSERVER_H

#include <memory>
#include <string>
#include <vector>
#include "wifi_log.h"
#include "wifi_msg.h"
#include "iremote_broker.h"
#include "ethernet_client.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {

class NetEapCallback : public NetManagerStandard::NetRegisterEapCallbackStub {
public:

    /**
     * @Description Construct of NetEapObserver
     */
    NetEapCallback();

    /**
     * @Description Destructor function
     */
    ~NetEapCallback();

    /**
     * @Description registers the EapCustomHandler callback function of the Wi-Fi state machine.
     *
     * @param callback - callback func
     */
    bool SetRegisterCustomEapCallback(const std::function<void(const std::string &)> &callback);

    /**
     * @Description registers the ReplyCustomEapData function of the Wi-Fi state machine.
     *
     * @param callback - callback func
     */
    bool SetReplyCustomEapDataCallback(const std::function<void(int, const std::string&)> &callback);

public:
    /**
     * @Description Register Custom Eap Callback
     *
     * @param regCmd - register command. eg: 2:277:278
     */
    int32_t OnRegisterCustomEapCallback(const std::string &regCmd) override;

    /**
     * @Description callback function used to Reply Custom EapData Event
     * @param result - Indicates the result of custom authentication
     * @param eapData - Indicates sptr of eap data
     */
    int32_t OnReplyCustomEapDataEvent(int result, const sptr<NetManagerStandard::EapData> &eapData) override;

    std::function<void(const std::string &)> GetRegisterCustomEapCallback();
public:
    std::function<void(const std::string &)> regCallback_ = nullptr;
    std::function<void(int, const std::string&)> replyCallback_ = nullptr;
    std::string regCmd_ = {};
};

class NetEapObserver {
public:
    static NetEapObserver &GetInstance();
    ~NetEapObserver();

    bool StartNetEapObserver();
    bool StopNetEapObserver();
    bool SetRegisterCustomEapCallback(const std::function<void(const std::string &)> &callback);
    bool SetReplyCustomEapDataCallback(const std::function<void(int, const std::string&)> &callback);
    void ReRegisterCustomEapCallback();
    bool NotifyWpaEapInterceptInfo(const WpaEapData &wpaEapData);
    void OnWifiStateOpen(int state);
    sptr<NetEapCallback> GetNetEapCallbackPtr()
    {
        return netEapCallback_;
    }

public:
    sptr<NetEapCallback> netEapCallback_ = nullptr;

private:
    NetEapObserver();
    std::mutex mutex_;
};

}
}
#endif