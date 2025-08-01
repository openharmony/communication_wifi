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
#ifndef OHOS_WIFI_EVENT_CALLBACK_H
#define OHOS_WIFI_EVENT_CALLBACK_H

#include <string>
#include <functional>

namespace OHOS {
namespace Wifi {
struct AssocRejectInfo {
    std::string bssid{""};
    int statusCode{0};
    int timeOut{0};
};
struct WifiEventCallback {
    std::function<void(int, int, const std::string &, int)> onConnectChanged;
    std::function<void(const std::string &, const std::string &)> onBssidChanged;
    std::function<void(int, const std::string &)> onWpaStateChanged;
    std::function<void(const std::string &)> onWpaSsidWrongKey;
    std::function<void(int)> onWpsOverlap;
    std::function<void(int)> onWpsTimeOut;
    std::function<void(void)> onWpaAuthTimeout;
    std::function<void(int)> onWpaConnectionFull;
    std::function<void(const AssocRejectInfo &)> onWpaConnectionReject;
    std::function<void(const std::string &)> onEventStaNotify;
    std::function<void(int, const std::string &)> onReportDisConnectReason;
};

enum class WpaEventCallback {
    HILINK_NUM = 1,
    EAP_SIM_NUM = 2,
    CSA_CHSWITCH_NUM = 3,
    CHR_EVENT_NUM = 4,
    MLO_STATE_NUM = 5,
    CUSTOMIZED_EAP_AUTH = 6,
};

}  // namespace Wifi
}  // namespace OHOS

#endif