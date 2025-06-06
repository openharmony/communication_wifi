/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_SECURITY_DETECT_H
#define WIFI_SECURITY_DETECT_H
#include "json/json.h"
#include "sta_service_callback.h"
#include "wifi_event_handler.h"
#include "wifi_datashare_utils.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {

struct SecurityModelResult {
    std::string devId;
    uint32_t modelId;
    std::string param;
    std::string result;
};

class WifiSecurityDetect {
public:
    WifiSecurityDetect();
    ~WifiSecurityDetect();
    static WifiSecurityDetect &GetInstance();
    StaServiceCallback GetStaCallback() const;

private:
    static Uri AssembleUri(const std::string &key);
    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    std::unique_ptr<WifiEventHandler> securityDetectThread_ = nullptr;
    StaServiceCallback staCallback_;
    int currentConnectedNetworkId_ = -1;
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId);
    static bool SettingDataOnOff();
    bool SecurityDetectTime(const int &networkId);
    static bool SecurityDetectResult(const std::string &devId, uint32_t modelId, const std::string &param);
    void SecurityDetect(const WifiLinkedInfo &info);
    static void PopupNotification(int status, int networkid);
    void WifiConnectConfigParma(const WifiLinkedInfo &info, Json::Value &root);
    int32_t AuthenticationCovert(std::string key);
};
}
}
#endif