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
    void SetDatashareReady();

private:
    Uri AssembleUri(const std::string &key);
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    std::unique_ptr<WifiEventHandler> securityDetectThread_ = nullptr;
    StaServiceCallback staCallback_;
    int currentConnectedNetworkId_ = -1;
    std::atomic<bool> datashareReady_ {false};
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId);
    bool IsSettingSecurityDetectOn();
    bool IsSecurityDetectTimeout(const int &networkId);
    ErrCode SecurityDetectResult(const std::string &devId, uint32_t modelId, const std::string &param, bool &result);
    void SecurityDetect(const WifiLinkedInfo &info);
    void PopupNotification(int status, int networkid);
    void ConverWifiLinkInfoToJson(const WifiLinkedInfo &info, Json::Value &root);
    int32_t AuthenticationConvert(std::string key);
};
}
}
#endif