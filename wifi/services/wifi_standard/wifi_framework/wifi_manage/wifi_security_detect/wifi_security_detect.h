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
#include "cJSON.h"
#include "sta_service_callback.h"
#include "wifi_event_handler.h"
#include "wifi_datashare_utils.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {

enum WifiNotification {
    OPEN = 1,  /* wifi_notification is open */
    CLOSE = 2, /* wifi_notification is close */
};
enum WireType {
    WIRE_802_11A = 1,
    WIRE_802_11B = 2,
    WIRE_802_11G = 3,
    WIRE_802_11N = 4,
    WIRE_802_11AC = 5,
    WIRE_802_11AX = 6,
};
enum SecurityType {
    SECURITY_TYPE_OPEN = 0,
    SECURITY_TYPE_WEP = 1,
    SECURITY_TYPE_PSK = 2,
    SECURITY_TYPE_EAP = 3,
    SECURITY_TYPE_SAE = 4,
    SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT = 5,
    SECURITY_TYPE_OWE = 6,
    SECURITY_TYPE_WAPI_PSK = 7,
    SECURITY_TYPE_WAPI_CERT = 8,
    SECURITY_TYPE_EAP_WPA3_ENTERPRISE = 9,
    SECURITY_TYPE_OSEN = 10,
    SECURITY_TYPE_PASSPOINT_R1_R2 = 11,
    SECURITY_TYPE_PASSPOINT_R3 = 12,
    SECURITY_TYPE_DPP = 13,
    SECURITY_TYPE_UNKNOWN = -1,
};

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
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    bool IsSettingSecurityDetectOn();
    Uri AssembleUri(const std::string &key);
    void SetDatashareReady();
    void SetChangeNetworkid(int networkid);
    void RegisterSecurityDetectObserver();
    void SecurityDetect(const WifiLinkedInfo &info);
    void AddWifiStandardToJson(cJSON *root, int wifiStandard);
    void PopupNotification(int status, int networkid);

private:
    std::unique_ptr<WifiEventHandler> securityDetectThread_ = nullptr;
    StaServiceCallback staCallback_;
    std::atomic<int> currentConnectedNetworkId_ {-1};
    std::atomic<bool> datashareReady_ {false};
    std::atomic<bool> networkDetecting_ {false};
    std::mutex shareSecurityObserverMutex_;
    std::mutex shareDetectMutex_;
    std::atomic<bool> isSecurityDetectObservered_ {false};
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId);
    bool IsSecurityDetectTimeout(const int &networkId);
    ErrCode SecurityDetectResult(const std::string &devId, uint32_t modelId, const std::string &param, bool &result);
    ErrCode SecurityModelJsonResult(SecurityModelResult model, bool &result);
    void ConverWifiLinkInfoToJson(const WifiLinkedInfo &info, cJSON *root);
    int32_t AuthenticationConvert(std::string key);
    void UnRegisterSecurityDetectObserver();
};
}
}
#endif