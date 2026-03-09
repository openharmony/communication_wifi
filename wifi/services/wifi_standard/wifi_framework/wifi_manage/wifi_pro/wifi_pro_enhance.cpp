/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "wifi_pro_enhance.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "wifi_msg.h"
#include "wifi_logger.h"
#include "network_black_list_manager.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProEnhance");
static constexpr int FEATURE_VALUE_LEN = 16;
static constexpr int FEATURE_VALUE_ON = 1;
static constexpr const char *FEATURE_NAME = "runtime.enhance_switch";

WifiProEnhance &WifiProEnhance::GetInstance()
{
    static WifiProEnhance gWifiProEnhance;
    return gWifiProEnhance;
}

WifiProEnhance::WifiProEnhance()
{
    char featureValue[FEATURE_VALUE_LEN + 1] = { 0 };
    int code = GetParamValue(FEATURE_NAME, "0", featureValue, FEATURE_VALUE_LEN);
    std::string featureStr(featureValue);
    featureOn_ = (code > 0 && CheckDataLegal(featureStr) == FEATURE_VALUE_ON);
    WIFI_LOGI("Enter WifiProEnhance");
}

WifiProEnhance::~WifiProEnhance()
{
    WIFI_LOGI("Enter ~WifiProEnhance");
}

bool WifiProEnhance::IsEnhanceSwitchEnable(const std::string &targetBssid)
{
    if (!featureOn_ || !enhanceSwitchEnable_.load()) {
        WIFI_LOGI("IsEnhanceSwitchEnable: disabled, featureOn=%{public}d, enhanceSwitchEnable=%{public}d",
            featureOn_, enhanceSwitchEnable_.load());
        return false;
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.networkId != INVALID_NETWORK_ID) {
        return IsEnhanceSwitchEnable(linkedInfo.bssid, targetBssid);
    }
    WIFI_LOGI("IsEnhanceSwitchEnable: networkId is invalid, skip enhance switch");
    return false;
}

bool WifiProEnhance::IsEnhanceSwitchEnable(const std::string &currentBssid, const std::string &targetBssid)
{
    if (!featureOn_ || !enhanceSwitchEnable_.load()) {
        WIFI_LOGI("IsEnhanceSwitchEnable: disabled, featureOn=%{public}d, enhanceSwitchEnable=%{public}d",
            featureOn_, enhanceSwitchEnable_.load());
        return false;
    }
    if (currentBssid.empty() || targetBssid.empty()) {
        WIFI_LOGI("IsEnhanceSwitchEnable: bssid is empty, currentBssid=%{public}s, targetBssid=%{public}s",
            MacAnonymize(currentBssid).c_str(), MacAnonymize(targetBssid).c_str());
        return false;
    }
    if (!NetworkBlockListManager::GetInstance().IsSameGateway(currentBssid, targetBssid)) {
        WIFI_LOGI("IsEnhanceSwitchEnable: not same gateway, currentBssid=%{public}s, targetBssid=%{public}s",
            MacAnonymize(currentBssid).c_str(), MacAnonymize(targetBssid).c_str());
        return false;
    }
    if (NetworkBlockListManager::GetInstance().IsInEnhanceSwitchBlocklist(targetBssid)) {
        WIFI_LOGI("IsEnhanceSwitchEnable: bssid %{public}s is in enhance switch blocklist",
            MacAnonymize(targetBssid).c_str());
        return false;
    }
    WIFI_LOGI("IsEnhanceSwitchEnable: enhance switch is enabled, currentBssid=%{public}s, targetBssid=%{public}s",
        MacAnonymize(currentBssid).c_str(), MacAnonymize(targetBssid).c_str());
    return true;
}

void WifiProEnhance::SetEnhanceSwitchEnable(bool enable)
{
    WIFI_LOGI("SetEnhanceSwitchEnable: %{public}d", enable);
    enhanceSwitchEnable_.store(enable);
}
}  // namespace Wifi
}  // namespace OHOS