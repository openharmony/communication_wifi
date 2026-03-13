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

#ifndef OHOS_WIFI_PRO_ENHANCE_H
#define OHOS_WIFI_PRO_ENHANCE_H
#include <string>

namespace OHOS {
namespace Wifi {

class WifiProEnhance {
    WifiProEnhance();
    ~WifiProEnhance();

public:
    static WifiProEnhance &GetInstance();
    bool IsEnhanceSwitchEnable(const std::string &targetBssid);
    bool IsEnhanceSwitchEnable(const std::string &currentBssid, const std::string &targetBssid);
    void SetEnhanceSwitchEnable(bool enable);
private:
    bool featureOn_ { false };
    std::atomic<bool> enhanceSwitchEnable_ { true };
};
}  // namespace Wifi
}  // namespace OHOS
#endif