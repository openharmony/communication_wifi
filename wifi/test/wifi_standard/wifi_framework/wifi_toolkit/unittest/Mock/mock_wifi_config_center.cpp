/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "mock_wifi_config_center.h"

namespace OHOS {
namespace Wifi {
WifiConfigCenter &WifiConfigCenter::GetInstance()
{
    static WifiConfigCenter instance;
    return instance;
}

WifiConfigCenter::WifiConfigCenter()
{
    wifiScanConfig = std::make_unique<WifiScanConfig>();
}

std::unique_ptr<WifiScanConfig>& WifiConfigCenter::GetWifiScanConfig()
{
    return wifiScanConfig;
}
}  // namespace Wifi
}  // namespace OHOS