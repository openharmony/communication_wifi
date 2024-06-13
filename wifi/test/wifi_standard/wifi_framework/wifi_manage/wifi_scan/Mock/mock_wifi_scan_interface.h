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
#ifndef OHOS_MOCK_WIFI_SCAN_INTERFACE_H
#define OHOS_MOCK_WIFI_SCAN_INTERFACE_H

#include <string>
#include <vector>
#include <gmock/gmock.h>
#include "wifi_error_no.h"
#include "wifi_internal_msg.h"
#include "wifi_idl_struct.h"
#include "wifi_scan_param.h"
#include "supplicant_event_callback.h"
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {

struct WifiStaHalInfo {
    bool scan = true;
    bool queryScanInfos = true;
    bool startPnoScan = true;
    bool stopPnoScan = true;
    bool getSupportFre = true;
    bool startWifi = true;
    bool stopWifi = true;
};

struct SupplicantHalInfo {
    bool unCallback = true;
    bool callback = true;
};

class MockWifiScanInterface {
public:
    MockWifiScanInterface() = default;
    virtual ~MockWifiScanInterface() = default;
    static MockWifiScanInterface &GetInstance(void);
public:
    WifiStaHalInfo pWifiStaHalInfo;
    SupplicantHalInfo pSupplicant;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
