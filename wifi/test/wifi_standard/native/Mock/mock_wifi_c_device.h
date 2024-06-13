/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_WIFICDEVICE_H
#define OHOS_MOCK_WIFICDEVICE_H

#include <gmock/gmock.h>
#include "kits/c/wifi_device_config.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class MockWifiCDevice {
public:
    virtual ~MockWifiCDevice() = default;
    virtual ErrCode GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate) = 0;
};

class WifiCDevice : public MockWifiCDevice {
public:
    static WifiCDevice &GetInstance(void);
    MOCK_METHOD2(GetDeviceConfigs, ErrCode(std::vector<WifiDeviceConfig> &result, bool isCandidate));
};
}  // namespace OHOS
}  // namespace Wifi

#endif
