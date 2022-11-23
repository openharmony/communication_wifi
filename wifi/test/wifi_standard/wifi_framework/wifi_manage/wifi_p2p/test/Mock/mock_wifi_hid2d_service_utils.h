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
#ifndef MOCK_WIFI_HID2D_SERVICE_UTILS_H
#define MOCK_WIFI_HID2D_SERVICE_UTILS_H
#include <gmock/gmock.h>
#include "wifi_hid2d_service_utils.h"
namespace OHOS {
namespace Wifi {
class MockWifiHid2dServiceUtils : public IpPool {
public:

    ~MockWifiHid2dServiceUtils() = default;
    MOCK_METHOD1(InitIpPool, bool(const std::string& serverIp));
};
}  // namespace Wifi
}  // namespace OHOS
#endif