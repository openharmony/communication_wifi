/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SECURITY_DETECT_TEST_H
#define OHOS_WIFI_SECURITY_DETECT_TEST_H
#include <gtest/gtest.h>
#include "wifi_security_detect.h"
#include "json/json.h"
#include "datashare_helper.h"
#include "sta_service_callback.h"
#include "wifi_event_handler.h"
#include "wifi_datashare_utils.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {

class WifiSecurityDetectTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        wifiSecurityDetect_ = std::make_unique<WifiSecurityDetect>();
    }
    void TearDown() override {}
    std::unique_ptr<WifiSecurityDetect> wifiSecurityDetect_;
};

} // namespace Wifi
} // namespace OHOS
#endif