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

#ifndef OHOS_SELECT_NETWORK_DATA_REPORT_TEST_H
#define OHOS_SELECT_NETWORK_DATA_REPORT_TEST_H
#include <gtest/gtest.h>
#include "select_network_data_report.h"
#include "wifi_crowdsourced_data.h"
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include <gmock/gmock.h>
#include "sta_state_machine.h"

namespace OHOS {
namespace Wifi {

class MockStaStateMachine : public StaStateMachine {
public:
    explicit MockStaStateMachine(int instId = 0) : StaStateMachine(instId) {}
};

class WifiDataReportServiceTest : public testing::Test {
public:
    WifiDataReportServiceTest()
        : mStaStateMachine(0), mWifiDataReportService_(mStaStateMachine, 0)
    {}

    ~WifiDataReportServiceTest() {}

    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override
    {
        mWifiDataReportService_.InitReportApAllInfo();
    }
    void TearDown() override {}

    MockStaStateMachine mStaStateMachine;
    WifiDataReportService mWifiDataReportService_;
};

} // namespace Wifi
} // namespace OHOS
#endif