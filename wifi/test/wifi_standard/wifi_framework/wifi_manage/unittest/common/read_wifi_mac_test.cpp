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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "wifi_log.h"
#include "wifi_logger.h"
#include "read_wifi_mac.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("ReadWifiMacTest");

class ReadWifiMacTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
    }
    virtual void TearDown() {}
private:
    std::shared_ptr<IReadMac> pReadWifiMac = nullptr;
};

HWTEST_F(ReadWifiMacTest, GetConstantMac, TestSize.Level1)
{
    std::string mac;
    pReadWifiMac = std::make_shared<ReadWifiMac>();
    if (pReadWifiMac) {
        pReadWifiMac->GetConstantMac(mac);
    }
    EXPECT_EQ(mac.empty(), false);
}

}

}