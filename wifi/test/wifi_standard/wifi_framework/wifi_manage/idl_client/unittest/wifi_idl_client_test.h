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
#ifndef OHOS_WIFI_IDL_CLIENT_TEST_H
#define OHOS_WIFI_IDL_CLIENT_TEST_H

#include <gtest/gtest.h>
#include "wifi_idl_client.h"
#include "mock_wifi_public.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
WifiIdlClient mClient;
int g_failnums = 10;
class WifiIdlClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        while (g_failnums--) {
            if (mClient.InitClient() == 0) {
                g_failnums = 0;
            }
        }
        EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillRepeatedly(Return(-1));
    }
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};
}  // namespace Wifi
}  // namespace OHOS
#endif