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
#include <gtest/gtest.h>
#include "wifi_broadcast_helper.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiBroadCastHelperTest");
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr unsigned char SERVICE_ERR = 4;
class WifiBroadCastHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pWifiBroadCastHelper = std::make_unique<WifiBroadCastHelper>();
    }

    virtual void TearDown()
    {
        pWifiBroadCastHelper.reset();
    }
public:
    std::unique_ptr<WifiBroadCastHelper> pWifiBroadCastHelper;
};
/**
 * @tc.name: Show001
 * @tc.desc: Show test
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiBroadCastHelperTest, Show001, TestSize.Level1)
{
    WIFI_LOGI("ChangePermission001 enter");
    WifiP2pServiceInfo v;
    v.SetServicerProtocolType(P2pServicerProtocolType::SERVICE_TYPE_ALL);
    pWifiBroadCastHelper->ChangePermission(v);
    v.SetServicerProtocolType(P2pServicerProtocolType::SERVICE_TYPE_BONJOUR);
    pWifiBroadCastHelper->ChangePermission(v);
    v.SetServicerProtocolType(P2pServicerProtocolType::SERVICE_TYPE_UP_NP);
    pWifiBroadCastHelper->ChangePermission(v);
    v.SetServicerProtocolType(P2pServicerProtocolType::SERVICE_TYPE_WS_DISCOVERY);
    pWifiBroadCastHelper->ChangePermission(v);
    v.SetServicerProtocolType(P2pServicerProtocolType::SERVICE_TYPE_VENDOR_SPECIFIC);
    pWifiBroadCastHelper->ChangePermission(v);
    v.SetServicerProtocolType(SERVICE_ERR);
    pWifiBroadCastHelper->ChangePermission(v);
}
}
}