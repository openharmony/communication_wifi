/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <memory>
#include "sta_network_check.h"
#include "wifi_settings.h"
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class StaNetworkCheckTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pStaNetworkCheck = std::make_unique<StaNetworkCheck>(nethandle, arpHandle, dnsHandle);
        pStaNetworkCheck->InitNetCheckThread();
        WifiSettings::GetInstance().GetPortalUri(mUrlInfo);
    }
    virtual void TearDown()
    {
        pStaNetworkCheck->ExitNetCheckThread();
        pStaNetworkCheck.reset();
    }

public:
    void StopNetCheckThreadSuccess();
    bool HttpDetectionSuccess();
    int HttpCheckResponseCode(std::string url, int codeNum);
public:
    std::unique_ptr<StaNetworkCheck> pStaNetworkCheck;
    NetStateHandler nethandle = nullptr;
    ArpStateHandler arpHandle = nullptr;
    DnsStateHandler dnsHandle = nullptr;
    WifiPortalConf mUrlInfo;
};

bool StaNetworkCheckTest::HttpDetectionSuccess()
{
    return pStaNetworkCheck->HttpPortalDetection(mUrlInfo.portalHttpUrl);
}

int StaNetworkCheckTest::HttpCheckResponseCode(std::string url, int codeNum)
{
    pStaNetworkCheck->CheckResponseCode(url, codeNum, mUrlInfo.portalHttpUrl.size());
    return 0;
}

HWTEST_F(StaNetworkCheckTest, HttpDetectionSuccess, TestSize.Level1)
{
    EXPECT_FALSE(HttpDetectionSuccess());
}

HWTEST_F(StaNetworkCheckTest, HttpCheckResponseCode1, TestSize.Level1)
{
    EXPECT_FALSE(HttpCheckResponseCode(mUrlInfo.portalHttpUrl, 200));
}

HWTEST_F(StaNetworkCheckTest, HttpCheckResponseCode2, TestSize.Level1)
{
    EXPECT_FALSE(HttpCheckResponseCode(mUrlInfo.portalHttpsUrl, 204));
}

HWTEST_F(StaNetworkCheckTest, HttpCheckResponseCode3, TestSize.Level1)
{
    EXPECT_FALSE(HttpCheckResponseCode(mUrlInfo.portalHttpsUrl, 0));
}
} // Wifi
} // OHOS
