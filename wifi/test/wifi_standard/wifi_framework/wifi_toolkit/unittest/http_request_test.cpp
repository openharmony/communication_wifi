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
#include "arp_checker.h"



using namespace testing::ext;

namespace OHOS {
namespace Wifi {

class HttpRequestTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pHttpRequest.reset(new HttpRequest());
    }
    virtual void TearDown()
    {
        pHttpRequest.reset();
    }

public:
    std::unique_ptr<HttpRequest> pHttpRequest;
};

HWTEST_F(HttpRequestTest, ArpChecker_Fail1, TestSize.Level1)
{
    std::string strUrl = "";
    std::string strResponse = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strResponse) == -1);
}

HWTEST_F(HttpRequestTest, ArpChecker_Fail2, TestSize.Level1)
{
    std::string str[1033] = {0};
    for (int i = 0; i<1033; i++)
		str[i] = "s";
    std::string strResponse = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strResponse) == -1);
}

HWTEST_F(HttpRequestTest, GetPortFromUrl_Fail3, TestSize.Level1)
{
    std::string strUrl = "https://-10";
    std::string strResponse = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strResponse) == -1);
}

HWTEST_F(HttpRequestTest, GetPortFromUrl_Fail3, TestSize.Level1)
{
    std::string strUrl = "https//";
    std::string strResponse = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strResponse) == -1);
}

HWTEST_F(HttpRequestTest, GetPortFromUrl_Fail4, TestSize.Level1)
{
    std::string strUrl = "http://192.168.3.22";
    std::string strResponse = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strResponse) == -1);
}

HWTEST_F(HttpRequestTest, HttpPost_Success, TestSize.Level1)
{
    std::string strUrl = "http://10";
    std::string strResponse = "";
    std::string strdata = "";
    EXPECT_TRUE(pArpChecker->HttpGet(&strUrl, &strdata, &strResponse) == -1);
}
}  // namespace Wifi
}  // namespace OHOS

