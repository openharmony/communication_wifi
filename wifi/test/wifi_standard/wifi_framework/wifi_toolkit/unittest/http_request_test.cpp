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
#include <gmock/gmock.h>
#include "securec.h"
#include "http_request.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("HttpRequestTest");

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
/**
 * @tc.name: HttpGet_001
 * @tc.desc: test strUrl is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_001, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_001");
    std::string strUrl = "";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(strUrl, strResponse) == -1);
}
/**
 * @tc.name: HttpGet_002
 * @tc.desc: test strUrl is over URLSIZE
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_002, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_002");
    char str[URLSIZE + 1];
    if (memset_s(str, URLSIZE + 1, '*', URLSIZE + 1) != EOK) {
        return;
    }
    std::string url = str;
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(url, strResponse) == -1);
}
/**
 * @tc.name: HttpGet_003
 * @tc.desc: test GetHostAddrFromUrl error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_003, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_003");
    std::string strUrl = "https://";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(strUrl, strResponse) == -1);
}
/**
 * @tc.name: HttpGet_004
 * @tc.desc: test GetHostAddrFromUrl error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_004, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_004");
    std::string strUrl = "http://";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(strUrl, strResponse) == -1);
}
/**
 * @tc.name: HttpGet_005
 * @tc.desc: test GetHostAddrFromUrl error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_005, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_005");
    std::string strUrl = "http://192.168.62.0:-10";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(strUrl, strResponse) == -1);
}
/**
 * @tc.name: HttpGet_006
 * @tc.desc: test GetHostAddrFromUrl error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpGet_006, TestSize.Level1)
{
    WIFI_LOGI("HttpGet_006");
    std::string strUrl = "http://:10";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpGet(strUrl, strResponse) == -1);
}
/**
 * @tc.name: HttpPost_001
 * @tc.desc: test GetHostAddrFromUrl error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpPost_001, TestSize.Level1)
{
    WIFI_LOGI("HttpPost_001");
    std::string strUrl = "http://192.168.62.0:10";
    std::string strResponse = "";
    EXPECT_TRUE(pHttpRequest->HttpPost(strUrl, "", strResponse) == -1);
}
/**
 * @tc.name: HttpPost_001
 * @tc.desc: test HttpDataTransmit error
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(HttpRequestTest, HttpDataTransmit_001, TestSize.Level1)
{
    WIFI_LOGI("HttpDataTransmit_001");
    int iSockFd = 1;
    pHttpRequest->httpHead = "Connection: Keep-Alive\r\n";
    EXPECT_TRUE(pHttpRequest->HttpDataTransmit(iSockFd) == -1);
}
}  // namespace Wifi
}  // namespace OHOS