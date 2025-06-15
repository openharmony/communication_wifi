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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "net_eap_observer.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifitest";
using namespace NetManagerStandard;
DEFINE_WIFILOG_LABEL("NetEapObserverTest");
class NetEapObserverTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        NetEapObserver::GetInstance();
    }
    virtual void TearDown() {}
};

HWTEST_F(NetEapObserverTest, SetRegisterCustomEapCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("SetRegisterCustomEapCallbackTest enter!");

    std::function<void(const std::string &)> mockCallback =
        [](const std::string &) {
        };

    auto ret = NetEapObserver::GetInstance().SetRegisterCustomEapCallback(mockCallback);
    EXPECT_TRUE(ret);
}

HWTEST_F(NetEapObserverTest, SetReplyCustomEapDataCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("SetReplyCustomEapDataCallbackTest enter!");

    std::function<void(int, const std::string &)> mockCallback =
        [](int, const std::string &) {
            // Mock implementation
        };

    // Set the net state callback
    auto ret = NetEapObserver::GetInstance().SetReplyCustomEapDataCallback(mockCallback);
    EXPECT_TRUE(ret);
}

HWTEST_F(NetEapObserverTest, StartNetEapObserverTest, TestSize.Level1)
{
    WIFI_LOGI("StartNetEapObserverTest enter!");
    NetEapObserver::GetInstance().StartNetEapObserver();
}

HWTEST_F(NetEapObserverTest, StopNetEapObserverTest, TestSize.Level1)
{
    WIFI_LOGI("StopNetEapObserverTest enter!");
    NetEapObserver::GetInstance().StopNetEapObserver();
}

HWTEST_F(NetEapObserverTest, ReRegisterCustomEapCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("ReRegisterCustomEapCallbackTest enter!");
    std::string regCmd;
    std::function<void(const std::string &)> mockCallback =
        [&regCmd](const std::string &param) {
            regCmd = param;
        };

    NetEapObserver::GetInstance().SetRegisterCustomEapCallback(mockCallback);
    NetEapObserver::GetInstance().GetNetEapCallbackPtr()->regCmd_ = "2:277:285";
    NetEapObserver::GetInstance().ReRegisterCustomEapCallback();

    EXPECT_EQ(regCmd, "2:277:285");
}

HWTEST_F(NetEapObserverTest, NotifyWpaEapInterceptInfoTest, TestSize.Level1)
{
    WIFI_LOGI("NotifyWpaEapInterceptInfoTest enter!");

    WpaEapData eapData;
    eapData.code = 1;
    eapData.type = 13;
    eapData.msgId = 22;
    eapData.bufferLen = 3;
    std::vector<uint8_t> data = {0x11, 0x22, 0x12};
    eapData.eapBuffer = data;
    NetEapObserver::GetInstance().NotifyWpaEapInterceptInfo(eapData);
}

HWTEST_F(NetEapObserverTest, OnRegisterCustomEapCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("OnRegisterCustomEapCallbackTest enter!");

    NetEapObserver::GetInstance().GetNetEapCallbackPtr()->regCmd_ = "2:277:285";
    int ret = NetEapObserver::GetInstance().GetNetEapCallbackPtr()->OnRegisterCustomEapCallback("2:277:285");
    EXPECT_EQ(ret, 0);

    std::string cmd;
    std::function<void(const std::string &)> mockCallback =
        [&cmd](const std::string &param) {
            cmd = param;
        };

    NetEapObserver::GetInstance().SetRegisterCustomEapCallback(mockCallback);
    NetEapObserver::GetInstance().GetNetEapCallbackPtr()->regCmd_ = "2:277:286";
    NetEapObserver::GetInstance().GetNetEapCallbackPtr()->OnRegisterCustomEapCallback("2:277:285");
    EXPECT_EQ(cmd, "2:277:285");
}

HWTEST_F(NetEapObserverTest, OnReplyCustomEapDataEventTest, TestSize.Level1)
{
    WIFI_LOGI("OnReplyCustomEapDataEventTest enter!");
    int result;
    std::string strEapData;
    std::function<void(int, const std::string &)> mockCallback =
        [&result, &strEapData](int rS, const std::string &eD) {
            result = rS;
            strEapData = eD;
        };

    NetEapObserver::GetInstance().SetReplyCustomEapDataCallback(mockCallback);

    sptr<EapData> eapData = new (std::nothrow) EapData();
    eapData->eapCode = 1;
    eapData->eapType = 13;
    eapData->msgId = 15;
    eapData->bufferLen = 4;
    std::vector<uint8_t> tmp = {0x11, 0x12};
    eapData->eapBuffer = tmp;

    int ret = NetEapObserver::GetInstance().GetNetEapCallbackPtr()->OnReplyCustomEapDataEvent(2, eapData);
    EXPECT_EQ(result, 2);
    EXPECT_EQ(ret, 0);
}
}  // namespace Wifi
}  // namespace OHOS