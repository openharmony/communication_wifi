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

#include "wifi_scan_callback_stub.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int NUMBER = 1;

class WifiScanCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(){}
    static void TearDownTestCase(){}
    virtual void SetUp()
	{
        pWifiScanCallbackStub = std:make_unique<WifiScanCallbackStub>(&test);
    }
    virtual void TearDown()
	{
        pWifiScanCallbackStub.reset();
    }
public:
    std::unique_ptr<WifiScanCallbackStub> pWifiScanCallbackStub;

}; 
HWTEST_F(WifiScanCallbackStubTest, OnWifiScanStateChangedTest, TestSize.Level1)
{
    int state = NUMBER;
    pWifiScanCallbackStub->OnWifiScanStateChanged(state);
}
HWTEST_F(WifiScanCallbackStubTest, SetRemoteDiedTest, TestSize.Level1)
{
    bool val = true;
    pWifiScanCallbackStub->SetRemoteDied(val);
}
HWTEST_F(WifiScanCallbackStubTest, IsRemoteDiedTest, TestSize.Level1)
{
    pWifiScanCallbackStub->IsRemoteDied();
}
HWTEST_F(WifiScanCallbackStubTest, RegisterCallBackTest, TestSize.Level1)
{
    sptr<IWifiScanCallback> userCallback;
    pWifiScanCallbackStub->RegisterCallBack(userCallback);
}
HWTEST_F(WifiScanCallbackStubTest, OnRemoteRequest, TestSize.Level1)
{
    uint32_t code = NUMBER;
	MessageParcel data;
	MessageParcel reply;
	MessageOption option;
    pWifiScanCallbackStub->OnRemoteRequest(code, data, reply, option);
}

}  // namespace Wifi
}  // namespace OHOS

