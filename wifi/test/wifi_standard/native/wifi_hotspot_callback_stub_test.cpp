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

#include "wifi_hotspot_callback_stub.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_logger.h"

using ::testing::Return;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiHotspotCallbackStub");

namespace OHOS {
namespace Wifi {
constexpr int NUMBER = 2;
class WifiHotspotCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(){}
    static void TearDownTestCase(){}
    virtual void SetUp()
    {
        pWifiHotspot = std::make_unique<WifiHotspotCallbackStub>();
    }
    virtual void TearDown()
    {
        pWifiHotspot.reset();
    }
public:
    std::unique_ptr<WifiHotspotCallbackStub> pWifiHotspot;
};

class IWifiHotspotCallbackMock : public IWifiHotspotCallback {
public:
    IWifiHotspotCallbackMock()
    {
        WIFI_LOGI("IWifiHotspotCallbackMock");
    }

    ~IWifiHotspotCallbackMock()
    {
        WIFI_LOGI("~IWifiHotspotCallbackMock");
    }

public:
    void OnHotspotStateChanged(int state) override
    {
        WIFI_LOGI("OnHotspotStateChanged Mock");
    }

    void OnHotspotStaJoin(const StationInfo &info) override
    {
        WIFI_LOGI("OnHotspotStaJoin Mock");
    }

    void OnHotspotStaLeave(const StationInfo &info) override
    {
        WIFI_LOGI("OnHotspotStaLeave Mock");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override 
    {
        return nullptr;
    }
};

HWTEST_F(WifiHotspotCallbackStubTest, RegisterCallBackTest, TestSize.Level1)
{
    sptr<IWifiHotspotCallback> userCallback =  new (std::nothrow) IWifiHotspotCallbackMock();
    pWifiHotspot->RegisterCallBack(userCallback);
    pWifiHotspot->RegisterCallBack(userCallback);
}

HWTEST_F(WifiHotspotCallbackStubTest, OnHotspotStateChangedTest, TestSize.Level1)
{
    int state = NUMBER;
    pWifiHotspot->OnHotspotStateChanged(state);
}

HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequestTest, TestSize.Level1)
{
    uint32_t code = NUMBER;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiHotspotCallback::GetDescriptor())) {
        return;
    }
    pWifiHotspot->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequestTest1, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest1 ENTER");
    uint32_t code = WIFI_CBK_CMD_SCAN_STATE_CHANGE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiHotspotCallback::GetDescriptor())) {
        return;
    }
    pWifiHotspot->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiHotspotCallback> userCallback =  new (std::nothrow) IWifiHotspotCallbackMock();
    pWifiHotspot->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiHotspotCallback::GetDescriptor())) {
        return;
    }
    pWifiHotspot->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiHotspotCallbackStubTest, SetRemoteDiedTest, TestSize.Level1)
{
    bool val = true;
    pWifiHotspot->SetRemoteDied(val);
}

HWTEST_F(WifiHotspotCallbackStubTest, IsRemoteDiedTest, TestSize.Level1)
{
    pWifiHotspot->IsRemoteDied();
}
}  // namespace Wifi
}  // namespace OHOS

