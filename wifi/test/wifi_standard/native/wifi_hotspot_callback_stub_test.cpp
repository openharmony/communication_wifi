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
#include "wifi_errcode.h"
#include "wifi_manager_service_ipc_interface_code.h"

using ::testing::Return;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiHotspotCallbackStubTest");

namespace OHOS {
namespace Wifi {
class WifiHotspotCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
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
/**
 * @tc.name: RegisterCallBack_001
 * @tc.desc: RegisterCallBack with nullptr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, RegisterCallBack_001, TestSize.Level1)
{
    WIFI_LOGI("RegisterCallBack_001 enter");
    pWifiHotspot->RegisterCallBack(nullptr);
}
/**
 * @tc.name: RegisterCallBack_002
 * @tc.desc: RegisterCallBack with userCallback
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, RegisterCallBack_002, TestSize.Level1)
{
    WIFI_LOGI("RegisterCallBack_002 enter");
    sptr<IWifiHotspotCallback> userCallback =  new (std::nothrow) IWifiHotspotCallbackMock();
    pWifiHotspot->RegisterCallBack(userCallback);
    delete userCallback;
}
/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest with RemoteDied is true
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequest_001 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    pWifiHotspot->SetRemoteDied(true);
    EXPECT_TRUE(pWifiHotspot->IsRemoteDied());
    EXPECT_TRUE(pWifiHotspot->OnRemoteRequest(code, data, reply, option) == WIFI_OPT_FAILED);
}
/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest without GetDescriptor
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequest_002 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    EXPECT_TRUE(pWifiHotspot->OnRemoteRequest(code, data, reply, option) == WIFI_OPT_FAILED);
}
/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest with exception is 1
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequest_003 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    if (!data.WriteInterfaceToken(IWifiHotspotCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(1);
    EXPECT_TRUE(pWifiHotspot->OnRemoteRequest(code, data, reply, option) == -1);
}
/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: OnRemoteRequest for default case
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnRemoteRequest_004, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequest_004 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1;
    if (!data.WriteInterfaceToken(IWifiHotspotCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    pWifiHotspot->OnRemoteRequest(code, data, reply, option);
}
/**
 * @tc.name: OnHotspotStateChanged_001
 * @tc.desc: OnHotspotStateChanged
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnHotspotStateChanged_001, TestSize.Level1)
{
    WIFI_LOGI("OnHotspotStateChanged_001 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_CHANGE);
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
    delete userCallback;
}
/**
 * @tc.name: OnHotspotStaJoin_001
 * @tc.desc: OnHotspotStaJoin
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnHotspotStaJoin_001, TestSize.Level1)
{
    WIFI_LOGI("OnHotspotStaJoin_001 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_JOIN);
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
    delete userCallback;
}
/**
 * @tc.name: OnHotspotStaLeave_001
 * @tc.desc: OnHotspotStaLeave
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotCallbackStubTest, OnHotspotStaLeave_001, TestSize.Level1)
{
    WIFI_LOGI("OnHotspotStaLeave_001 enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_LEAVE);
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
    delete userCallback;
}

}  // namespace Wifi
}  // namespace OHOS

