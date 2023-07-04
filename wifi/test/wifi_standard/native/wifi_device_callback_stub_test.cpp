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
#include "wifi_device_callback_stub.h"
#include "wifi_logger.h"
#include "wifi_manager_service_ipc_interface_code.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackStubTest");
namespace OHOS {
namespace Wifi {
class WifiDeviceCallBackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiDeviceCallBackStub = std::make_unique<WifiDeviceCallBackStub>();
    }

    virtual void TearDown()
    {
        pWifiDeviceCallBackStub.reset();
    }

public:
    std::unique_ptr<WifiDeviceCallBackStub> pWifiDeviceCallBackStub;
};

class IWifiDeviceCallBackMock : public IWifiDeviceCallBack {
public:
    IWifiDeviceCallBackMock()
    {
        WIFI_LOGI("IWifiDeviceCallBackMock");
    }

    ~IWifiDeviceCallBackMock()
    {
        WIFI_LOGI("~IWifiDeviceCallBackMock");
    }

public:
    void OnWifiStateChanged(int state) override
    {
        WIFI_LOGI("OnWifiStateChanged test");
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override
    {
        WIFI_LOGI("OnWifiConnectionChanged test");
    }

    void OnWifiRssiChanged(int rssi) override
    {
        WIFI_LOGI("OnWifiRssiChanged test");
    }

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override
    {
        WIFI_LOGI("OnWifiWpsStateChanged test");
    }

    void OnStreamChanged(int direction) override
    {
        WIFI_LOGI("OnStreamChanged test");
    }

    void OnDeviceConfigChanged(ConfigChange value) override
    {
        WIFI_LOGI("OnDeviceConfigChanged test");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest1, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest1 enter");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(1);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest2, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest2 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STATE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    pWifiDeviceCallBackStub->RegisterUserCallBack(nullptr);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest3, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest3 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_CONNECTION_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest4, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest4 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_RSSI_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest5, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest5 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_WPS_STATE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest6, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest6 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STREAM_DIRECTION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest7, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest7 enter");
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceCallBackStub->RegisterUserCallBack(callBack);
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
    delete callBack;
}

HWTEST_F(WifiDeviceCallBackStubTest, OnRemoteRequestTest8, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest8 enter");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiDeviceCallBack::GetDescriptor())) {
        return;
    }
    pWifiDeviceCallBackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiDeviceCallBackStubTest, IsRemoteDiedTest, TestSize.Level1)
{
    WIFI_LOGI("IsRemoteDiedTest enter");
    bool val = false;
    pWifiDeviceCallBackStub->SetRemoteDied(val);
    EXPECT_TRUE(pWifiDeviceCallBackStub->IsRemoteDied() == false);
    val = true;
    pWifiDeviceCallBackStub->SetRemoteDied(val);
    EXPECT_TRUE(pWifiDeviceCallBackStub->IsRemoteDied() == true);
}
} // namespace Wifi
} // namespace OHOS
