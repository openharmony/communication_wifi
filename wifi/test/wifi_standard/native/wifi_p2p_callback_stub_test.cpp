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
#include "wifi_logger.h"
#include "wifi_p2p_callback_stub.h"
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

DEFINE_WIFILOG_LABEL("WifiP2pCallbackStubTest");
namespace OHOS {
namespace Wifi {
constexpr int BUFFER_1K = 1024;
class WifiP2pCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiP2pCallbackStub = std::make_unique<WifiP2pCallbackStub>();
    }

    virtual void TearDown()
    {
        pWifiP2pCallbackStub.reset();
    }

public:
    std::unique_ptr<WifiP2pCallbackStub> pWifiP2pCallbackStub;
};

class IWifiP2pCallbackMock : public IWifiP2pCallback {
public:
    IWifiP2pCallbackMock()
    {
        WIFI_LOGI("IWifiP2pCallbackMock");
    }

    ~IWifiP2pCallbackMock()
    {
        WIFI_LOGI("~IWifiP2pCallbackMock");
    }

public:
    void OnP2pStateChanged(int state) override
    {
        WIFI_LOGI("OnP2pStateChanged Mock");
    }

    void OnP2pPersistentGroupsChanged(void) override
    {
        WIFI_LOGI("OnP2pPersistentGroupsChanged Mock");
    }

    void OnP2pThisDeviceChanged(const WifiP2pDevice& device) override
    {
        WIFI_LOGI("OnP2pThisDeviceChanged Mock");
    }

    void OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices) override
    {
        WIFI_LOGI("OnP2pPeersChanged Mock");
    }

    void OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo) override
    {
        WIFI_LOGI("OnP2pServicesChanged Mock");
    }

    void OnP2pConnectionChanged(const WifiP2pLinkedInfo& info) override
    {
        WIFI_LOGI("OnP2pConnectionChanged Mock");
    }

    void OnP2pDiscoveryChanged(bool isChange) override
    {
        WIFI_LOGI("OnP2pDiscoveryChanged Mock");
    }

    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override
    {
        WIFI_LOGI("OnP2pActionResult Mock");
    }

    void OnConfigChanged(CfgType type, char* data, int dataLen) override
    {
        WIFI_LOGI("OnConfigChanged Mock");
    }

    void OnP2pGcJoinGroup(const GcInfo &info) override
    {
        WIFI_LOGI("OnP2pGcJoinGroup Mock");
    }

    void OnP2pGcLeaveGroup(const GcInfo &info) override
    {
        WIFI_LOGI("OnP2pGcLeaveGroup Mock");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override{
        return nullptr;
    }
};

HWTEST_F(WifiP2pCallbackStubTest, OnRemoteRequestTest1, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest1 enter");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, OnRemoteRequestTest2, TestSize.Level1)
{
    WIFI_LOGI("OnRemoteRequestTest2 enter");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(1);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pStateChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pStateChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_STATE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pPersistentGroupsChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pPersistentGroupsChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PERSISTENT_GROUPS_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pThisDeviceChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pThisDeviceChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_THIS_DEVICE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pPeersChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pPeersChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PEER_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(1);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pPeersChangedTest2, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pPeersChangedTest2 enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PEER_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(BUFFER_1K);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pServicesChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pServicesChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_SERVICE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(1);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pServicesChangedTest2, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pServicesChangedTest2 enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_SERVICE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(BUFFER_1K);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pConnectionChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pConnectionChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CONNECT_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pDiscoveryChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pDiscoveryChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_DISCOVERY_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pActionResultTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pActionResultTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_ACTION_RESULT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnConfigChangedTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnConfigChangedTest enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(0);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnConfigChangedTest1, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnConfigChangedTest1 enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(1);
    data.WriteInt32(1);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnConfigChangedTest2, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnConfigChangedTest2 enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    reply.WriteBuffer("abcd", 1);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(1);
    data.WriteInt32(1);
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, RemoteOnP2pGcJoinGroupTest, TestSize.Level1)
{
    WIFI_LOGI("RemoteOnP2pGcJoinGroup enter");
    uint32_t code = static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_GC_JOIN_GROUP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    const sptr<IWifiP2pCallback> userCallback = new (std::nothrow) IWifiP2pCallbackMock();
    pWifiP2pCallbackStub->RegisterCallBack(userCallback);
    if (!data.WriteInterfaceToken(IWifiP2pCallback::GetDescriptor())) {
        return;
    }
    pWifiP2pCallbackStub->OnRemoteRequest(code, data, reply, option);
    delete userCallback;
}

HWTEST_F(WifiP2pCallbackStubTest, IsRemoteDiedTest, TestSize.Level1)
{
    WIFI_LOGI("IsRemoteDiedTest enter");
    bool val = false;
    pWifiP2pCallbackStub->SetRemoteDied(val);
    EXPECT_TRUE(pWifiP2pCallbackStub->IsRemoteDied() == false);
}
} // namespace Wifi
} // namespace OHOS
