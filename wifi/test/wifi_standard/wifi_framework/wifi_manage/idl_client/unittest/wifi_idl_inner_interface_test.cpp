/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "securec.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_ap_event_callback.h"
#include "wifi_event_callback.h"
#include "wifi_idl_inner_interface.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiIdlInnerInterfaceTest"
using namespace testing::ext;

namespace OHOS {
namespace Wifi {
constexpr int LENTH = 16;
constexpr int LENTH1 = 11;

static void OnConnectChangedMock(int status, int networkId, const std::string &bssid)
{
    LOGI("OnConnectChangedMock");
}

static void OnBssidChangedMock(const std::string &reason, const std::string &bssid)
{
    LOGI("OnBssidChangedMock");
}

static void OnWpaStateChangedMock(int status)
{
    LOGI("OnWpaStateChangedMock");
}

static void OnWpaSsidWrongKeyMock(int status)
{
    LOGI("OnWpaSsidWrongKeyMock");
}

static void OnWpsOverlapMock(int status)
{
    LOGI("OnWpsOverlapMock");
}

static void OnWpsTimeOutMock(int status)
{
    LOGI("OnWpsTimeOutMock");
}

static void OnWpaConnectionFullMock(int status)
{
    LOGI("OnWpaConnectionFullMock");
}

static void OnWpaConnectionRejectMock(int status)
{
    LOGI("OnWpaConnectionRejectMock");
}

static void OnStaJoinOrLeaveMock(const WifiApConnectionNofify &info)
{
    LOGI("OnStaJoinOrLeaveMock");
}

static void OnApEnableOrDisableMock(int state)
{
    LOGI("OnApEnableOrDisableMock");
}

static void OnConnectSupplicantMock(int status)
{
    LOGI("OnConnectSupplicantMock");
}

static void OnDeviceFoundMock(const IdlP2pDeviceFound &info)
{
    LOGI("OnDeviceFoundMock");
}

static void OnDeviceLostMock(const std::string &address)
{
    LOGI("OnDeviceLostMock");
}

static void OnGoNegotiationRequestMock(const std::string &srcAddr, short passId)
{
    LOGI("OnGoNegotiationRequestMock");
}

static void OnGoNegotiationSuccessMock()
{
    LOGI("OnGoNegotiationSuccessMock");
}

static void OnGoNegotiationFailureMock(int status)
{
    LOGI("OnGoNegotiationFailureMock");
}

static void OnInvitationReceivedMock(const IdlP2pInvitationInfo &info)
{
    LOGI("OnInvitationReceivedMock");
}

static void OnInvitationResultMock(const std::string &bssid, int status)
{
    LOGI("OnInvitationResultMock");
}

static void OnGroupFormationSuccessMock()
{
    LOGI("OnGroupFormationSuccessMock");
}

static void OnGroupFormationFailureMock(const std::string &reason)
{
    LOGI("OnGroupFormationFailureMock");
}

static void OnProvisionDiscoveryPbcRequestMock(const std::string &address)
{
    LOGI("OnProvisionDiscoveryPbcRequestMock");
}

static void OnProvisionDiscoveryPbcResponseMock(const std::string &address)
{
    LOGI("OnProvisionDiscoveryPbcResponseMock");
}

static void OnProvisionDiscoveryEnterPinMock(const std::string &address)
{
    LOGI("OnProvisionDiscoveryEnterPinMock");
}

static void OnProvisionDiscoveryShowPinMock(const std::string &address, const std::string &pin)
{
    LOGI("OnProvisionDiscoveryShowPinMock");
}

static void OnProvisionDiscoveryFailureMock()
{
    LOGI("OnProvisionDiscoveryFailureMock");
}

static void OnServiceDiscoveryResponseMock(
    const std::string &srcAddress, short updateIndicator, const std::vector<unsigned char> &tlvs)
{
    LOGI("OnServiceDiscoveryResponseMock");
}

static void OnStaDeauthorizedMock(const std::string &address)
{
    LOGI("OnStaDeauthorizedMock");
}

static void OnStaAuthorizedMock(const std::string &devAddress, const std::string &groupAddress)
{
    LOGI("OnStaAuthorizedMock");
}

static void ConnectSupplicantFailedMock()
{
    LOGI("ConnectSupplicantFailedMock");
}

static void OnP2pServDiscReqMock(const IdlP2pServDiscReqInfo &info)
{
    LOGI("OnP2pServDiscReqMock");
}

static void OnP2pIfaceCreatedMock(const std::string &ifName, int isGo)
{
    LOGI("OnP2pIfaceCreatedMock");
}

class WifiIdlInnerInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
    void RegisterStaCallbackMock(WifiEventCallback *callback)
    {
        callback->onConnectChanged = OnConnectChangedMock;
        callback->onBssidChanged = OnBssidChangedMock;
        callback->onWpaStateChanged = OnWpaStateChangedMock;
        callback->onWpaSsidWrongKey = OnWpaSsidWrongKeyMock;
        callback->onWpsOverlap = OnWpsOverlapMock;
        callback->onWpsTimeOut = OnWpsTimeOutMock;
        callback->onWpaConnectionFull = OnWpaConnectionFullMock;
        callback->onWpaConnectionReject = OnWpaConnectionRejectMock;
    }

    void UnRegisterStaCallbackMock(WifiEventCallback *callback)
    {
        callback->onConnectChanged = nullptr;
        callback->onBssidChanged = nullptr;
        callback->onWpaStateChanged = nullptr;
        callback->onWpaSsidWrongKey = nullptr;
        callback->onWpsOverlap = nullptr;
        callback->onWpsTimeOut = nullptr;
        callback->onWpaConnectionFull = nullptr;
        callback->onWpaConnectionReject = nullptr;
    }

    void RegisterApCallbackMock(IWifiApMonitorEventCallback *callback)
    {
        callback->onStaJoinOrLeave = OnStaJoinOrLeaveMock;
        callback->onApEnableOrDisable = OnApEnableOrDisableMock;
    }

    void UnRegisterApCallbackMock(IWifiApMonitorEventCallback *callback)
    {
        callback->onStaJoinOrLeave = nullptr;
        callback->onApEnableOrDisable = nullptr;
    }

    void RegisterP2pCallbackMock(P2pHalCallback *callback)
    {
        callback->onConnectSupplicant = OnConnectSupplicantMock;
        callback->onDeviceFound = OnDeviceFoundMock;
        callback->onDeviceLost = OnDeviceLostMock;
        callback->onGoNegotiationRequest = OnGoNegotiationRequestMock;
        callback->onGoNegotiationSuccess = OnGoNegotiationSuccessMock;
        callback->onGoNegotiationFailure = OnGoNegotiationFailureMock;
        callback->onInvitationReceived = OnInvitationReceivedMock;
        callback->onInvitationResult = OnInvitationResultMock;
        callback->onGroupFormationSuccess = OnGroupFormationSuccessMock;
        callback->onGroupFormationFailure = OnGroupFormationFailureMock;
        callback->onProvisionDiscoveryPbcRequest = OnProvisionDiscoveryPbcRequestMock;
        callback->onProvisionDiscoveryPbcResponse = OnProvisionDiscoveryPbcResponseMock;
        callback->onProvisionDiscoveryEnterPin = OnProvisionDiscoveryEnterPinMock;
        callback->onProvisionDiscoveryShowPin = OnProvisionDiscoveryShowPinMock;
        callback->onProvisionDiscoveryFailure = OnProvisionDiscoveryFailureMock;
        callback->onServiceDiscoveryResponse = OnServiceDiscoveryResponseMock;
        callback->onStaDeauthorized = OnStaDeauthorizedMock;
        callback->onStaAuthorized = OnStaAuthorizedMock;
        callback->connectSupplicantFailed = ConnectSupplicantFailedMock;
        callback->onP2pServDiscReq = OnP2pServDiscReqMock;
        callback->onP2pIfaceCreated = OnP2pIfaceCreatedMock;
    }

    void UnRegisterP2pCallbackMock(P2pHalCallback *callback)
    {
        callback->onConnectSupplicant = nullptr;
        callback->onDeviceFound = nullptr;
        callback->onDeviceLost = nullptr;
        callback->onGoNegotiationRequest = nullptr;
        callback->onGoNegotiationSuccess = nullptr;
        callback->onGoNegotiationFailure = nullptr;
        callback->onInvitationReceived = nullptr;
        callback->onInvitationResult = nullptr;
        callback->onGroupFormationSuccess = nullptr;
        callback->onGroupFormationFailure = nullptr;
        callback->onProvisionDiscoveryPbcRequest = nullptr;
        callback->onProvisionDiscoveryPbcResponse = nullptr;
        callback->onProvisionDiscoveryEnterPin = nullptr;
        callback->onProvisionDiscoveryShowPin = nullptr;
        callback->onProvisionDiscoveryFailure = nullptr;
        callback->onServiceDiscoveryResponse = nullptr;
        callback->onStaDeauthorized = nullptr;
        callback->onStaAuthorized = nullptr;
        callback->connectSupplicantFailed = nullptr;
        callback->onP2pServDiscReq = nullptr;
        callback->onP2pIfaceCreated = nullptr;
    }
};
/**
 * @tc.name: OnApStaJoinOrLeaveTest
 * @tc.desc: OnApStaJoinOrLeaveTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnApStaJoinOrLeaveTest, TestSize.Level1)
{
    LOGI("OnApStaJoinOrLeaveTest enter");
    CStationInfo* info = nullptr;
    int id = 1;
    OnApStaJoinOrLeave(info, id);
    CStationInfo infomation;
    infomation.type = 1;
    if (memcpy_s(infomation.mac, WIFI_MAX_MAC_ADDR_LENGTH, "00:00:AA:BB:CC:DD", WIFI_MAX_MAC_ADDR_LENGTH - 1) != EOK) {
        return;
    }
    IWifiApMonitorEventCallback callback;
    RegisterApCallbackMock(&callback);
    WifiApHalInterface::GetInstance().RegisterApEvent(callback);
    OnApStaJoinOrLeave(&infomation, id);
    UnRegisterApCallbackMock(&callback);
    WifiApHalInterface::GetInstance().RegisterApEvent(callback);
    OnApStaJoinOrLeave(&infomation, id);
}
/**
 * @tc.name: OnApEnableOrDisableTest
 * @tc.desc: OnApEnableOrDisableTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnApEnableOrDisableTest, TestSize.Level1)
{
    LOGI("OnApEnableOrDisableTest enter");
    int status = 1;
    int id = 1;
    IWifiApMonitorEventCallback callback;
    RegisterApCallbackMock(&callback);
    WifiApHalInterface::GetInstance().RegisterApEvent(callback);
    OnApEnableOrDisable(status, id);
    UnRegisterApCallbackMock(&callback);
    WifiApHalInterface::GetInstance().RegisterApEvent(callback);
    OnApEnableOrDisable(status, id);
}
/**
 * @tc.name: OnConnectChangedTest
 * @tc.desc: Sta OnConnectChangedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnConnectChangedTest, TestSize.Level1)
{
    LOGI("OnConnectChangedTest enter");
    int status = 1;
    int networkId = 1;
    char *mac = nullptr;
    OnConnectChanged(status, networkId, mac);
    char mac1[] = "00:00:AA:BB:CC:DD";
    WifiEventCallback callback;
    RegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnConnectChanged(status, networkId, mac1);
    UnRegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnConnectChanged(status, networkId, mac1);
}
/**
 * @tc.name: OnBssidChangedTest
 * @tc.desc: OnBssidChangedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnBssidChangedTest, TestSize.Level1)
{
    LOGI("OnBssidChangedTest enter");
    char *rea = nullptr;
    char *bss = nullptr;
    OnBssidChanged(rea, bss);
    char reason[] = "none";
    OnBssidChanged(reason, bss);
    char bssid[] = "00:00:AA:BB:CC:DD";
    WifiEventCallback callback;
    RegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnBssidChanged(reason, bssid);
    UnRegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnBssidChanged(reason, bssid);
}
/**
 * @tc.name: OnWpaStateChangedTest
 * @tc.desc: OnWpaStateChangedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnWpaStateChangedTest, TestSize.Level1)
{
    LOGI("OnWpaStateChangedTest enter");
    int status = 1;
    WifiEventCallback callback;
    RegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnWpaStateChanged(status);
    OnWpaSsidWrongKey(status);
    OnWpaConnectionFull(status);
    OnWpaConnectionReject(status);
    OnWpsOverlap(status);
    OnWpsTimeOut(status);
    UnRegisterStaCallbackMock(&callback);
    WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callback);
    OnWpaStateChanged(status);
    OnWpaSsidWrongKey(status);
    OnWpaConnectionFull(status);
    OnWpaConnectionReject(status);
    OnWpsOverlap(status);
    OnWpsTimeOut(status);
}
/**
 * @tc.name: OnP2pDeviceFoundTest
 * @tc.desc: OnP2pDeviceFoundTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pDeviceFoundTest, TestSize.Level1)
{
    LOGI("OnP2pDeviceFoundTest enter");
    P2pDeviceInfo* info = nullptr;
    OnP2pDeviceFound(info);
    P2pDeviceInfo information;
    if (memcpy_s(information.wfdDeviceInfo, WIFI_P2P_WFD_DEVICE_INFO_LENGTH, "watchpannel", LENTH1) != EOK) {
        return;
    }
    information.wfdLength = LENTH1;
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pDeviceFound(&information);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pDeviceFound(&information);
}
/**
 * @tc.name: OnP2pDeviceLostTest
 * @tc.desc: OnP2pDeviceLostTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pDeviceLostTest, TestSize.Level1)
{
    LOGI("OnP2pDeviceLostTest enter");
    char *p2pDevic = nullptr;
    OnP2pDeviceLost(p2pDevic);
    char p2pDeviceAddress[] = "00:00:AA:BB:CC:DD";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pDeviceLost(p2pDeviceAddress);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pDeviceLost(p2pDeviceAddress);
}
/**
 * @tc.name: OnP2pGoNegotiationRequestTest
 * @tc.desc: OnP2pGoNegotiationRequestTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGoNegotiationRequestTest, TestSize.Level1)
{
    LOGI("OnP2pGoNegotiationRequestTest enter");
    char *srcAdd = nullptr;
    short passwordId = 1;
    OnP2pGoNegotiationRequest(srcAdd, passwordId);
    char srcAddress[] = "00:00:AA:BB:CC:DD";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationRequest(srcAddress, passwordId);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationRequest(srcAddress, passwordId);
}
/**
 * @tc.name: OnP2pGoNegotiationSuccessTest
 * @tc.desc: OnP2pGoNegotiationSuccessTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGoNegotiationSuccessTest, TestSize.Level1)
{
    LOGI("OnP2pGoNegotiationSuccessTest enter");
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationSuccess();
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationSuccess();
}
/**
 * @tc.name: OnP2pGoNegotiationFailureTest
 * @tc.desc: OnP2pGoNegotiationFailureTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGoNegotiationFailureTest, TestSize.Level1)
{
    LOGI("OnP2pGoNegotiationFailureTest enter");
    int status = 1;
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationFailure(status);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGoNegotiationFailure(status);
}
/**
 * @tc.name: OnP2pInvitationResultTest
 * @tc.desc: OnP2pInvitationResultTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pInvitationResultTest, TestSize.Level1)
{
    LOGI("OnP2pInvitationResultTest enter");
    char *bss = nullptr;
    int status = 1;
    OnP2pInvitationResult(bss, status);
    char bssid[] = "00:00:AA:BB:CC:DD";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pInvitationResult(bssid, status);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pInvitationResult(bssid, status);
}
/**
 * @tc.name: OnP2pInvitationReceivedTest
 * @tc.desc: OnP2pInvitationReceivedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pInvitationReceivedTest, TestSize.Level1)
{
    LOGI("OnP2pInvitationReceivedTest enter");
    P2pInvitationInfo *info = nullptr;
    OnP2pInvitationReceived(info);
    P2pInvitationInfo information;
    information.type = 1;
    information.persistentNetworkId = 1;
    information.operatingFrequency = 1;
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pInvitationReceived(&information);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pInvitationReceived(&information);
}
/**
 * @tc.name: OnP2pGroupFormationSuccessTest
 * @tc.desc: OnP2pGroupFormationSuccessTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGroupFormationSuccessTest, TestSize.Level1)
{
    LOGI("OnP2pGroupFormationSuccessTest enter");
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupFormationSuccess();
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupFormationSuccess();
}
/**
 * @tc.name: OnP2pGroupFormationFailureTest
 * @tc.desc: OnP2pGroupFormationFailureTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGroupFormationFailureTest, TestSize.Level1)
{
    LOGI("OnP2pGroupFormationFailureTest enter");
    char *failure = nullptr;
    OnP2pGroupFormationFailure(failure);
    char failureReason[] = "test";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupFormationFailure(failureReason);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupFormationFailure(failureReason);
}
/**
 * @tc.name: OnP2pGroupStartedTest
 * @tc.desc: OnP2pGroupStartedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGroupStartedTest, TestSize.Level1)
{
    LOGI("OnP2pGroupStartedTest enter");
    P2pGroupInfo *group = nullptr;
    OnP2pGroupStarted(group);
    P2pGroupInfo groupInfo;
    groupInfo.isGo = 1;
    groupInfo.isPersistent = 0;
    groupInfo.frequency = 1;
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupStarted(&groupInfo);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupStarted(&groupInfo);
}
/**
 * @tc.name: OnP2pGroupRemovedTest
 * @tc.desc: OnP2pGroupRemovedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pGroupRemovedTest, TestSize.Level1)
{
    LOGI("OnP2pGroupRemovedTest enter");
    char *groupIf = nullptr;
    int isGo = 1;
    OnP2pGroupRemoved(groupIf, isGo);
    char groupIfName[] = "P2pGroupRemoved";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupRemoved(groupIfName, isGo);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pGroupRemoved(groupIfName, isGo);
}
/**
 * @tc.name: OnP2pProvisionDiscoveryTest
 * @tc.desc: OnP2pProvisionDiscoveryTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pProvisionDiscoveryTest, TestSize.Level1)
{
    LOGI("OnP2pProvisionDiscoveryTest enter");
    char *p2pDeviceAdd = nullptr;
    OnP2pProvisionDiscoveryPbcRequest(p2pDeviceAdd);
    OnP2pProvisionDiscoveryPbcResponse(p2pDeviceAdd);
    OnP2pProvisionDiscoveryEnterPin(p2pDeviceAdd);
    char p2pDeviceAddress[] = "00:22:AA:BB:CC:DD";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryPbcRequest(p2pDeviceAddress);
    OnP2pProvisionDiscoveryPbcResponse(p2pDeviceAddress);
    OnP2pProvisionDiscoveryEnterPin(p2pDeviceAddress);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryPbcRequest(p2pDeviceAddress);
    OnP2pProvisionDiscoveryPbcResponse(p2pDeviceAddress);
    OnP2pProvisionDiscoveryEnterPin(p2pDeviceAddress);
}
/**
 * @tc.name: OnP2pProvisionDiscoveryShowPinTest
 * @tc.desc: OnP2pProvisionDiscoveryShowPinTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pProvisionDiscoveryShowPinTest, TestSize.Level1)
{
    LOGI("OnP2pProvisionDiscoveryShowPinTest enter");
    char *p2pDeviceAddress = nullptr;
    char *generatedPin = nullptr;
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAddress, generatedPin);
    char p2pDeviceAdd[] = "00:22:AA:BB:CC:DD";
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAdd, generatedPin);
    char pin[] = "test";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAdd, pin);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAdd, pin);
}
/**
 * @tc.name: OnP2pProvisionDiscoveryFailureTest
 * @tc.desc: OnP2pProvisionDiscoveryFailureTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pProvisionDiscoveryFailureTest, TestSize.Level1)
{
    LOGI("OnP2pProvisionDiscoveryFailureTest enter");
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryFailure();
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pProvisionDiscoveryFailure();
}
/**
 * @tc.name: OnP2pFindStoppedTest
 * @tc.desc: OnP2pFindStoppedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pFindStoppedTest, TestSize.Level1)
{
    LOGI("OnP2pFindStoppedTest enter");
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pFindStopped();
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pFindStopped();
}
/**
 * @tc.name: OnP2pServiceDiscoveryResponseTest
 * @tc.desc: OnP2pServiceDiscoveryResponseTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pServiceDiscoveryResponseTest, TestSize.Level1)
{
    LOGI("OnP2pServiceDiscoveryResponseTest enter");
    char *srcAdd = nullptr;
    short updateIndicator = 1;
    unsigned char tlvs[] = "test";
    size_t tlvsLength = 1;
    OnP2pServiceDiscoveryResponse(srcAdd, updateIndicator, tlvs, tlvsLength);
    char srcAddress[] = "AA:BB:CC:DD:EE:FF";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pServiceDiscoveryResponse(srcAddress, updateIndicator, tlvs, tlvsLength);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pServiceDiscoveryResponse(srcAddress, updateIndicator, tlvs, tlvsLength);
}
/**
 * @tc.name: OnP2pStaDeauthorizedTest
 * @tc.desc: OnP2pStaDeauthorizedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pStaDeauthorizedTest, TestSize.Level1)
{
    LOGI("OnP2pStaDeauthorizedTest enter");
    char *p2pDeviceAddress = nullptr;
    char *p2pGroupAddress = nullptr;
    OnP2pStaDeauthorized(p2pDeviceAddress);
    OnP2pStaAuthorized(p2pDeviceAddress, p2pGroupAddress);
    char p2pDeviceAdd[] = "AA:BB:CC:DD:EE:FF";
    char p2pGroupAdd[] = "AA:BB:CC:DD:EE:FF";
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pStaDeauthorized(p2pDeviceAdd);
    OnP2pStaAuthorized(p2pDeviceAdd, p2pGroupAdd);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pStaDeauthorized(p2pDeviceAdd);
    OnP2pStaAuthorized(p2pDeviceAdd, p2pGroupAdd);
}
/**
 * @tc.name: OnP2pConnectSupplicantFailedTest
 * @tc.desc: OnP2pConnectSupplicantFailedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pConnectSupplicantFailedTest, TestSize.Level1)
{
    LOGI("OnP2pConnectSupplicantFailedTest enter");
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pConnectSupplicantFailed();
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pConnectSupplicantFailed();
}
/**
 * @tc.name: OnP2pServDiscReqTest
 * @tc.desc: OnP2pServDiscReqTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pServDiscReqTest, TestSize.Level1)
{
    LOGI("OnP2pServDiscReqTest enter");
    P2pServDiscReqInfo *info = nullptr;
    OnP2pServDiscReq(info);
    P2pServDiscReqInfo infomation;
    infomation.tlvsLength = LENTH;
    if (memcpy_s(infomation.tlvs, WIFI_MAX_MAC_ADDR_LENGTH, "AABBCCDDEEFFGGHH", LENTH) != EOK) {
        return;
    }
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pServDiscReq(&infomation);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pServDiscReq(&infomation);
}
/**
 * @tc.name: OnP2pIfaceCreatedTest
 * @tc.desc: OnP2pIfaceCreatedTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiIdlInnerInterfaceTest, OnP2pIfaceCreatedTest, TestSize.Level1)
{
    LOGI("OnP2pIfaceCreatedTest enter");
    char ifName[] = "TV";
    int isGo = 1;
    P2pHalCallback callback;
    RegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pIfaceCreated(ifName, isGo);
    UnRegisterP2pCallbackMock(&callback);
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    OnP2pIfaceCreated(ifName, isGo);
}
}  // namespace Wifi
}  // namespace OHOS