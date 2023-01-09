/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "wifi_idl_inner_interface.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

constexpr int LENTH = 16;
class wifi_idl_inner_interface_test : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(wifi_idl_inner_interface_test, OnApStaJoinOrLeaveTest, TestSize.Level1)
{
    CStationInfo* info = nullptr;
    int id = 1;
    OnApStaJoinOrLeave(info, id);
    CStationInfo infomation;
    infomation.type = 1;
    infomation.mac = "00:00:AA:BB:CC:DD";
    OnApStaJoinOrLeave(&info, id);
}

HWTEST_F(wifi_idl_inner_interface_test, OnApEnableOrDisableTest, TestSize.Level1)
{
    int status = 1;
    int id = 1;
    OnApEnableOrDisable(status, id);
}

HWTEST_F(wifi_idl_inner_interface_test, OnConnectChangedTest, TestSize.Level1)
{
    int status = 1;
    int networkId = 1;
    char *mac = nullptr;
    OnConnectChanged(status, networkId, mac);
}

HWTEST_F(wifi_idl_inner_interface_test, OnBssidChangedTest, TestSize.Level1)
{
    char *rea = nullptr;
    char *bss = nullptr;
    OnBssidChanged(rea, bss);
    char reason[] = "none";
    OnBssidChanged(reason, bss);
    char bssid[] = "00:00:AA:BB:CC:DD";
    OnBssidChanged(reason, bssid);
}

HWTEST_F(wifi_idl_inner_interface_test, OnWpaStateChangedTest, TestSize.Level1)
{
    int status = 1;
    OnWpaStateChanged(status);
    OnWpaSsidWrongKey(status);
    OnWpaConnectionFull(status);
    OnWpaConnectionReject(status);
    OnWpsOverlap(status);
    OnWpsTimeOut(status);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pDeviceFoundTest, TestSize.Level1)
{
    P2pDeviceInfo* info = nullptr;
    OnP2pDeviceFound(info);
    P2pDeviceInfo information;
    information.srcAddress = "AA:BB:CC:DD:EE:FF";
    information.p2pDeviceAddress = "AA:BB:CC:DD:EE:FF";
    information.primaryDeviceType = "NONE";
    information.configMethods = 1;
    information.deviceCapabilities = 1;
    information.groupCapabilities = 1;
    information.wfdDeviceInfo = "tv";
    information.wfdLength = LENTH;
    OnP2pDeviceFound(information);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pDeviceLostTest, TestSize.Level1)
{
    char *p2pDevic = nullptr;
    OnP2pDeviceLost(p2pDevic);
    char p2pDeviceAddress[] = "00:00:AA:BB:CC:DD";
    OnP2pDeviceLost(&p2pDeviceAddress);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGoNegotiationRequestTest, TestSize.Level1)
{
    char *srcAdd = nullptr;
    short passwordId = 1;
    OnP2pGoNegotiationRequest(srcAdd, passwordId);
    char srcAddress = "00:00:AA:BB:CC:DD";
    OnP2pGoNegotiationRequest(&srcAddress, passwordId);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGoNegotiationSuccessTest, TestSize.Level1)
{
    OnP2pGoNegotiationSuccess();
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGoNegotiationFailureTest, TestSize.Level1)
{
    int status = 1;
    OnP2pGoNegotiationFailure(status);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pInvitationResultTest, TestSize.Level1)
{
    char *bssid = nullptr;
    int status = 1;
    OnP2pInvitationResult(bssid, status);
    char *bssid = "00:00:AA:BB:CC:DD";
    OnP2pInvitationResult(&bssid, status);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pInvitationReceivedTest, TestSize.Level1)
{
    P2pInvitationInfo *info = nullptr;
    OnP2pDeviceLost(info);
    P2pInvitationInfo information;
    information.type = 1;
    information.persistentNetworkId = 1;
    information.operatingFrequency = 1;
    information.srcAddress = "00:00:AA:BB:CC:DD";
    information.goDeviceAddress = "00:11:AA:BB:CC:DD";
    information.bssid = "00:22:AA:BB:CC:DD";
    OnP2pDeviceLost(&information);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGroupFormationSuccessTest, TestSize.Level1)
{
    OnP2pGroupFormationSuccess();
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGroupFormationFailureTest, TestSize.Level1)
{
    char *failure = nullptr;
    OnP2pGroupFormationFailure(failure);
    char *failureReason = "test";
    OnP2pGroupFormationFailure(failureReason);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGroupStartedTest, TestSize.Level1)
{
    P2pGroupInfo *group = nullptr;
    OnP2pGroupStarted(group);
    P2pGroupInfo groupInfo;
    groupInfo.isGo = 1;
    groupInfo.isPersistent = 0;
    groupInfo.frequency = 1;
    groupInfo.ssid = "hauwei";
    OnP2pGroupStarted(&groupInfo);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pGroupRemovedTest, TestSize.Level1)
{
    char *groupIfName = nullptr;
    int isGo = 1;
    OnP2pGroupRemoved(groupIfName, isGo);
    char *groupIfName = "huawei";
    OnP2pGroupRemoved(groupIfName);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pProvisionDiscoveryTest, TestSize.Level1)
{
    char *p2pDeviceAdd = nullptr;
    OnP2pProvisionDiscoveryPbcRequest(p2pDeviceAdd);
    OnP2pProvisionDiscoveryPbcResponse(p2pDeviceAdd);
    OnP2pProvisionDiscoveryEnterPin(p2pDeviceAdd);
    char *p2pDeviceAddress = "00:22:AA:BB:CC:DD";
    OnP2pProvisionDiscoveryPbcRequest(p2pDeviceAddress);
    OnP2pProvisionDiscoveryPbcResponse(p2pDeviceAddress);
    OnP2pProvisionDiscoveryEnterPin(p2pDeviceAddress);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pProvisionDiscoveryShowPinTest, TestSize.Level1)
{
    char *p2pDeviceAddress = nullptr;
    char *generatedPin = nullptr;
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAddress, generatedPin);
    char *p2pDeviceAdd = "00:22:AA:BB:CC:DD";
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAdd, generatedPin);
    char *Pin = "test";
    OnP2pProvisionDiscoveryShowPin(p2pDeviceAdd, Pin);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pProvisionDiscoveryFailureTest, TestSize.Level1)
{
    OnP2pProvisionDiscoveryFailure();
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pFindStoppedTest, TestSize.Level1)
{
    OnP2pFindStopped();
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pServiceDiscoveryResponseTest, TestSize.Level1)
{
    char *srcAddress = nullptr;
    short updateIndicator = 1;
    unsigned char *tlvs = "test";
    size_t tlvsLength = 1;
    OnP2pServiceDiscoveryResponse(srcAddress, updateIndicator, tlvs, tlvsLength);
    char *srcAddress = "AA:BB:CC:DD:EE:FF";
    OnP2pServiceDiscoveryResponse(srcAddress, updateIndicator, tlvs, tlvsLength);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pStaDeauthorizedTest, TestSize.Level1)
{
    char *p2pDeviceAddress = nullptr;
    OnP2pStaDeauthorized(p2pDeviceAddress);
    OnP2pStaAuthorized(p2pDeviceAddress);
    char *p2pDeviceAdd = "AA:BB:CC:DD:EE:FF";
    OnP2pStaDeauthorized(p2pDeviceAdd);
    OnP2pStaAuthorized(p2pDeviceAdd);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pConnectSupplicantFailedTest, TestSize.Level1)
{
    OnP2pConnectSupplicantFailed();
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pServDiscReqTest, TestSize.Level1)
{
    P2pServDiscReqInfo *info = nullptr;
    OnP2pServDiscReq(info);
    P2pServDiscReqInfo infomation;
    infomation.tlvsLength = LENTH;
    infomation.tlvs = "AABBCCDDEEFFGGHH";
    OnP2pServDiscReq(&info);
}

HWTEST_F(wifi_idl_inner_interface_test, OnP2pIfaceCreatedTest, TestSize.Level1)
{
    char *ifName = "TV";
    int isGo = 1;
    OnP2pIfaceCreated(ifName, isGo);
}
}  // namespace Wifi
}  // namespace OHOS