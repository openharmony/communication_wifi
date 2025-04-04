/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "p2p_interface.h"
#include "wifi_internal_msg.h"
#include "wifi_logger.h"


namespace OHOS {
namespace Wifi {
P2pInterface::P2pInterface()
    : p2pAuthorizingNegotiationRequestState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupFormedState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupNegotiationState(p2pStateMachine, groupManager, deviceMgr),
      p2pInvitationReceivedState(p2pStateMachine, groupManager, deviceMgr),
      p2pInvitationRequestState(p2pStateMachine, groupManager, deviceMgr),
      p2pDefaultState(p2pStateMachine),
      p2pDisabledState(p2pStateMachine, groupManager, deviceMgr, svrMgr),
      p2pDisablingState(p2pStateMachine, groupManager, deviceMgr),
      p2pEnabledState(p2pStateMachine, groupManager, deviceMgr),
      p2pEnablingState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupFormationState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupJoinState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupOperatingState(p2pStateMachine, groupManager, deviceMgr),
      p2pIdleState(p2pStateMachine, groupManager, deviceMgr),
      p2pInvitingState(p2pStateMachine, groupManager, deviceMgr),
      p2pProvisionDiscoveryState(p2pStateMachine, groupManager, deviceMgr),
      p2pGroupRemoveState(),

      p2pStateMachine(p2pMonitor, groupManager, deviceMgr, svrMgr, p2pAuthorizingNegotiationRequestState,
          p2pGroupFormedState, p2pGroupNegotiationState, p2pInvitationReceivedState, p2pInvitationRequestState,
          p2pDefaultState, p2pDisabledState, p2pDisablingState, p2pEnabledState, p2pEnablingState,
          p2pGroupFormationState, p2pGroupJoinState, p2pGroupOperatingState, p2pIdleState, p2pInvitingState,
          p2pProvisionDiscoveryState, p2pGroupRemoveState),
      p2pService(p2pStateMachine, deviceMgr, groupManager, svrMgr)
{}

extern "C" IP2pService *CreateP2pInterface()
{
    return new P2pInterface();
}

extern "C" void DestroyP2pInterface(IP2pService *p2pInterface)
{
    delete p2pInterface;
    p2pInterface = nullptr;
}

ErrCode P2pInterface::EnableP2p()
{
    return p2pService.EnableP2p();
}

ErrCode P2pInterface::DisableP2p()
{
    return p2pService.DisableP2p();
}

ErrCode P2pInterface::DiscoverDevices()
{
    return p2pService.DiscoverDevices();
}

ErrCode P2pInterface::StopDiscoverDevices()
{
    return p2pService.StopDiscoverDevices();
}

ErrCode P2pInterface::DiscoverServices()
{
    return p2pService.DiscoverServices();
}

ErrCode P2pInterface::StopDiscoverServices()
{
    return p2pService.StopDiscoverServices();
}

ErrCode P2pInterface::PutLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    return p2pService.PutLocalP2pService(srvInfo);
}

ErrCode P2pInterface::DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    return p2pService.DeleteLocalP2pService(srvInfo);
}

ErrCode P2pInterface::RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request)
{
    return p2pService.RequestService(device, request);
}

ErrCode P2pInterface::StartP2pListen(int period, int interval)
{
    return p2pService.StartP2pListen(period, interval);
}

ErrCode P2pInterface::StopP2pListen()
{
    return p2pService.StopP2pListen();
}

ErrCode P2pInterface::CreateGroup(const WifiP2pConfig &config)
{
    return p2pService.CreateGroup(config);
}

ErrCode P2pInterface::RemoveGroup()
{
    return p2pService.RemoveGroup();
}

ErrCode P2pInterface::RemoveGroupClient(const GcInfo &info)
{
    return p2pService.RemoveGroupClient(info);
}

ErrCode P2pInterface::DeleteGroup(const WifiP2pGroupInfo &group)
{
    return p2pService.DeleteGroup(group);
}

ErrCode P2pInterface::CreateRptGroup(const WifiP2pConfig &config)
{
    return p2pService.CreateRptGroup(config);
}

ErrCode P2pInterface::GetRptStationsList(std::vector<StationInfo> &result)
{
    return p2pService.GetRptStationsList(result);
}

ErrCode P2pInterface::P2pConnect(const WifiP2pConfig &config)
{
    return p2pService.P2pConnect(config);
}

ErrCode P2pInterface::P2pCancelConnect()
{
    return p2pService.P2pCancelConnect();
}

ErrCode P2pInterface::SetP2pDeviceName(const std::string &devName)
{
    return p2pService.SetP2pDeviceName(devName);
}

ErrCode P2pInterface::SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo)
{
    return p2pService.SetP2pWfdInfo(wfdInfo);
}

ErrCode P2pInterface::QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo)
{
    return p2pService.QueryP2pLinkedInfo(linkedInfo);
}

ErrCode P2pInterface::GetCurrentGroup(WifiP2pGroupInfo &group)
{
    return p2pService.GetCurrentGroup(group);
}

ErrCode P2pInterface::GetP2pEnableStatus(int &status)
{
    return p2pService.GetP2pEnableStatus(status);
}

ErrCode P2pInterface::GetP2pDiscoverStatus(int &status)
{
    return p2pService.GetP2pDiscoverStatus(status);
}

ErrCode P2pInterface::GetP2pConnectedStatus(int &status)
{
    return p2pService.GetP2pConnectedStatus(status);
}

ErrCode P2pInterface::QueryP2pDevices(std::vector<WifiP2pDevice> &devices)
{
    return p2pService.QueryP2pDevices(devices);
}

ErrCode P2pInterface::QueryP2pLocalDevice(WifiP2pDevice &device)
{
    return p2pService.QueryP2pLocalDevice(device);
}

ErrCode P2pInterface::QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups)
{
    return p2pService.QueryP2pGroups(groups);
}

ErrCode P2pInterface::QueryP2pServices(std::vector<WifiP2pServiceInfo> &services)
{
    return p2pService.QueryP2pServices(services);
}

ErrCode P2pInterface::RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    return p2pService.RegisterP2pServiceCallbacks(callbacks);
}

ErrCode P2pInterface::UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    return p2pService.UnRegisterP2pServiceCallbacks(callbacks);
}

ErrCode P2pInterface::Hid2dCreateGroup(const int frequency, FreqType type)
{
    return p2pService.Hid2dCreateGroup(frequency, type);
}

ErrCode P2pInterface::Hid2dConnect(const Hid2dConnectConfig& config)
{
    return p2pService.Hid2dConnect(config);
}

ErrCode P2pInterface::Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr)
{
    return p2pService.Hid2dRequestGcIp(gcMac, ipAddr);
}

void P2pInterface::IncreaseSharedLink(int callingUid)
{
    p2pService.IncreaseSharedLink(callingUid);
}

void P2pInterface::DecreaseSharedLink(int callingUid)
{
    p2pService.DecreaseSharedLink(callingUid);
}

ErrCode P2pInterface::HandleBusinessSAException(int systemAbilityId)
{
    return p2pService.HandleBusinessSAException(systemAbilityId);
}

int P2pInterface::GetP2pRecommendChannel(void)
{
    return p2pService.GetP2pRecommendChannel();
}

ErrCode P2pInterface::Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene)
{
    return p2pService.Hid2dSetUpperScene(ifName, scene);
}

ErrCode P2pInterface::MonitorCfgChange(void)
{
    return p2pService.MonitorCfgChange();
}

ErrCode P2pInterface::DiscoverPeers(int32_t channelid)
{
    return p2pService.DiscoverPeers(channelid);
}

ErrCode P2pInterface::DisableRandomMac(int setmode)
{
    return p2pService.DisableRandomMac(setmode);
}

ErrCode P2pInterface::SetGcIpAddress(const IpAddrInfo& ipInfo)
{
    return p2pService.SetGcIpAddress(ipInfo);
}

ErrCode P2pInterface::SetEnhanceService(IEnhanceService* enhanceService)
{
    return p2pService.SetEnhanceService(enhanceService);
}

void P2pInterface::NotifyWscDialogConfirmResult(bool isAccept)
{
    return p2pService.NotifyWscDialogConfirmResult(isAccept);
}

ErrCode P2pInterface::SetMiracastSinkConfig(const std::string& config)
{
    return p2pService.SetMiracastSinkConfig(config);
}
}  // namespace Wifi
}  // namespace OHOS
