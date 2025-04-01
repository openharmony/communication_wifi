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

#include "mock_p2p_interface.h"
#include "wifi_internal_msg.h"


namespace OHOS {
namespace Wifi {

P2pInterface::P2pInterface()
{}

ErrCode P2pInterface::EnableP2p()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DisableP2p()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DiscoverDevices()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::StopDiscoverDevices()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DiscoverServices()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::StopDiscoverServices()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::PutLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::StartP2pListen(int period, int interval)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::StopP2pListen()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::CreateGroup(const WifiP2pConfig &config)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::RemoveGroup()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DeleteGroup(const WifiP2pGroupInfo &group)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::P2pConnect(const WifiP2pConfig &config)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::P2pCancelConnect()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::SetP2pDeviceName(const std::string &devName)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::GetCurrentGroup(WifiP2pGroupInfo &group)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::GetP2pEnableStatus(int &status)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::GetP2pDiscoverStatus(int &status)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::GetP2pConnectedStatus(int &status)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::QueryP2pDevices(std::vector<WifiP2pDevice> &devices)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::QueryP2pLocalDevice(WifiP2pDevice &device)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::QueryP2pServices(std::vector<WifiP2pServiceInfo> &services)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::Hid2dCreateGroup(const int frequency, FreqType type)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::Hid2dConnect(const Hid2dConnectConfig& config)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr)
{
    return WIFI_OPT_SUCCESS;
}

void P2pInterface::IncreaseSharedLink(int callingUid)
{
    return;
}

void P2pInterface::DecreaseSharedLink(int callingUid)
{
    return;
}

ErrCode P2pInterface::HandleBusinessSAException(int systemAbilityId)
{
    return WIFI_OPT_SUCCESS;
}

int P2pInterface::GetP2pRecommendChannel(void)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::MonitorCfgChange(void)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DiscoverPeers(int32_t channelid)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::DisableRandomMac(int setmode)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::CreateRptGroup(const WifiP2pConfig &config)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode P2pInterface::GetRptStationsList(std::vector<StationInfo> &result)
{
    return WIFI_OPT_SUCCESS;
}

void P2pInterface::NotifyWscDialogConfirmResult(bool isAccept)
{
    return;
}

ErrCode P2pInterface::SetMiracastSinkConfig(const std::string& config)
{
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
