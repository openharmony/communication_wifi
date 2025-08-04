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

#ifndef OHOS_MOCK_P2P_INTERFACE_H
#define OHOS_MOCK_P2P_INTERFACE_H
#include "ip2p_service.h"

namespace OHOS {
namespace Wifi {
class P2pInterface {
public:
    P2pInterface();
    ~P2pInterface() = default;

public:
    virtual ErrCode EnableP2p();
    virtual ErrCode DisableP2p();
    virtual ErrCode DiscoverDevices();
    virtual ErrCode StopDiscoverDevices();
    virtual ErrCode DiscoverServices();
    virtual ErrCode StopDiscoverServices();
    virtual ErrCode PutLocalP2pService(const WifiP2pServiceInfo &srvInfo);
    virtual ErrCode DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo);
    virtual ErrCode RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request);
    virtual ErrCode StartP2pListen(int period, int interval);
    virtual ErrCode StopP2pListen();
    virtual ErrCode CreateGroup(const WifiP2pConfig &config);
    virtual ErrCode RemoveGroup();
    virtual ErrCode DeleteGroup(const WifiP2pGroupInfo &group);
    virtual ErrCode P2pConnect(const WifiP2pConfig &config);
    virtual ErrCode P2pCancelConnect();
    virtual ErrCode SetP2pDeviceName(const std::string &devName);
    virtual ErrCode QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo);
    virtual ErrCode SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo);
    virtual ErrCode GetCurrentGroup(WifiP2pGroupInfo &group);
    virtual ErrCode GetP2pEnableStatus(int &status);
    virtual ErrCode GetP2pDiscoverStatus(int &status);
    virtual ErrCode GetP2pConnectedStatus(int &status);
    virtual ErrCode QueryP2pDevices(std::vector<WifiP2pDevice> &devices);
    virtual ErrCode QueryP2pLocalDevice(WifiP2pDevice &device);
    virtual ErrCode QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups);
    virtual ErrCode QueryP2pServices(std::vector<WifiP2pServiceInfo> &services);
    virtual ErrCode RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks);
    virtual ErrCode UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks);
    virtual ErrCode Hid2dCreateGroup(const int frequency, FreqType type);
    virtual ErrCode Hid2dConnect(const Hid2dConnectConfig& config);
    virtual ErrCode Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr);
    void IncreaseSharedLink(int callingUid);
    void DecreaseSharedLink(int callingUid);
    virtual ErrCode HandleBusinessSAException(int systemAbilityId);
    int GetP2pRecommendChannel(void);
    virtual ErrCode Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene);
    virtual ErrCode MonitorCfgChange(void) ;
    virtual ErrCode DiscoverPeers(int32_t channelid);
    virtual ErrCode DisableRandomMac(int setmode);
    virtual ErrCode CreateRptGroup(const WifiP2pConfig &config);
    virtual ErrCode GetRptStationsList(std::vector<StationInfo> &result);
    virtual void NotifyWscDialogConfirmResult(bool isAccept);
    virtual ErrCode SetMiracastSinkConfig(const std::string& config);
    virtual ErrCode NotifyRemoteDie(int uid);
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // OHOS_P2P_INTERFACE_H
