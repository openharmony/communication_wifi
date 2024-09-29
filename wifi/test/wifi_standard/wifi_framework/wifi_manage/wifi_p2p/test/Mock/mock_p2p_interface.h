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
class P2pInterface : public IP2pService {
public:
    P2pInterface();
    ~P2pInterface() = default;

public:
    virtual ErrCode EnableP2p() override;
    virtual ErrCode DisableP2p() override;
    virtual ErrCode DiscoverDevices() override;
    virtual ErrCode StopDiscoverDevices() override;
    virtual ErrCode DiscoverServices() override;
    virtual ErrCode StopDiscoverServices() override;
    virtual ErrCode PutLocalP2pService(const WifiP2pServiceInfo &srvInfo) override;
    virtual ErrCode DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo) override;
    virtual ErrCode RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request) override;
    virtual ErrCode StartP2pListen(int period, int interval) override;
    virtual ErrCode StopP2pListen() override;
    virtual ErrCode CreateGroup(const WifiP2pConfig &config) override;
    virtual ErrCode RemoveGroup() override;
    virtual ErrCode DeleteGroup(const WifiP2pGroupInfo &group) override;
    virtual ErrCode P2pConnect(const WifiP2pConfig &config) override;
    virtual ErrCode P2pCancelConnect() override;
    virtual ErrCode SetP2pDeviceName(const std::string &devName) override;
    virtual ErrCode QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo) override;
    virtual ErrCode SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo) override;
    virtual ErrCode GetCurrentGroup(WifiP2pGroupInfo &group) override;
    virtual ErrCode GetP2pEnableStatus(int &status) override;
    virtual ErrCode GetP2pDiscoverStatus(int &status) override;
    virtual ErrCode GetP2pConnectedStatus(int &status) override;
    virtual ErrCode QueryP2pDevices(std::vector<WifiP2pDevice> &devices) override;
    virtual ErrCode QueryP2pLocalDevice(WifiP2pDevice &device) override;
    virtual ErrCode QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups) override;
    virtual ErrCode QueryP2pServices(std::vector<WifiP2pServiceInfo> &services) override;
    virtual ErrCode RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks) override;
    virtual ErrCode UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks) override;
    virtual ErrCode Hid2dCreateGroup(const int frequency, FreqType type) override;
    virtual ErrCode Hid2dConnect(const Hid2dConnectConfig& config) override;
    virtual ErrCode Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr) override;
    void IncreaseSharedLink(int callingUid) override;
    void DecreaseSharedLink(int callingUid) override;
    virtual ErrCode HandleBusinessSAException(int systemAbilityId) override;
    int GetP2pRecommendChannel(void) override;
    virtual ErrCode Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene) override;
    virtual ErrCode MonitorCfgChange(void)  override;
    virtual ErrCode DiscoverPeers(int32_t channelid) override;
    virtual ErrCode DisableRandomMac(int setmode) override;
    virtual ErrCode CreateRptGroup(const WifiP2pConfig &config) override;
    virtual ErrCode GetRptStationsList(std::vector<StationInfo> &result) override;
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // OHOS_P2P_INTERFACE_H
