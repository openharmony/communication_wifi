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

#ifndef OHOS_P2P_SERVICE_H
#define OHOS_P2P_SERVICE_H

#include "wifi_errcode.h"
#include "p2p_define.h"
#include "ip2p_service.h"
#include "ip2p_service_callbacks.h"
#include "p2p_state_machine.h"

namespace OHOS {
namespace Wifi {
class WifiP2pService : public IP2pService {
public:
    /**
     * @Description Construct a new WifiP2pService object.
     */
    explicit WifiP2pService(P2pStateMachine &p2pStateMachine, WifiP2pDeviceManager &setDeviceMgr,
        WifiP2pGroupManager &setGroupMgr, WifiP2pServiceManager &setSvrMgr);
    /**
     * @Description Destroy the WifiP2pService object.
     */
    virtual ~WifiP2pService() override;

public:
    /**
     * @Description - Enable the P2P mode.
     * @return ErrCode - operation result
     */
    virtual ErrCode EnableP2p() override;
    /**
     * @Description - Disable the P2P mode.
     * @return ErrCode - operation result
     */
    virtual ErrCode DisableP2p() override;
    /**
     * @Description - Start P2P device search.
     * @return ErrCode - operation result
     */
    virtual ErrCode DiscoverDevices() override;
    /**
     * @Description - Stop P2P device search.
     * @return ErrCode - operation result
     */
    virtual ErrCode StopDiscoverDevices() override;
    /**
     * @Description - Start P2P service search.
     * @return ErrCode - operation result
     */
    virtual ErrCode DiscoverServices() override;
    /**
     * @Description - Stop P2P service search.
     * @return ErrCode - operation result
     */
    virtual ErrCode StopDiscoverServices() override;
    /**
     * @Description - Register the local P2P service.
     * @param  srvInfo - local service information
     * @return ErrCode - operation result
     */
    virtual ErrCode PutLocalP2pService(const WifiP2pServiceInfo &srvInfo) override;
    /**
     * @Description - Delete the local P2P service.
     * @param  srvInfo - local service information
     * @return ErrCode - operation result
     */
    virtual ErrCode DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo) override;

    /**
     * @Description - Request specified services.
     * @param  device - requested target device
     * @param  request - initiated service request data
     * @return ErrCode - operation result
     */
    virtual ErrCode RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request) override;
    /**
     * @Description - Start the P2P listening. Unit: millisecond.
     * @param  period - listening period
     * @param  interval - listening interval
     * @return ErrCode - operation result
     */
    virtual ErrCode StartP2pListen(int period, int interval) override;
    /**
     * @Description - Stop the P2P listening.
     * @return ErrCode - operation result
     */
    virtual ErrCode StopP2pListen() override;
    /**
     * @Description - Create a P2P group.
     * @param  config - config for creating group
     * @return ErrCode - operation result
     */
    virtual ErrCode CreateGroup(const WifiP2pConfig &config) override;
    /**
     * @Description - Remove the current P2P group.
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveGroup() override;
    /**
     * @Description - Delete a persistent group.
     * @param  group - specified group
     * @return ErrCode - operation result
     */
    virtual ErrCode DeleteGroup(const WifiP2pGroupInfo &group) override;
    /**
     * @Description - Connect to a P2P device.
     * @param  config - config for connection
     * @return ErrCode - operation result
     */
    virtual ErrCode P2pConnect(const WifiP2pConfig &config) override;
    /**
     * @Description - Canceling a P2P connection.
     * @return ErrCode - operation result
     */
    virtual ErrCode P2pCancelConnect() override;
    /**
     * @Description - Set this device name.
     *
     * @param devName - specified device name
     * @return ErrCode
     */
    virtual ErrCode SetP2pDeviceName(const std::string &devName) override;
    /**
     * @Description - Query P2P connection information.
     * @param  linkedInfo - object that stores connection information
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo) override;
    /**
     * @Description - Get the current group information.
     * @param  group - object that stores the current group
     * @return ErrCode - operation result
     */
    virtual ErrCode GetCurrentGroup(WifiP2pGroupInfo &group) override;
    /**
     * @Description - Obtain the P2P status.
     * @param  status - object that stores P2P status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pEnableStatus(int &status) override;
    /**
     * @Description - Obtain the P2P discovery status.
     * @param  status - object that stores discovery status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pDiscoverStatus(int &status) override;
    /**
     * @Description - Obtain the P2P connection status.
     * @param  status - object that stores connection status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pConnectedStatus(int &status) override;
    /**
     * @Description - Query the information about the found devices.
     * @param  devices - list of queryed device
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pDevices(std::vector<WifiP2pDevice> &devices) override;
    /**
     * @Description - Query the information about own device.
     * @param  device - own device
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pLocalDevice(WifiP2pDevice &device) override;
    /**
     * @Description - Obtain information about all groups.
     * @param  groups - list of group information
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups) override;
    /**
     * @Description - Query the information about the found services.
     * @param  services - list of service information
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pServices(std::vector<WifiP2pServiceInfo> &services) override;
    /**
     * @Description - Register all callbacks provided by the P2P.
     * @param  callbacks - all callbacks added
     * @return ErrCode - operation result
     */
    virtual ErrCode RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks) override;

    /**
     * @Description set p2p wifi display info
     *
     * @param wfdInfo - wifi display info
     * @return ErrCode - operation result
     */
    virtual ErrCode SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo) override;

    /**
     * @Description Create hid2d group, used on the GO side.
     *
     * @param frequency - frequency
     * @param type - frequency type
     * @return ErrCode - operation result
     */
    virtual ErrCode Hid2dCreateGroup(const int frequency, FreqType type) override;

    /**
     * @Description Connect to a specified group using hid2d, used on the GC side.
     *
     * @param config - connection parameters
     * @return ErrCode - operation result
     */
    virtual ErrCode Hid2dConnect(const Hid2dConnectConfig& config) override;

    /**
     * @Description Get self config info
     *
     * @param cfgType - config type
     * @param cfgData - config data
     * @param getDatValidLen - data length
     * @return ErrCode - operate result
     */
    virtual ErrCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType,
        char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen) override;

    /**
     * @Description Set self config info
     *
     * @param cfgType - config type
     * @param cfgData - config data
     * @param setDataValidLen - data length
     * @return ErrCode - operate result
     */
    virtual ErrCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType,
        char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen) override;

    /**
     * @Description Set self config info
     *
     * @param gcMac - gc mac address
     * @param ipAddr - allocated ip address
     * @return ErrCode - operate result
     */
    virtual ErrCode Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr) override;

    /**
     * @Description Increase the reference count of the hid2d service.
     *
     */
    virtual void IncreaseSharedLink(void) override;

    /**
     * @Description Decrease the reference count of the hid2d service.
     *
     */
    virtual void DecreaseSharedLink(void) override;

    /**
     * @Description Get the reference count of the hid2d service.
     *
     * @return int - reference count
     */
    virtual int GetSharedLinkCount(void) override;

    /**
     * @Description - Get P2P recommended channel.
     *
     * @return - int - Recommended channel
     */
    virtual int GetP2pRecommendChannel(void) override;

    /**
     * @Description Set the scene of upper layer
     *
     * @param ifName - interface name
     * @param scene - scene
     * @return ErrCode - operate result
     */
    virtual ErrCode Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene) override;

    /**
     * @Description Monitor the wifi configuration change
     *
     * @return ErrCode - operate result
     */
    virtual ErrCode MonitorCfgChange(void) override;

private:
    /**
     * @Description - P2P state machine deregistration event callback.
     */
    virtual void UnRegisterP2pServiceCallbacks();

private:
    P2pStateMachine &p2pStateMachine;
    WifiP2pDeviceManager &deviceManager; /* device manager */
    WifiP2pGroupManager &groupManager;   /* group manager */
    WifiP2pServiceManager &serviceManager;
};
}  // namespace Wifi
}  // namespace OHOS

#endif  /* OHOS_P2P_SERVICE_H */
