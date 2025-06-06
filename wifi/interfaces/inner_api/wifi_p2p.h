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

#ifndef OHOS_WIFI_P2P_H
#define OHOS_WIFI_P2P_H

#include "wifi_errcode.h"
#include "wifi_p2p_msg.h"
#include "i_wifi_p2p_callback.h"

namespace OHOS {
namespace Wifi {
class WifiP2p {
public:
    static std::shared_ptr<WifiP2p> GetInstance(int system_ability_id);

    virtual ~WifiP2p();

    /**
     * @Description Enabling the P2P Mode.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode EnableP2p(void) = 0;

    /**
     * @Description Disable the P2P mode.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode DisableP2p(void) = 0;

    /**
     * @Description Start Wi-Fi P2P device search.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode DiscoverDevices(void) = 0;

    /**
     * @Description Stop Wi-Fi P2P device search.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode StopDiscoverDevices(void) = 0;

    /**
     * @Description Start the search for the Wi-Fi P2P service.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode DiscoverServices(void) = 0;

    /**
     * @Description Stop the search for the Wi-Fi P2P service.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode StopDiscoverServices(void) = 0;

    /**
     * @Description request the P2P service.
     *
     * @param device - WifiP2pDevice object
     * @param request - WifiP2pServiceRequest object
     * @return ErrCode - operation result
     */
    virtual ErrCode RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request) = 0;

    /**
     * @Description Register the local P2P service.
     *
     * @param srvInfo - WifiP2pServiceInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode PutLocalP2pService(const WifiP2pServiceInfo &srvInfo) = 0;

    /**
     * @Description Delete the local P2P service.
     *
     * @param srvInfo - WifiP2pServiceInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo) = 0;

    /**
     * @Description Enable Wi-Fi P2P listening.
     *
     * @param period - period
     * @param interval - interval
     * @return ErrCode - operation result
     */
    virtual ErrCode StartP2pListen(int period, int interval) = 0;

    /**
     * @Description Disable Wi-Fi P2P listening.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode StopP2pListen(void) = 0;

    /**
     * @Description Creating a P2P Group.
     *
     * @param config - WifiP2pConfig object
     * @return ErrCode - operation result
     */
    virtual ErrCode CreateGroup(const WifiP2pConfig &config) = 0;

    /**
     * @Description Remove a P2P Group.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveGroup(void) = 0;

    /**
     * @Description Remove a P2P client of current group.
     *
     * @param deviceMac - client deviceMac address
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveGroupClient(const GcInfo &info) = 0;

    /**
     * @Description Delete a p2p Group.
     *
     * @param group - WifiP2pGroupInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode DeleteGroup(const WifiP2pGroupInfo &group) = 0;

    /**
     * @Description P2P connection.
     *
     * @param config - WifiP2pConfig object
     * @return ErrCode - operation result
     */
    virtual ErrCode P2pConnect(const WifiP2pConfig &config) = 0;

    /**
     * @Description Canceling a P2P connection.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode P2pCancelConnect(void) = 0;

    /**
     * @Description Querying Wi-Fi P2P Connection Information.
     *
     * @param linkedInfo - Get the WifiP2pLinkedInfo msg
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo) = 0;

    /**
     * @Description Get the Current Group object.
     *
     * @param group - the WifiP2pGroupInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode GetCurrentGroup(WifiP2pGroupInfo &group) = 0;

    /**
     * @Description Obtains the P2P switch status.
     *
     * @param status - the P2P switch status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pEnableStatus(int &status) = 0;

    /**
     * @Description Obtains the P2P discovery status.
     *
     * @param status - the P2P discovery status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pDiscoverStatus(int &status) = 0;

    /**
     * @Description Obtains the P2P connection status.
     *
     * @param status - the P2P connection status
     * @return ErrCode - operation result
     */
    virtual ErrCode GetP2pConnectedStatus(int &status) = 0;

    /**
     * @Description Query the local device information.
     *
     * @param devives - Get result of WifiP2pDevice
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pLocalDevice(WifiP2pDevice &device) = 0;

    /**
     * @Description Query the information about the found devices.
     *
     * @param devices - Get result vector of WifiP2pDevice
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pDevices(std::vector<WifiP2pDevice> &devices) = 0;

    /**
     * @Description Query the information about the found groups.
     *
     * @param groups - Get result vector of WifiP2pGroupInfo
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups) = 0;

    /**
     * @Description Query the service information.
     *
     * @param services - Get result vector of Device
     * @return ErrCode - operation result
     */
    virtual ErrCode QueryP2pServices(std::vector<WifiP2pServiceInfo> &services) = 0;

    /**
     * @Description Register callback function.
     *
     * @param callback - IWifiP2pCallback object
     * @return ErrCode - operation result
     */
    virtual ErrCode RegisterCallBack(const sptr<IWifiP2pCallback> &callback, const std::vector<std::string> &event) = 0;

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    virtual ErrCode GetSupportedFeatures(long &features) = 0;

    /**
     * @Description Check if supported input feature
     *
     * @param feature - input feature
     * @return bool - true if supported, false if unsupported
     */
    virtual bool IsFeatureSupported(long feature) = 0;

    /**
     * @Description set the device name
     *
     * @param deviceName - device name
     * @return ErrCode - operation result
     */
    virtual ErrCode SetP2pDeviceName(const std::string &deviceName) = 0;

    /**
     * @Description set p2p wifi display info
     *
     * @param wfdInfo - wifi display info
     * @return ErrCode - operation result
     */
    virtual ErrCode SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo) = 0;

    /**
     * @Description set p2p wifi display info
     *
     * @param wfdInfo - wifi display info
     * @return ErrCode - operation result
     */
    virtual ErrCode DiscoverPeers(int32_t channelid) = 0;

    /**
     * @Description set p2p wifi display info
     *
     * @param wfdInfo - wifi display info
     * @return ErrCode - operation result
     */
    virtual ErrCode DisableRandomMac(int setmode) = 0;

    /**
     * @Description Check can use P2P
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode CheckCanUseP2p() = 0;

    /**
     * @Description Set miracast sink config
     *
     * @param config - miracast config
     * @return ErrCode - operation result
     */
    virtual ErrCode SetMiracastSinkConfig(const std::string& config) = 0;

    /**
     * @Description Get support channels for band
     *
     * @param channels - support channels
     * @param band - channel band
     * @return ErrCode - operation result
     */
    virtual ErrCode GetSupportedChanForBand(std::vector<int> &channels, int band) = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif