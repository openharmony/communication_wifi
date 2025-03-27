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
#ifndef OHOS_IENHANCE_SERVICE_H
#define OHOS_IENHANCE_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_scan_control_msg.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
using P2pEnhanceCallback = std::function<void(const std::string &, int32_t, int32_t)>;
using P2pEnhanceActionListenCallback = std::function<void(int)>;
class IEnhanceService {
public:
    virtual ~IEnhanceService() = default;
    /**
     * @Description  Enhance service initialization function.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode Init() = 0;
    /**
     * @Description  Stopping the Enhance Service.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode UnInit() = 0;
    /**
     * @Description  check Scan is allowed.
     *
     * @return true: allowed, false: not allowed
     */
    virtual bool AllowScanBySchedStrategy() = 0;
    /**
     * @Description  Set EnhanceService Param.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetEnhanceParam(int64_t availableTime) = 0;

    /**
     * @Description Install Paket Filter Program
     *
     * @param ipAddr - ip address
     * @param netMaskLen - net mask length
     * @param macAddr - mac address
     * @param macLen - mac address length
     * @param screenState - screen state
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode InstallFilterProgram(
        unsigned int ipAddr, int netMaskLen, const unsigned char *macAddr, int macLen, int screenState) = 0;

    /**
     * @Description Get wifi category
     *
     * @param infoElems - info elems
     * @param chipsetCategory - chipset category
     * @param chipsetFeatrureCapability - chipset featrure capability
     * @return 1: DEFAULT, 2: WIFI6, 3: WIFI6_PLUS, 4: WIFI7, 5: WIFI7_PLUS
     */
    virtual WifiCategory GetWifiCategory(
        std::vector<WifiInfoElem> infoElems, int chipsetCategory, int chipsetFeatrureCapability) = 0;

    /**
     * @Description set low tx power
     *
     * @param wifiLowPowerParam - wifi low power param
     * @return ErrCode - operation result
     */
    virtual ErrCode SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam) = 0;
    
    /**
     * @Description Notify internet state
     *
     * @param netState - net state
     */
    virtual void NotifyInternetState(const int netState) = 0;

    /**
     * @Description Notify wur state
     *
     * @param wurState - wur state
     * @param reasonCode - reason code
     */
    virtual void NotifyWurState(const int wurState, const uint16_t reasonCode) = 0;
    
    /**
     * @Description Notify wifi netlink message
     *
     * @param type - wifi netlink message type
     * @param recvMsg - wifi netlink message
     */
    virtual void ProcessWifiNetlinkReportEvent(const int type, const std::vector<uint8_t>& recvMsg) = 0;

    /**
     * @Description Check Chba conncted
     *
     * @return true: conncted, false: not conncted
     */
    virtual bool CheckChbaConncted() = 0;

    /**
     * @Description Stop Get CAC Result And Local CAC
     *
     * @param reason - reason
     * @return void
     */
    virtual void StopGetCacResultAndLocalCac(int reason) = 0;

    /**
     * @Description Is external scan allowed.
     *
     * @param scanDeviceInfo - scan device info
     * @return true: allowed, false: not allowed
     */
    virtual bool IsScanAllowed(WifiScanDeviceInfo &scanDeviceInfo) = 0;

    /**
     * @Description Is customer network.
     *
     * @param scanDeviceInfo - scan device info
     * @return true: allowed, false: not allowed
     */
    virtual bool IsHwItCustNetwork(WifiDeviceConfig &config) = 0;

    /**
     * @Description selfcure for multi dhcp server.
     *
     * @param cmd - add、get size、clear
     * @param ipInfo - ip information
     * @param retSize - get dhcp offer size
     * @return ErrCode - operation result
     */
    virtual ErrCode DealDhcpOfferResult(const OperationCmd &cmd, const IpInfo &ipInfo, uint32_t &retSize) = 0;

    /**
     * @Description selfcure for multi dhcp server.
     *
     * @param isChanged - is gateway changed situation
     * @return ErrCode - operation result
     */
    virtual ErrCode IsGatewayChanged(bool &isChanged) = 0;

    /**
     * @Description selfcure for multi dhcp server.
     *
     * @param isMultiDhcpServer - true、false
     * @param startSelfcure - true、false
     * @param ipInfo - get ipinfo
     * @return ErrCode - operation result
     */
    virtual ErrCode GetStaticIpConfig(const bool &isMultiDhcpServer, const bool &startSelfcure, IpInfo &ipInfo) = 0;

    /**
     * @Description Is Wide Bandwidth Supported.
     *
     * @return true: support, false: not support
     */
    virtual bool IsWideBandwidthSupported() = 0;

    /**
     * @Description Register P2pEnhance state Callback
     * @param name - registrant name
     * @param p2pEnhanceCallback - callback
     * @return ErrCode - operation result
     */
    virtual ErrCode RegisterP2pEnhanceCallback(const std::string &name, P2pEnhanceCallback callback) = 0;

    /**
     * @Description Register P2pEnhance state Callback
     * @param name - registrant name
     * @param P2pEnhanceActionListenCallback - callback
     * @return ErrCode - operation result
     */
    virtual ErrCode RegisterP2pEnhanceActionListenCallback(
        const std::string &name, P2pEnhanceActionListenCallback callback) = 0;

    /**
     * @Description Check Enhance Vap Available
     *
     * @return true: available, false: not available
     */
    virtual bool CheckEnhanceVapAvailable() = 0;

    /**
     * @Description Check if custom network
     *
     * @return true or false
     */
    virtual bool IsCustomNetwork(WifiDeviceConfig &config) = 0;

    /**
     * @Description Check if specific network
     *
     * @return true or false
     */
    virtual bool IsSpecificNetwork(WifiDeviceConfig &config) = 0;

    /**
     * @Description get the self wifi configuration information
     *
     * @param cfgType - configuration type
     * @param cfgData - the queried data of wifi configuration
     * @param getDatValidLen - the valid data length in the array `cfgData`
     * @return ErrCode - operation result
     */
    virtual ErrCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int* getDatValidLen) = 0;

    /**
     * @Description set the peer wifi configuration information
     *
     * @param cfgType - configuration type
     * @param cfgData - the wifi configuration data to be set
     * @param setDataValidLen - the valid data length in the array `cfgData`
     * @return ErrCode - operation result
     */
    virtual ErrCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int setDataValidLen) = 0;

    /**
     * @Description on notification receive
     */
    virtual void OnNotificationReceive() = 0;
 
    /**
     * @Description on dialog receive
     *
     * @param click - user click accept or reject
     */
    virtual void OnDialogClick(bool click) = 0;

    /**
     * @Description user reset network settings notify
     */
    virtual void ResetNetworkSettingsNotify() = 0;
 
    /**
     * @Description obtain supported frequency
     *
     * @param freq - current use freq
     * @param is160M - where use 160M Frequency
     * @return int - supported frequency
     */
    virtual int FreqEnhance(int freq, bool is160M) = 0;

    /**
     * @Description set the enhance signal poll info
     *
     * @param info - signal info
     * @return void
     */
    virtual void SetEnhanceSignalPollInfo(WifiSignalPollInfo &info) = 0;

    /**
     * @Description notify wifi link type changed
     *
     * @param apJsonData - ap Info
     * @param gpsFlag - gps flag
     * @param version - report version
     * @return void
     */
    virtual void CrowdsourcedDataReportInterface(std::string &apJsonData, const int gpsFlag, const int version);

    /**
     * @Description notify wifi link type changed
     *
     * @param wifiLinkType - wifiLinkType
     * @return void
     */
    virtual void OnWifiLinkTypeChanged(const WifiLinkType &wifiLinkType);
};
}  // namespace Wifi
}  // namespace OHOS
#endif