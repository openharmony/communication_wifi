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

#ifndef OHOS_WIFI_STA_SERVICE_H
#define OHOS_WIFI_STA_SERVICE_H

#include "sta_define.h"
#include "wifi_errcode.h"
#ifndef OHOS_ARCH_LITE
#include "app_state_data.h"
#include "ienhance_service.h"
#include "iself_cure_service.h"
#endif
#include "wifi_msg.h"
#include "sta_service_callback.h"
#include "network_selection.h"

namespace OHOS {
namespace Wifi {
class IStaService {
public:
    virtual ~IStaService() = default;
    /**
     * @Description  Enable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableStaService() = 0;
    /**
     * @Description  Disable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableStaService() = 0;
    /**
     * @Description  Connect to a new network
     *
     * @param config - the configuration of network which is going to connect.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectToDevice(const WifiDeviceConfig &config) = 0;
    /**
     * @Description  Connecting to a specified network.
     *
     * @param networkId - interior saved network index.(in)
     * @param type - select network type: SelectedType
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectToNetwork(int networkId, int type = NETWORK_SELECTED_BY_USER) = 0;

    /**
     * @Description roam to target bssid
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @return ErrCode - operation result
     */
    virtual ErrCode StartConnectToBssid(const int32_t networkId, const std::string bssid,
        int32_t type = NETWORK_SELECTED_BY_USER) = 0;

    /**
     * @Description connect to user select ssid and bssid network
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @return ErrCode - operation result
     */
    virtual ErrCode StartConnectToUserSelectNetwork(int networkId, std::string bssid) = 0;

    /**
     * @Description  Disconnect to the network
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode Disconnect() = 0;
    /**
     * @Description  ReConnect network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReConnect() = 0;
    /**
     * @Description  ReAssociate network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReAssociate() = 0;

    /**
     * @Description Add a specified candidate hotspot configuration.
     *
     * @param uid - call app uid
     * @param config - WifiDeviceConfig object
     * @param netWorkId - the network id of the hotspot configuration.(out)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId) = 0;

    /**
     * @Description Add wifi block list and wifi white list
     *
     * @param config - WifiAccessInfo object
     * @param result - the result of wifi access list
     * @return ErrCode - operation result
     */
#ifdef FEATURE_WIFI_BLOCKLIST_WHITELIST_SUPPORT
    virtual ErrCode SetWifiAccessList(const std::vector<WifiAccessInfo> &wifiAccessList) = 0;
#endif

    /**
     * @Description Connect to a candidate specified network.
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @Return ErrCode - operation result
     */
    virtual ErrCode ConnectToCandidateConfig(const int uid, const int networkId) = 0;

    /**
     * @Description Remove the wifi candidate device config equals to input network id
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveCandidateConfig(const int uid, const int networkId) = 0;

    /**
     * @Description Remove all the wifi candidate device config equals to input uid
     *
     * @param uid - call app uid
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveAllCandidateConfig(const int uid) = 0;

    /**
     * @Description  Add a network to config
     *
     * @param config -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) = 0;
    /**
     * @Description  Update a network to config
     *
     * @param config -The Network info(in)
     * @Return success: networkId  fail: -1
     */
    virtual int UpdateDeviceConfig(const WifiDeviceConfig &config) = 0;
    /**
     * @Description  Remove network
     *
     * @param networkId -The NetworkId is going to be removed.(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveDevice(int networkId) = 0;
    /**
     * @Description  Remove all network configs
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveAllDevice() = 0;
    /**
     * @Description  Enable WI-FI device configuration
     *
     * @param networkId - The NetworkId (in)
     * @param networkId - if set true, disable other device configuration (in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) = 0;
    /**
     * @Description Disable WI-FI device configuration
     *
     * @param networkId - device configuration's network id
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableDeviceConfig(int networkId) = 0;
    /**
     * @Description Set whether to allow automatic connect by networkid.
     *
     * @param networkId - Identifies the network to be set. The value of networkId cannot be less thann 0.
     * @param isAllowed - Identifies whether allow auto connect or not.
     * @return ErrCode - operation result
     */
    virtual ErrCode AllowAutoConnect(int32_t networkId, bool isAllowed) = 0;
    /**
     * @Description  Start WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode StartWps(const WpsConfig &config) = 0;
    /**
     * @Description  Close WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode CancelWps() = 0;

    /**
     * @Description  ConnectivityManager process scan results.
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectivityManager(const std::vector<InterScanInfo> &scanInfos) = 0;
    /**
     * @Description Register sta callback function
     *
     * @param callbacks - Callback function pointer storage structure
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RegisterStaServiceCallback(const StaServiceCallback &callbacks) = 0;

    /**
     * @Description UnRegister sta callback function
     *
     * @param callbacks - Callback function pointer storage structure
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode UnRegisterStaServiceCallback(const StaServiceCallback &callbacks) = 0;

    /**
     * @Description send suspend mode for wpa.
     *
     * @param mode: true for suspend, false for resume.
     * @return WifiErrorNo
     */
    virtual ErrCode SetSuspendMode(bool mode) = 0;

    /**
     * @Description send power mode for wpa.
     *
     * @param mode: true for power, false for resume.
     * @return WifiErrorNo
     */
    virtual ErrCode SetPowerMode(bool mode) = 0;

    /**
     * @Description systemabilitychanged
     *
     * @param mode: true for setup, false for shutdown.
     * @return WifiErrorNo
     */
    virtual ErrCode OnSystemAbilityChanged(int systemAbilityid, bool add) = 0;
    /**
     * @Description Processes interface service screen change request.
     *
     * @param screenState screen state[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnScreenStateChanged(int screenState) = 0;

    /**
     * @Description  disable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    virtual ErrCode DisableAutoJoin(const std::string &conditionName) = 0;

    /**
     * @Description  enable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    virtual ErrCode EnableAutoJoin(const std::string &conditionName) = 0;

    /**
     * @Description  register auto join condition.
     *
     * @param conditionName the name of condition.
     * @param autoJoinCondition condition.
     * @return WifiErrorNo
     */
    virtual ErrCode RegisterAutoJoinCondition(const std::string &conditionName,
                                              const std::function<bool()> &autoJoinCondition) = 0;

    /**
     * @Description  deregister auto join condition.
     *
     * @param conditionName the name of condition.
     * @return WifiErrorNo
     */
    virtual ErrCode DeregisterAutoJoinCondition(const std::string &conditionName) = 0;

    /**
     * @Description  register external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @param filterBuilder filter builder.
     * @return WifiErrorNo
     */
    virtual ErrCode RegisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName,
                                          const FilterBuilder &filterBuilder) = 0;

    /**
     * @Description  deregister external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @return WifiErrorNo
     */
    virtual ErrCode DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName) = 0;

   /**
     * Register the common builder function
     *
     * @param TagType scoreTag which define where the score or filter should be inserted.
     * @param tagName the score or filter name.
     * @param CommonBuilder CommonBuilder function.
     */
    virtual ErrCode RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                               const CommonBuilder &commonBuilder) = 0;
 
    /**
     * Deregister the common builder function
     *
     * @param TagType TagType which define where the score or filter should be inserted.
     * @param tagName the score or filte name.
     */
    virtual ErrCode DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName) = 0;

    /**
     * @Description start portal certification.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StartPortalCertification() = 0;

    /**
     * @Description Handle foreground app changed action.
     *
     * @param bundleName app name.
     * @param uid app uid.
     * @param pid app pid.
     * @param state app state.
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
#ifndef OHOS_ARCH_LITE
    virtual ErrCode HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData) = 0;

    /**
     * @Description Set EnhanceService to sta Service.
     *
     * @param enhanceService IEnhanceService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetEnhanceService(IEnhanceService *enhanceService) = 0;

    /**
     * @Description Set SelfcureService to sta Service.
     *
     * @param enhanceService ISelfCureService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetSelfCureService(ISelfCureService *selfCureService) = 0;
#endif
    /**
     * @Description enable hilink
     *
	 * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableHiLinkHandshake(bool uiFlag, const WifiDeviceConfig &config, const std::string &bssid) = 0;

    /**
     * @Description deliver mac
     *
	 * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DeliverStaIfaceData(const std::string &currentMac) = 0;

    /**
     * @Description Deliver Audio State
     *
	 * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DeliverAudioState(int state) = 0;

    /**
     * @Description  wifiPro service initialization function.
     *
     * @return VoWifiSignalInfo : wifi signal info
     */
    virtual ErrCode FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo) = 0;
 
    /**
     * @Description  Check Is Support VoWifi Detect.
     *
     * @return bool - supported: true, unsupported: false.
     */
    virtual ErrCode IsSupportVoWifiDetect(bool &isSupported) = 0;
 
    /**
     * @Description  set VoWifi detect mode.
     *
     * @param info WifiDetectConfInfo
     */
    virtual ErrCode SetVoWifiDetectMode(WifiDetectConfInfo info) = 0;
 
    /**
     * indicate VoWifiDetectMode
     *
     * @return VoWifiDetectMode
     */
    virtual ErrCode GetVoWifiDetectMode(WifiDetectConfInfo &info) = 0;
 
    /**
     * @Description  set vowifi detect period.
     *
     * @param period period of vowifi detect
     */
    virtual ErrCode SetVoWifiDetectPeriod(int period) = 0;
 
    /**
     * Get vowifi detection period
     *
     * @return vowifi detection period
     */
    virtual ErrCode GetVoWifiDetectPeriod(int &period) = 0;
 
    /**
     * @Description Notify vowifi signal detect interrupt message from netlink.
     *
     * @param type - wifi netlink message type
     */
    virtual void ProcessVoWifiNetlinkReportEvent(const int type) = 0;

    /**
     * @Description  get Detect result.
     *
     * @param state net state
     */
    virtual void GetDetectNetState(OperateResState &state) = 0;

    virtual ErrCode GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length) = 0;

    /**
     * @Description fold status
     *
     * @param success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnFoldStateChanged(const int foldStatus) = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif