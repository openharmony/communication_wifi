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

#ifndef OHOS_WIFI_SERVICE_H
#define OHOS_WIFI_SERVICE_H

#include <codecvt>
#include "wifi_internal_msg.h"
#include "sta_auto_connect_service.h"
#include "sta_monitor.h"
#include "sta_state_machine.h"
#include "network_selection.h"
#include "wifi_chr_utils.h"
#ifndef OHOS_ARCH_LITE
#include "i_wifi_country_code_change_listener.h"
#endif

namespace OHOS {
namespace Wifi {
class StaService {
    FRIEND_GTEST(StaService);
public:
    explicit StaService(int instId = 0);
    virtual ~StaService();
    /**
     * @Description  Initialize StaService module.
     *
     * @param callbacks - sta service callback
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode InitStaService(const std::vector<StaServiceCallback> &callbacks);
    /**
     * @Description  Enable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableStaService();
    /**
     * @Description  Disable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableStaService() const;
    /**
     * @Description  Connect to a new network
     *
     * @param config - the configuration of network which is going to connect.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectToDevice(const WifiDeviceConfig &config) const;
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
    virtual ErrCode ConnectToNetwork(int networkId, int type = NETWORK_SELECTED_BY_USER) const;

    /**
     * @Description roam to target bssid
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @param type - select network type: SelectedType
     * @return ErrCode - operation result
     */
    virtual ErrCode StartConnectToBssid(const int32_t networkId, const std::string bssid,
        int32_t type = NETWORK_SELECTED_BY_USER) const;

    /**
     * @Description connect to user select ssid and bssid network
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @return ErrCode - operation result
     */
    virtual ErrCode StartConnectToUserSelectNetwork(int networkId, std::string bssid) const;

    /**
     * @Description  Disconnect to the network
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode Disconnect() const;
    /**
     * @Description  ReAssociate network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReAssociate() const;
    /**
     * @Description Add a specified candidate hotspot configuration.
     *
     * @param uid - call app uid
     * @param config - WifiDeviceConfig object
     * @param netWorkId - the network id of the hotspot configuration.(out)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId) const;
    /**
     * @Description Connect to a candidate specified network.
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @Return ErrCode - operation result
     */
    virtual ErrCode ConnectToCandidateConfig(const int uid, const int networkId) const;
    /**
     * @Description Remove the wifi candidate device config equals to input network id
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveCandidateConfig(const int uid, const int networkId) const;
    /**
     * @Description Remove all the wifi candidate device config equals to input uid
     *
     * @param uid - call app uid
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveAllCandidateConfig(const int uid) const;
    /**
     * @Description  Update a network to config
     *
     * @param config -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) const;
    /**
     * @Description Update a network to config.
     *
     * @param config -The Network info(in)
     * @Return success: networkId  fail: -1
     */
    virtual int UpdateDeviceConfig(const WifiDeviceConfig &config) const;
    /**
     * @Description  Remove network config.
     *
     * @param networkId -The NetworkId is going to be removed.(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveDevice(int networkId) const;
    /**
     * @Description  Remove all network configs.
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveAllDevice() const;
    /**
     * @Description  Enable WI-FI device Configuration.
     *
     * @param networkId - The NetworkId (in)
     * @param networkId - if set true, disable other device config (in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) const;
    /**
     * @Description Disable WI-FI device Configuration.
     *
     * @param networkId - device Configuration's network id
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableDeviceConfig(int networkId) const;
    /**
     * @Description Set whether to allow automatic connect by networkid.
     *
     * @param networkId - Identifies the network to be set. The value of networkId cannot be less thann 0.
     * @param isAllowed - Identifies whether allow auto connect or not.
     * @return ErrCode - operation result
     */
    virtual ErrCode AllowAutoConnect(int32_t networkId, bool isAllowed) const;
    /**
     * @Description  Start WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode StartWps(const WpsConfig &config) const;
    /**
     * @Description  Close WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode CancelWps() const;

    /**
     * @Description  ConnectivityManager process scan results.
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode AutoConnectService(const std::vector<InterScanInfo> &scanInfos);
    /**
     * @Description Register sta callback function
     *
     * @param callbacks - Callback function pointer storage structure
     */
    virtual void RegisterStaServiceCallback(const std::vector<StaServiceCallback> &callbacks) const;

    /**
     * @Description Register sta callback function
     *
     * @param callbacks - Callback function pointer storage structure
     */
    virtual void UnRegisterStaServiceCallback(const StaServiceCallback &callbacks) const;

    /**
     * @Description  Reconnect network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReConnect() const;

    /**
     * @Description  Set suspend mode to wpa
     *
     * @param mode - true for suspend mode, false for resume mode
     *
     * @Return success: WIFI_OPT_SUCCESS, fail: WIFI_OPT_FAILED
     */
    virtual ErrCode SetSuspendMode(bool mode) const;

    /**
     * @Description  Set power mode to wpa
     *
     * @param mode - true for power mode, false for resume mode
     *
     * @Return success: WIFI_OPT_SUCCESS, fail: WIFI_OPT_FAILED
     */
    virtual ErrCode SetPowerMode(bool mode) const;

    /**
     * @Description systemabilitychanged
     *
     * @param mode: true for setup, false for shutdown.
     * @return WifiErrorNo
     */
    virtual ErrCode OnSystemAbilityChanged(int systemAbilityid, bool add);
    /**
     * @Description Screen State (On/Off) Change Handler
     *
     */
    virtual void HandleScreenStatusChanged(int screenState);

    /**
     * @Description  disable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    virtual ErrCode DisableAutoJoin(const std::string &conditionName);

    /**
     * @Description  enable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    virtual ErrCode EnableAutoJoin(const std::string &conditionName);

    /**
     * @Description  register auto join condition.
     *
     * @param conditionName the name of condition.
     * @param autoJoinCondition condition.
     * @return WifiErrorNo
     */
    virtual ErrCode RegisterAutoJoinCondition(const std::string &conditionName,
                                              const std::function<bool()> &autoJoinCondition);
    /**
     * @Description  deregister auto join condition.
     *
     * @param conditionName the name of condition.
     * @return WifiErrorNo
     */
    virtual ErrCode DeregisterAutoJoinCondition(const std::string &conditionName);

    /**
     * @Description  register external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @param filterBuilder filter builder.
     * @return WifiErrorNo
     */
    virtual ErrCode RegisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName,
                                          const FilterBuilder &filterBuilder);
    /**
     * @Description  deregister external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @return WifiErrorNo
     */
    virtual ErrCode DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName);

    /**
     * Register the common builder function
     *
     * @param TagType scoreTag which define where the score or filter should be inserted.
     * @param tagName the score or filter name.
     * @param CommonBuilder CommonBuilder function.
     */
    virtual ErrCode RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                               const CommonBuilder &commonBuilder);
 
    /**
     * Deregister the common builder function
     *
     * @param TagType TagType which define where the score or filter should be inserted.
     * @param tagName the score or filte name.
     */
    virtual ErrCode DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName);

    /**
     * @Description start portal certification.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StartPortalCertification();

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
    virtual ErrCode HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData);

    /**
     * @Description Set EnhanceService
     *
     * @param enhanceService IEnhanceService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetEnhanceService(IEnhanceService* enhanceService);

    /**
     * @Description Set SelfcureService.
     *
     * @param enhanceService ISelfCureService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetSelfCureService(ISelfCureService *selfCureService);
#endif
    /**
     * @Description enable hilink
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableHiLinkHandshake(bool uiFlag, const WifiDeviceConfig &config, const std::string &cmd);

    /**
     * @Description start wifi detection
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StartWifiDetection();

    /**
     * @Description deliver mac
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DeliverStaIfaceData(const std::string &currentMac);

    /**
     * @Description deliver audio state
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DeliverAudioState(int state);

/**
     * @Description fold status
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual void HandleFoldStatusChanged(int foldstatus);

    virtual ErrCode GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length);

    /* VOWIFI */
    virtual std::string VoWifiDetect(std::string cmd);
 
    /**
     * @Description  wifiPro service initialization function.
     *
     * @return std::vector<unsigned char> : wifi signal info
     */
    virtual VoWifiSignalInfo FetchWifiSignalInfoForVoWiFi();
 
    /**
     * @Description  set VoWifi detect mode.
     *
     * @param info WifiDetectConfInfo
     */
    virtual void ProcessSetVoWifiDetectMode(WifiDetectConfInfo info);
 
    /**
     * @Description  set vowifi detect period.
     *
     * @param period period of vowifi detect
     */
    virtual void ProcessSetVoWifiDetectPeriod(int period);

    /**
     * @Description  get Detect result.
     *
     * @param state net state
     */
    virtual void GetDetectNetState(OperateResState &state);

    /**
     * @Description Add wifi block list and wifi white list
     *
     * @param config - WifiRestrictedInfo object
     * @param result - the result of wifi access list
     * @return ErrCode - operation result
     */
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    virtual ErrCode SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList) const;
#endif
private:
    void NotifyDeviceConfigChange(ConfigChange value, WifiDeviceConfig config, bool isRemoveAll) const;
    void NotifyCandidateApprovalStatus(CandidateApprovalStatus status) const;
    int FindDeviceConfig(const WifiDeviceConfig &config, WifiDeviceConfig &outConfig) const;
    std::string ConvertString(const std::u16string &wideText) const;
    std::string GetMcc(const std::string &imsi) const;
    std::string GetMnc(const std::string &imsi, const int mncLen) const;
    void UpdateEapConfig(const WifiDeviceConfig &config, WifiEapConfig &wifiEapConfig) const;
    int ConvertToAccessType(int linkSpeed, int frequency);
    bool VoWifiDetectSet(std::string cmd);
#ifndef OHOS_ARCH_LITE
    void GetStaControlInfo();
    bool IsAppInCandidateFilterList(int uid) const;
#endif

private:
#ifndef OHOS_ARCH_LITE
    class WifiCountryCodeChangeObserver : public IWifiCountryCodeChangeListener {
    public:
        WifiCountryCodeChangeObserver(const std::string &name, StateMachine &stateMachineObj)
            : IWifiCountryCodeChangeListener(name, stateMachineObj) {}
        ~WifiCountryCodeChangeObserver() override = default;
        ErrCode OnWifiCountryCodeChanged(const std::string &wifiCountryCode) override;
        std::string GetListenerModuleName() override;
    };
    std::shared_ptr<IWifiCountryCodeChangeListener> m_staObserver;
#endif
    StaStateMachine *pStaStateMachine;
    StaMonitor *pStaMonitor;
    StaAutoConnectService *pStaAutoConnectService;

    int m_instId;
    std::vector<PackageInfo> sta_candidate_trust_list;
    bool m_connMangerStatus = true;
    std::shared_mutex voWifiCallbackMutex_;
    int lastTxPktCnt_ = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif