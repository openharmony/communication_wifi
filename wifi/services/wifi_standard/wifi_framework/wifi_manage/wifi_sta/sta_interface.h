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

#ifndef OHOS_WIFI_STA_INTERFACE_H
#define OHOS_WIFI_STA_INTERFACE_H

#include "sta_define.h"
#include "ista_service.h"
#include "wifi_errcode.h"
#include "define.h"
namespace OHOS {
namespace Wifi {
class StaService;
class StaInterface : public IStaService  {
    FRIEND_GTEST(StaInterface);
public:
    explicit StaInterface(int instId = 0);
    virtual ~StaInterface() override;

    /**
     * @Description  Enable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableWifi() override;
    /**
     * @Description  Disable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableWifi() override;
    /**
     * @Description  Connect to a new network
     *
     * @param config - the configuration of network which is going to connect.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectToNetwork(int networkId) override;
    /**
     * @Description  Connecting to a specified network.
     *
     * @param networkId - interior saved network index.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectToDevice(const WifiDeviceConfig &config) override;
    /**
     * @Description  Disconnect to the network
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode Disconnect() override;
    /**
     * @Description  ReConnect network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReConnect() override;
    /**
     * @Description  ReAssociate network
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ReAssociate() override;
    /**
     * @Description Add a specified candidate hotspot configuration.
     *
     * @param uid - call app uid
     * @param config - WifiDeviceConfig object
     * @param netWorkId - the network id of the hotspot configuration.(out)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId) override;
    /**
     * @Description Connecting to a candidate specified network.
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @Return ErrCode - operation result
     */
    ErrCode ConnectToCandidateConfig(const int uid, const int networkId) override;
    /**
     * @Description Remove the wifi candidate device config equals to input network id
     *
     * @param uid - call app uid
     * @param networkId - the candidate device network id
     * @return ErrCode - operation result
     */
    ErrCode RemoveCandidateConfig(const int uid, const int networkId) override;
    /**
     * @Description Remove all the wifi candidate device config equals to input uid
     *
     * @param uid - call app uid
     * @return ErrCode - operation result
     */
    ErrCode RemoveAllCandidateConfig(const int uid) override;
    /**
     * @Description  Add a network to config
     *
     * @param config -The Network info(in)
     * @Return success: networkId  fail: -1
     */
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) override;
    /**
     * @Description  Update a network to config
     *
     * @param config -The Network info(in)
     * @Return success: networkId  fail: -1
     */
    virtual int UpdateDeviceConfig(const WifiDeviceConfig &config) override;
    /**
     * @Description  Remove network
     *
     * @param networkId -The NetworkId is going to be removed.(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveDevice(int networkId) override;
    /**
     * @Description  Remove all network configs
     *
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RemoveAllDevice() override;
    /**
     * @Description  Enable WI-FI device configuration
     *
     * @param networkId - The NetworkId (in)
     * @param networkId - if set true, disable other device configuration (in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) override;
    /**
     * @Description Disable WI-FI device configuration
     *
     * @param networkId - device configuration's network id
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableDeviceConfig(int networkId) override;
    /**
     * @Description  Start WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode StartWps(const WpsConfig &config) override;
    /**
     * @Description  Close WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode CancelWps() override;
    /**
     * @Description  ConnectivityManager process scan results.
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through callback function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode ConnectivityManager(const std::vector<InterScanInfo> &scanInfos) override;

    /**
     * @Description Register sta callback function
     *
     * @param callbacks - Callback function pointer storage structure
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode RegisterStaServiceCallback(const StaServiceCallback &callbacks) override;
    /**
     * @Description send suspend mode for wpa.
     *
     * @param mode: true for suspend, false for resume.
     * @return WifiErrorNo
     */
    virtual ErrCode SetSuspendMode(bool mode) override;

    /**
     * @Description send power mode for wpa.
     *
     * @param mode: true for power, false for resume.
     * @return WifiErrorNo
     */
    virtual ErrCode SetPowerMode(bool mode) override;

    /**
     * @Description systemabilitychanged
     *
     * @param add: true for setup, false for shutdown.
     * @return WifiErrorNo
     */
    virtual ErrCode OnSystemAbilityChanged(int systemAbilityid, bool add) override;
    /**
     * @Description Processes interface service screen change request.
     *
     * @param screenState screen state[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnScreenStateChanged(int screenState) override;

    /**
     * @Description  disable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    ErrCode DisableAutoJoin(const std::string &conditionName) override;

    /**
     * @Description  enable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    ErrCode EnableAutoJoin(const std::string &conditionName) override;

    /**
     * @Description  register auto join condition.
     *
     * @param conditionName the name of condition.
     * @param autoJoinCondition condition.
     * @return WifiErrorNo
     */
    ErrCode RegisterAutoJoinCondition(const std::string &conditionName,
                                      const std::function<bool()> &autoJoinCondition) override;

    /**
     * @Description  deregister auto join condition.
     *
     * @param conditionName the name of condition.
     * @return WifiErrorNo
     */
    ErrCode DeregisterAutoJoinCondition(const std::string &conditionName) override;

    /**
     * @Description  register external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @param filterBuilder filter builder.
     * @return WifiErrorNo
     */
    ErrCode RegisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName,
                                  const FilterBuilder &filterBuilder) override;

    /**
     * @Description  deregister external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @return WifiErrorNo
     */
    ErrCode DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName) override;
    /**
     * @Description start portal certification.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StartPortalCertification() override;
	
	/**
     * @Description renew dhcp.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode RenewDhcp() override;

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
    virtual ErrCode HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData) override;
#endif
	/**
     * @Description EnableHiLinkHandshake.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode EnableHiLinkHandshake(const WifiDeviceConfig &config, const std::string &bssid) override;
 
	/**
     * @Description DeliverStaIfaceData.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DeliverStaIfaceData(const std::string &bssid) override;
private:
    std::vector<StaServiceCallback> m_staCallback;
    StaService *pStaService;
    std::mutex mutex;
    int m_instId;
};
}  // namespace Wifi
}  // namespace OHOS
#endif