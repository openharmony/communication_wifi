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

#ifndef OHOS_WIFI_AUTO_CONNECT_SERVICE_H
#define OHOS_WIFI_AUTO_CONNECT_SERVICE_H

#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "sta_define.h"
#include "sta_state_machine.h"
#include "sta_saved_device_appraisal.h"
#include "network_selection_manager.h"
#include "magic_enum.h"

namespace OHOS {
namespace Wifi {
static const int MAX_BSSID_BLOCKLIST_COUNT = 3;
static const int AP_CANNOT_HANDLE_NEW_STA = 17;
static const int MAX_BSSID_BLOCKLIST_TIME = 60; // 60s
static const int BLOCKLIST_INVALID_SIZE = -1;
static const int STA_CAP_ROAMING = 0x800000;
static const int MIN_APPRAISAL_PRIORITY = 6;
static const int MAX_APPRAISAL_NUM = 6;
static const int MIN_SELECT_NETWORK_TIME = 30;
static const int MIN_5GHZ_BAND_FREQUENCY = 5000;
static const int RSSI_DELIMITING_VALUE = -65;
static const int MIN_RSSI_VALUE_24G = -77;
static const int MIN_RSSI_VALUE_5G = -80;
static const int TIME_FROM_LAST_SELECTION = 60;
static const int MIN_ROAM_RSSI_DIFF = 6;
class StaAutoConnectService {
    FRIEND_GTEST(StaAutoConnectService);
public:
    StaAutoConnectService(StaStateMachine *staStateMachine, int instId = 0);
    virtual ~StaAutoConnectService();
    /**
     * @Description  Initialize StaAutoConnectService
     *
     */
    virtual ErrCode InitAutoConnectService();
    /**
     * @Description  Processing scan results
     *
     * @param scanInfos - The list of scanning results(in)
     */
    virtual void OnScanInfosReadyHandler(const std::vector<InterScanInfo> &scanInfos);
    /**
     * @Description  Whether tracking should enable or disable scanned BSSIDs
     *
     * @param bssid - BSSID to be enabled/disabled(in)
     * @param enable - true: Enable the BSSID. false: disable the BSSID.(in)
     * @param reason - Enable/Disable reason code.(in)
     * @Return success: true. failed： false.
     */
    virtual bool EnableOrDisableBssid(std::string bssid, bool enable, int reason);
    /**
     * @Description  Select the best device from the range.
     *
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @param blockedBssids - Blocklisted BSSID List(in)
     * @param info - Current Connected Device(in)
     * @param electedDevice - Elected Device(out)
     * @Return success : WIFI_OPT_SUCCESS  failed : WIFI_OPT_FAILED
     */
    virtual ErrCode AutoSelectDevice(WifiDeviceConfig &electedDevice, const std::vector<InterScanInfo> &scanInfos,
        std::vector<std::string> &blockedBssids, WifiLinkedInfo &info);
    /**
     * @Description  Registering the Device Appraisal
     *
     * @param appraisal - Device appraisal to be registered(in)
     * @param priority - Value between 0 and (SCORER_MIN_PRIORITY – 1)(in)
     * @Return success : true  failed : false
     */
    virtual bool RegisterDeviceAppraisal(StaDeviceAppraisal *appraisal, int priority);

    /**
     * @Description  disable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     */
    virtual void DisableAutoJoin(const std::string &conditionName);

    /**
     * @Description  enable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     */
    virtual void EnableAutoJoin(const std::string &conditionName);

    /**
     * @Description  register auto join condition.
     *
     * @param conditionName the name of condition.
     * @param autoJoinCondition condition.
     */
    virtual void RegisterAutoJoinCondition(const std::string &conditionName,
                                           const std::function<bool()> &autoJoinCondition);

    /**
     * @Description  deregister auto join condition.
     *
     * @param conditionName the name of condition.
     */
    virtual void DeregisterAutoJoinCondition(const std::string &conditionName);

    /**
     * @Description  set auto connect state callback.
     *
     * @param callbacks callbacks.
     */
    virtual void SetAutoConnectStateCallback(const std::vector<StaServiceCallback> &callbacks);
private:
    StaStateMachine *pStaStateMachine;
    StaDeviceAppraisal *pSavedDeviceAppraisal;
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = nullptr;
    bool firmwareRoamFlag;
    int selectDeviceLastTime;
    StaDeviceAppraisal *pAppraisals[MAX_APPRAISAL_NUM];
    int m_instId;
    std::map<std::string, std::function<bool()>> autoJoinConditionsMap{};
    std::mutex autoJoinMutex;
    std::vector<StaServiceCallback> mStaCallbacks;
    /**
     * @Description  Get available device
     *
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @param blockedBssids - Blocklisted BSSID List(in)
     * @param info - Current Connected Device(in)
     * @param availableScanInfos - Available Scan Info(out)
     */
    void GetAvailableScanInfos(std::vector<InterScanInfo> &availableScanInfos,
        const std::vector<InterScanInfo> &scanInfos, std::vector<std::string> &blockedBssids, WifiLinkedInfo &info);
    /**
     * @Description  Whether the device needs to be switched.
     *
     * @param info - Current Connected Device(in)
     * @Return success : true  failed : false
     */
    bool AllowAutoSelectDevice(WifiLinkedInfo &info);
    /**
     * @Description  Whether the device needs to be switched.
     *
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Device(in)
     * @Return success : true  failed : false
     */
    bool AllowAutoSelectDevice(const std::vector<InterScanInfo> &scanInfos, WifiLinkedInfo &info);
    /**
     * @Description  Whether the device strength is sufficient.
     *
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Device(in)
     * @Return success : true  failed : false
     */
    bool CurrentDeviceGoodEnough(const std::vector<InterScanInfo> &scanInfos, WifiLinkedInfo &info);
    /**
     * @Description  Whether 5G devices are available.
     *
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @Return success : true  failed : false
     */
    bool WhetherDevice5GAvailable(const std::vector<InterScanInfo> &scanInfos);
    /**
     * @Description  Select Roaming Device.
     *
     * @param availableScanInfos - Available device(in)
     * @param scanInfos - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Device(in)
     * @param electedDevice - Elected Device(out)
     * @Return success : true  failed : false
     */
    bool RoamingSelection(
        WifiDeviceConfig &electedDevice, std::vector<InterScanInfo> &availableScanInfos, WifiLinkedInfo &info);
    /**
     * @Description  Select Roaming Device.
     *
     * @param WifiScanInfo - A scan result(in)
     * @param info - Current Connected Device(in)
     * @param electedDevice - Elected Device(out)
     * @Return success : true  failed : false
     */
    bool RoamingEncryptionModeCheck(WifiDeviceConfig &electedDevice, InterScanInfo scanInfo, WifiLinkedInfo &info);
    /**
     * @Description  Whether the device is a 2.4G device.
     *
     * @param frequency(in)
     * @Return success : true  failed : false
     */
    bool Whether24GDevice(int frequency);
    /**
     * @Description Whether allow auto join.
     *
     * @return true if allow autoJoin.
     */
    bool IsAllowAutoJoin();
    /**
     * @Description  Whether the device is a 5G device.
     *
     * @param frequency(in)
     * @Return success : true  failed : false
     */
    bool Whether5GDevice(int frequency);

    /**
     * @Description  override the candidate chosen by autoConnectSelector with the user chosen if one exists
     *
     * @param candidate chosen by autoConnectSelector
     * @Return true if candidate be overrid otherwise false
     */
    bool OverrideCandidateWithUserSelectChoice(NetworkSelectionResult &candidate);

    /**
     * @Description whether p2p enhance filter cause auto connect fail
     *
     * @param scanInfos WifiScanInfo list of all APs in the range(in)
     * @Return true if p2p enhance filter cause auto connect fail otherwise false
     */
    bool IsAutoConnectFailByP2PEnhanceFilter(const std::vector<InterScanInfo> &scanInfos);

    /**
     * @Description  determine whether the candidate is a hidden network selected by the user
     *
     * @param candidate chosen by autoConnectSelector
     * @Return true if candidate is user choice hidden network otherwise false
     */
    bool IsCandidateWithUserSelectChoiceHidden(NetworkSelectionResult &candidate);

    bool SelectNetworkFailConnectChoiceNetWork(NetworkSelectionResult &networkSelectionResult,
        const std::vector<InterScanInfo> &scanInfos);

    void ConnectNetwork(NetworkSelectionResult &networkSelectionResult, SelectedType &selectedType);
};
}  // namespace Wifi
}  // namespace OHOS
#endif