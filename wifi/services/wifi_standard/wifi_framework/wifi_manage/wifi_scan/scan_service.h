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
#ifndef OHOS_WIFI_SCAN_SERVICE_H
#define OHOS_WIFI_SCAN_SERVICE_H

#include <string>
#include <map>
#include <mutex>
#include <ctime>
#include <set>
#include <math.h>
#include <unordered_set>
#include "iscan_service_callbacks.h"
#include "define.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_manager.h"
#endif
#include "wifi_scan_msg.h"
#include "wifi_errcode.h"
#include "scan_common.h"
#include "scan_monitor.h"
#include "scan_state_machine.h"
#include "ienhance_service.h"

namespace OHOS {
namespace Wifi {
inline const int DISCONNECTED_SCAN_INTERVAL = 20 * 60 * 1000;
inline const int RESTART_PNO_SCAN_TIME = 5 * 1000;
inline const int RESTART_SYSTEM_SCAN_TIME = 2 * 1000;
inline const int RESTART_COMMON_SCAN_TIME = 0;
inline const int FREQS_24G_MAX_VALUE = 2500;
inline const int FREQS_5G_MIN_VALUE = 5000;
inline const int SECOND_TO_MICRO_SECOND = 1000000;
inline const int MAX_PNO_SCAN_FAILED_NUM = 5;
inline const int MAX_SYSTEM_SCAN_FAILED_NUM = 5;
inline const int DOUBLE_SCAN_INTERVAL = 2;
inline const int SYSTEM_SCAN_INIT_TIME = 10;
inline const int SYSTEM_SCAN_INTERVAL_ONE_HOUR = 60 * 60;
inline const int SYSTEM_SCAN_INTERVAL_FIVE_MINUTE = 5 * 60;
inline const int SYSTEM_SCAN_INTERVAL_160_SECOND = 160;
inline const int SYSTEM_SCAN_INTERVAL_10_SECOND = 10;
inline const int SYSTEM_SCAN_INTERVAL_30_SECOND = 30;
inline const int SYSTEM_SCAN_INTERVAL_60_SECOND = 60;
inline const int SYSTEM_SCAN_COUNT_3_TIMES = 3;
inline const int DEFAULT_PNO_SCAN_INTERVAL = 300;

inline const int TONE_PER_SYM_11ABG = 48;
inline const int TONE_PER_SYM_11N_20MHZ = 52;
inline const int TONE_PER_SYM_11N_40MHZ = 108;
inline const int TONE_PER_SYM_11AC_20MHZ = 52;
inline const int TONE_PER_SYM_11AC_40MHZ = 108;
inline const int TONE_PER_SYM_11AC_80MHZ = 234;
inline const int TONE_PER_SYM_11AC_160MHZ = 468;
inline const int TONE_PER_SYM_11AX_20MHZ = 234;
inline const int TONE_PER_SYM_11AX_40MHZ = 468;
inline const int TONE_PER_SYM_11AX_80MHZ = 980;
inline const int TONE_PER_SYM_11AX_160MHZ = 1960;

inline const int SYM_DURATION_11ABG_NS = 4000;
// 11n OFDM symbol duration in ns with 0.4us guard interval
inline const int SYM_DURATION_11N_NS = 3600;
// 11ac OFDM symbol duration in ns with 0.4us guard interval
inline const int SYM_DURATION_11AC_NS = 3600;
inline const int SYM_DURATION_11AX_NS = 13600;
inline const int MICRO_TO_NANO_RATIO = 1000;

inline const int BIT_PER_TONE_SCALE = 1000;
inline const int MAX_BITS_PER_TONE_11ABG = (int) round((6 * 3.0 * BIT_PER_TONE_SCALE) / 4.0);
inline const int MAX_BITS_PER_TONE_11N = (int) round((6 * 5.0 * BIT_PER_TONE_SCALE) / 6.0);
inline const int MAX_BITS_PER_TONE_11AC = (int) round((8 * 5.0 * BIT_PER_TONE_SCALE) / 6.0);
inline const int MAX_BITS_PER_TONE_11AX = (int) round((10 * 5.0 * BIT_PER_TONE_SCALE) / 6.0);

inline const int TWO_DB = 3;
inline const int SNR_BIT_PER_TONE_HIGH_SNR_SCALE = BIT_PER_TONE_SCALE / TWO_DB;
inline const int SNR_BIT_PER_TONE_LUT_MIN = -10; // minimum snrDb supported by LUT
inline const int SNR_BIT_PER_TONE_LUT_MAX = 9;   // maximum snrDb supported by LUT
inline const int SNR_BIT_PER_TONE_LUT[] = {0, 171, 212, 262, 323, 396, 484, 586,
                                          706, 844, 1000, 1176, 1370, 1583, 1812, 2058, 2317, 2588, 2870, 3161};
inline const int NOISE_FLOOR_20MHZ_DBM = -96;

inline const int SNR_MARGIN_DB = 16;
inline const int MAX_NUM_SPATIAL_STREAM_11AX = 8;
inline const int MAX_NUM_SPATIAL_STREAM_11AC = 8;
inline const int MAX_NUM_SPATIAL_STREAM_11N = 4;
inline const int MAX_NUM_SPATIAL_STREAM_11ABG = 1;

inline const int B_MODE_MAX_MBPS = 11;
inline const int MAX_CHANNEL_UTILIZATION = 255;
inline const int MAX_RSSI = 200;

inline const int MAX_RX_SPATIAL_STREAMS = 2;
inline const int MAX_TX_SPATIAL_STREAMS = 2;

inline const int LOCATOR_SA_UID = 1021;

inline constexpr int P2P_ENHANCE_BC_CONNECT_SUCC = 4;
inline constexpr int P2P_ENHANCE_BC_DESTROYED = 10;
inline constexpr int P2P_ENHANCE_BC_SWITCH_NOTIFY_SUCC = 11;

int WifiMaxThroughput(int wifiStandard, bool is11bMode,
                      WifiChannelWidth channelWidth, int rssiDbm, int maxNumSpatialStream, int channelUtilization);

class ScanService {
    FRIEND_GTEST(ScanService);
public:
    explicit ScanService(int instId = 0);
    virtual ~ScanService();
    /**
     * @Description  Initializing the Scan Service.
     *
     * @param scanSerivceCallbacks Callback function registered with the wifiManager[in].
     * @return success: true, failed: false
     */
    virtual bool InitScanService(const IScanSerivceCallbacks &scanSerivceCallbacks);
    /**
     * @Description Stopping the Scan Service.
     *
     */
    virtual void UnInitScanService();
    /**
     * @Description Registers the callback function of the scanning module to the interface service.
     *
     * @param scanSerivceCallbacks callback function
     */
    virtual void RegisterScanCallbacks(const IScanSerivceCallbacks &iScanSerivceCallbacks);

    void RegisterP2pEnhanceCallback();

    void P2pEnhanceStateChange(const std::string &ifName, int32_t state, int32_t frequency);

    /**
     * @Description Start a complete Wi-Fi scan.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode Scan(ScanType scanType, int scanStyle = SCAN_DEFAULT_TYPE);
    /**
     * @Description Start Wi-Fi scanning based on specified parameters.
     *
     * @param params - Scan specified parameters[in]
     * @param scanType it is from ScanType[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode ScanWithParam(const WifiScanParams &params, ScanType scanType);
    /**
     * @Description Convert scanned hotspots to GBK.
     *
     * @param ssid - ssid of saved networks[in]
     * @param hiddenNetworkSsidList it is hiddenNetworkSsidList[out]
     */
    virtual void AddSsidToHiddenNetworkList(const std::string ssid, std::vector<std::string>& hiddenNetworkSsidList);
    /**
     * @Description Disable/Restore the scanning operation.
     *
     * * @param params - disable or not.
     * @return WIFI_OPT_SUCCESS: success, WIFI_OPT_FAILED: failed
     */
    ErrCode DisableScan(bool disable);
    /**
     * @Description Start/Stop pno scan
     *
     * @param isStartAction - true:start pno scan; false:stop pno scan
     * @param periodMs - pno scan interval
     * @param suspendReason - pno scan suspent reason
     * @return WIFI_OPT_SUCCESS: success, WIFI_OPT_FAILED: failed
     */
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason);
    /**
     * @Description Starting a Single Scan.
     *
     * @param scanConfig - Scanning parameters[in]
     * @return success: true, failed: false
     */
    bool SingleScan(ScanConfig &scanConfig);
    /**
     * @Description  Start PNO scanning
     * @return success: true, failed: false
     */
    bool BeginPnoScan();
    /**
     * @Description Start PNO scanning
     *
     * @param pnoScanConfig - PNO scanning parameters[in]
     * @param interScanConfig - common scanning parameters[in]
     * @return success: true, failed: false
     */
    bool PnoScan(const PnoScanConfig &pnoScanConfig, const InterScanConfig &interScanConfig);
    /**
     * @Description Disable PNO scanning.
     *
     */
    void EndPnoScan();
    /**
     * @Description Stop pno scan and clear local resource.
     */
    void StopPnoScan();
    /**
     * @Description The system scans and selects a scanning mode
     *              based on the current screen status and STA status.
     *
     * @param scanAtOnce - Whether to start scanning immediately[in]
     */
    virtual void SystemScanProcess(bool scanAtOnce);

    void ResetSingleScanCountAndMessage();

    void AddSingleScanCountAndMessage(int delaySeconds);

    /**
     * @Description The system single scans when sta disconnected &&
     *              screen On && scan is forbidden by Hid2dScene.
     */
    void SystemSingleScanProcess();

    /**
     * @Description Get some related freqs.
     * @param lastStaFreq - The frequency of last connected STA.[out]
     * @param p2pFreq - The frequency of current connected P2P.[out]
     * @param p2pEnhanceFreq - The frequency of current connected P2PEnhance.[out]
     */
    void GetRelatedFreqs(int &lastStaFreq, int &p2pFreq, int &p2pEnhanceFreq);

    /**
     * @Description The timeout processing of system single scan, which ignoring scan control.
     * @param scanStyle - Type of scan to trigger the WiFi chip
     */
    void StartSingleScanWithoutControlTimer(int scanStyle = SCAN_DEFAULT_TYPE);

    void SelectTheFreqToSingleScan(const int lastStaFreq, const int p2pFreq, const int p2pEnhanceFreq,
        int scanStyle = SCAN_DEFAULT_TYPE);

    /**
     * @Description Start single periodic scanning.
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @param freq - Single scan frequency.[in]
     */
    void StartSingleScanWithoutControl(int freq, int scanStyle = SCAN_DEFAULT_TYPE);

    /**
     * @Description Status reported by the state machine.
     *
     * @param scanStatusReport - Structure of the reported status.[in]
     */
    virtual void HandleScanStatusReport(ScanStatusReport &scanStatusReport);
    /**
     * @Description Internal event reporting and processing.
     *
     * @param innerEvent - Internal event[in]
     */
    void HandleInnerEventReport(ScanInnerEventType innerEvent);
    /**
     * @Description Screen State (On/Off) Change Handler
     *
     */
    virtual void HandleScreenStatusChanged();
    /**
     * @Description STA status change processing
     *
     * @param state - STA state[in]
     */
    virtual void HandleStaStatusChanged(int status);
    /**
     * @Description Network quality change processing
     *
     * @param state - Network quality[in]
     */
    virtual void HandleNetworkQualityChanged(int status);
    /**
     * @Description movingfreeze status change processing
     *
     */
    virtual void HandleMovingFreezeChanged();
    /**
     * @Description custom scene status change processing
     *
     * @param customScene custom scene[in]
     * @param customSceneStatus custom scene status[in]
     */
    virtual void HandleCustomStatusChanged(int customScene, int customSceneStatus);
    /**
     * @Description Get custom scene state.
     *
     * @param customState custom scene state map[out]
     * @return
     */
    virtual void HandleGetCustomSceneState(std::map<int, time_t>& sceneMap) const;
    /**
     * @Description Handle auto connect state.
     *
     * @param success auto connect state[in]
     * @return
     */
    virtual void HandleAutoConnectStateChanged(bool success);
    /**
     * @Description Query and save the scan control policy.
     *
     */
    virtual void GetScanControlInfo();
    /**
     * @Description When scanning control changes, the count data needs to be cleared.
     *
     */
    void ClearScanControlValue();
    /**
     * @Description When scanning control changes, the count data needs to be cleared.
     *
     */
    virtual void SetStaCurrentTime();
    /**
     * @Description Set EnhanceService to Scan Service.
     *
     * @param enhanceService IEnhanceService object
     * @return void
     */
    virtual void SetEnhanceService(IEnhanceService* enhanceService);
    /**
     * @Description Init chipset info.
     */
    virtual void InitChipsetInfo();
    /**
     * @Description  SetNetworkInterfaceUpDown
     *
     * @Output: Return operating results to Interface Service after set iface up dwon
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode SetNetworkInterfaceUpDown(bool upDown);
    /**
     * @Description Reset scan interval.
     *
     */
    virtual void ResetScanInterval();

private:
    using ScanConfigMap = std::map<int, StoreScanConfig>;
    using ScanInfoHandlerMap = std::map<std::string, ScanInfoHandler>;
    using PnoScanInfoHandlerMap = std::map<std::string, PnoScanInfoHandler>;

    std::shared_mutex mScanCallbackMutex;
    IScanSerivceCallbacks mScanSerivceCallbacks;
    ScanStateMachine *pScanStateMachine;             /* Scanning state machine pointer */
    ScanMonitor *pScanMonitor;                       /* Scanning Monitor Pointer */
    bool scanStartedFlag;                            /* The scanning is started */
    ScanInfoHandlerMap scanInfoHandlerMap;              /* Map of obtaining the scanning result */
    PnoScanInfoHandlerMap pnoScanInfoHandlerMap;        /* Map of obtaining PNO scanning results */
    ScanConfigMap scanConfigMap;                     /* Save Scan Configuration */
    int scanConfigStoreIndex;                        /* Index for saving the scan configuration */
    int64_t pnoScanStartTime;                        /* PNO scanning start time */
    int staStatus;                                   /* STA state */
    bool isPnoScanBegined;                           /* The PNO scanning has been started */
    bool autoNetworkSelection;                       /* Automatic network selection */
    int64_t lastSystemScanTime;                      /* Last System Scan Time */
    int pnoScanFailedNum;                            /* Number of PNO Scan Failures */
    std::atomic<int> systemScanFailedNum;
    ScanControlInfo scanControlInfo;                 /* Scan Control Policy */
    std::atomic<bool> disableScanFlag {false};       /* Disable Scan Flag. */
    std::vector<int> freqs2G;                        /* The support frequencys for 2.4G */
    std::vector<int> freqs5G;                        /* The support frequencys for 5G */
    std::vector<int> freqsDfs;                       /* The support frequencys for DFS */
    SystemScanIntervalMode systemScanIntervalMode;   /* Store system scan data */
    PnoScanIntervalMode pnoScanIntervalMode;         /* Store pno scan data */
    time_t customCurrentTime; /* Indicates the time when the STA enters the Customer-defined scenario */
    std::vector<SingleAppForbid> appForbidList; /* Store extern app scan data */
    /*
     * If the number of consecutive count times is less than the value of
     * interval, the user is added to the blocklist and cannot be scanned.
     */
    std::vector<int> scanBlocklist;
    /* Stores data that is scanned and controlled regardless of applications. */
    std::vector<SingleAppForbid> fullAppForbidList;
    std::map<int, time_t> customSceneTimeMap; /* Record the time when a scene is entered. */
    std::vector<PackageInfo> scan_thermal_trust_list;
    std::vector<PackageInfo> scan_frequency_trust_list;
    std::vector<PackageInfo> scan_screen_off_trust_list;
    std::vector<PackageInfo> scan_gps_block_list;
    std::vector<PackageInfo> scan_hid2d_list;
    int customSceneForbidCount;
    mutable std::mutex scanConfigMapMutex;
    mutable std::mutex scanControlInfoMutex;
    bool scanTrustMode;                              /* scan trustlist mode */
    std::unordered_set<int> scanTrustSceneIds;       /* scan scene ids */
    std::atomic<bool> lastFreezeState{false};                            /* last freeze state. */
    bool isAbsFreezeScaned;                          /* scanned in freeze state. */
    int scanResultBackup;                            /* scan result backup. */
    IEnhanceService *mEnhanceService;                /* EnhanceService handle */
    int m_instId;
    int lastNetworkQuality;
    int chipsetCategory;
    int chipsetFeatrureCapability {0};
    bool isChipsetInfoObtained;
    std::atomic<int> currSingleScanCount {0};
    int lastP2pEnhanceState {0};
    /**
     * @Description Obtains the frequency of a specified band.
     *
     * @param band - Scan frequency bands. Obtain the frequency list based on the frequency bands.[in]
     * @param freqs - Frequency list[out]
     * @return success: true, failed: false
     */
    bool GetBandFreqs(ScanBandType band, std::vector<int> &freqs);
    /**
     * @Description Enter the scanning message body.
     *
     * @param interMessage - Message pointer[in]
     * @param interConfig - Scan Configuration[in]
     * @return success: true, failed: false
     */
    bool AddScanMessageBody(InternalMessagePtr interMessage, const InterScanConfig &interConfig);
    /**
     * @Description Save Request Configuration
     *
     * @param scanConfig - Scanning parameters[in]
     * @param interConfig - Internal Scanning Parameters[in]
     * @return success: Saved request index, failed: MAX_SCAN_CONFIG_STORE_INDEX
     */
    int StoreRequestScanConfig(const ScanConfig &scanConfig, const InterScanConfig &interConfig);

    int GetWifiMaxSupportedMaxSpeed(const InterScanInfo &scanInfo, const int &maxNumberSpatialStreams);
    /**
     * @Description Convert InterScanInfo to WifiScanInfo
     *
     * @param scanInfo - Scanning Result[in]
     * @param interConfig - Internal Scanning Result[in]
     */
    void ConvertScanInfo(WifiScanInfo &scanInfo, const InterScanInfo &interInfo);

#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    /**
     * @Description get risktype of each wifi based on the entire scan list.
     * @param scanInfos - Scanning Result list
     */
    void GetWifiRiskType(std::vector<InterScanInfo> &scanInfos);

    /**
     * @Description get report clone attack chr event
     * @param interInfo -single wifi scan result
     */
    void ReportWifiCloneAttackHiSysEvent(const InterScanInfo &interInfo);
#endif
    
    /**
     * @Description Merge scan result
     *
     * @param results - Scanning Result Cache[in]
     * @param storeInfoList - New Scanning Result[in]
     */
    void MergeScanResult(std::vector<WifiScanInfo> &results, std::vector<WifiScanInfo> &storeInfoList);
    /**
     * @Description Try to restore saved network
     */
    void TryToRestoreSavedNetwork();
    /**
     * @Description Save the scanning result in the configuration center.
     *
     * @param scanConfig - scan Config[in]
     * @param scanInfoList - scan result list[in]
     * @return success: true, failed: false
     */
    bool StoreFullScanInfo(const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList);
    /**
     * @Description Saves the scanning result of specified parameters in the configuration center.
     *
     * @param scanConfig - scan Config[in]
     * @param scanInfoList - scan result list[in]
     * @return success: true, failed: false
     */
    bool StoreUserScanInfo(const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList);

    void ReportScanStartEvent();
    void ReportScanStopEvent();
    void ReportScanFinishEvent(int event);
    /**
     * @Description Sends the scanning result to the interface service,
     *              which then sends the scanning result to the connection
     *              management module for processing.
     *
     * @param scanInfoList - scan result list[in]
     */
    void ReportScanInfos(std::vector<InterScanInfo> &interScanList);

    /**
     * @Description Sends the store scanning result to the interface service,
     *              which then sends the store scanning result to the connection
     *              management module for processing.
     *
     * @param scanInfoList - scan result list[in]
     */
    void ReportStoreScanInfos(std::vector<InterScanInfo> &interScanList);

    /**
     * @Description Enter the PNO scanning message body.
     *
     * @param interMessage - Message pointer[in]
     * @param pnoScanConfig - PNO Scanning Configuration[in]
     * @return success: true, failed: false
     */
    bool AddPnoScanMessageBody(InternalMessagePtr interMessage, const PnoScanConfig &pnoScanConfig);
    /**
     * @Description Stopping System Scanning
     *
     */
    void StopSystemScan();
    /**
     * @Description Start the periodic scanning.
     *
     * @param scanAtOnce - Whether to start a scan immediately[in]
     */
    void StartSystemTimerScan(bool scanAtOnce);
    /**
     * @Description System scanning timer expiration processing.
     *
     */
    void HandleSystemScanTimeout();
    /**
     * @Description Detected disconnections at intervals and started scanning.
     *
     */
    void DisconnectedTimerScan();
    /**
     * @Description Detected disconnections at intervals and started scanning.
     *
     */
    void HandleDisconnectedScanTimeout();
    /**
     * @Description Callback function for obtaining the scanning result
     *
     * @param requestIndexList - Request Index List[in]
     * @param scanInfoList - Scan Info List[in]
     */
    void HandleCommonScanInfo(std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList);
    /**
     * @Description Handle scanning result
     *
     * @param requestIndexList - Request Index List[in]
     * @param scanInfoList - Scan Info List[in]
     * @param fullScanStored - Full scan stored [in]
     */
    void HandleScanResults(std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList,
        bool &fullScanStored);
    /**
     * @Description Common scanning failure processing
     *
     * @param requestIndexList - Request Index List[in]
     */
    void HandleCommonScanFailed(std::vector<int> &requestIndexList);
    /**
     * @Description System scanning failure processing, restart after a delay.
     *
     */
    void HandleSystemScanFailed();
    /**
     * @Description LP scanning failure processing, restart common scan after a delay.
     *
     */
    void HandleLpScanFailed();
    /**
     * @Description Determine whether to allow common scan when LP scan fails.
     *
     */
    bool AllowCommonScanOnLpScanFailure();
    /**
     * @Description Callback function for obtaining the PNO scanning result
     *
     * @param scanInfoList - Scan Info List[in]
     */
    void HandlePnoScanInfo(std::vector<InterScanInfo> &scanInfoList);
    /**
     * @Description PNO scanning failed, Restart after a delay.
     *
     */
    void RestartPnoScanTimeOut();
    /**
     * @Description Control the strategy of inner scan
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     */
    ErrCode ScanControlInner(ScanType scanType, int &scanStyle);
    /**
     * @Description Lp scan failed, Restart common scan after a delay.
     */
    void RestartCommonScanAfterLpScanFailed();
    /**
     * @Description System scanning failed, Restart after a delay.
     */
    void RestartSystemScanTimeOut();
    /**
     * @Description System single freq scanning timer expiration processing.
     */
    void HandleSystemSingleScanTimeOut();
    /**
     * @Description Determines whether external scanning is allowed based on the scanning policy.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowExternScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether native external scanning is allowed based on the scanning policy.
     *
     * @return success: true, failed: false
     */
    ErrCode AllowNativeExternScan();
    /**
     * @Description Determine whether to allow scheduled system scanning.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowSystemTimerScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Extra determine whether to allow scheduled system scanning.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowSystemTimerScanExtra(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether to allow PNO scanning based on the scanning policy.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowPnoScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether to allow WifiPro scanning based on the scanning policy.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowWifiProScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether to allow 5G Ap scanning based on the scanning policy.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode Allow5GApScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether to allow single frequency scan based on
     *              screenState && staState && Hid2dScanControl.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return success: true, failed: false
     */
    ErrCode AllowSystemSingleScan(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether to allow scanning based on the scanning type..
     *
     * @param scanType - scan type: 0 - Extern; 1 - SystemTimer 2 Pno
     * @param scanStyle - Type of scan to trigger the WiFi chip
     * @return true: allow, false: not allowed.
     */
    ErrCode AllowScanByType(ScanType scanType, int &scanStyle);
    /**
     * @Description Set the current mode to trust list mode.
     *
     */
    void SetScanTrustMode();
    /**
     * @Description Reset to non scan trust list mode.
     *
     */
    void ResetToNonTrustMode();
    /**
     * @Description Is it the trust list mode?
     *
     * @param sceneId - current scene id[out].
     * @return true: success, false: failed
     */
    bool IsScanTrustMode() const;
    /**
     * @Description Add the scene id to trust list.
     * Assume that the scene id of moving freeze is -1.
     *
     * @param sceneId - scene id.
     */
    void AddScanTrustSceneId(int sceneId);
    /**
     * @Description Clear trust list.
     *
     */
    void ClearScanTrustSceneIds();
    /**
     * @Description Is sceneId in trust list.
     *
     * @param sceneId - scene id.
     */
    bool IsInScanTrust(int sceneId) const;
    /**
     * @Description Is it the moving freeze state?
     *
     * @param appRunMode - current scan mode.
     * @return true: success, false: failed
     */
    bool IsMovingFreezeState(ScanMode appRunMode) const;
    /**
     * @Description Whether scanned in moving freeze state.?
     *
     */
    bool IsMovingFreezeScaned() const;
    /**
     * @Description Apply trustlists scanning policies.
     *
     * @param scanType - scan type: 0 - Extern; 1 - SystemTimer 2 Pno
     * @return true: success, false: failed
     */
    ErrCode ApplyTrustListPolicy(ScanType scanType);
    /* *
     * @Description  Obtains the current screen.
     *
     * @return success: ScanScene, failed: SCAN_SCENE_MAX
     */
    int GetStaScene();

    /**
     * @Description Determines whether externally initiated scanning is being processed.
     *
     * @return success: true, failed: false
     */
    bool IsExternScanning() const;
    /**
     * @Description Indicates whether scanning with parameter.
     *
     * @return success: true, failed: false
     */
    bool IsScanningWithParam();
    /**
     * @Description Adjust the frequency band and frequency based on the scanning policy.
     *
     * @param scanBand - scan band[in]
     * @param freqs - scan frequency[in]
     */
    void GetAllowBandFreqsControlInfo(ScanBandType &scanBand, std::vector<int> &freqs);
    /**
     * @Description Do not adjust the frequency band when the 2.4 GHz frequency band is used.
     *
     * @param scanBand - scan band[in]
     * @return ScanBandType - scan band
     */
    ScanBandType ConvertBandNotAllow24G(ScanBandType scanBand);
    /**
     * @Description Do not adjust the frequency band when the 5 GHz frequency band is used.
     *
     * @param scanBand - scan band[in]
     * @return ScanBandType - scan band
     */
    ScanBandType ConvertBandNotAllow5G(ScanBandType scanBand);
    /**
     * @Description Delete the 2.4 GHz frequency from the frequency list.
     *
     * @param freqs - frequency[in]
     */
    void Delete24GhzFreqs(std::vector<int> &freqs);
    /**
     * @Description Delete the 5 GHz frequency from the frequency list.
     *
     * @param freqs - frequency list[in]
     */
    void Delete5GhzFreqs(std::vector<int> &freqs);
    /**
     * @Description Get the ssid of saved networks.
     *
     * @param savedNetworkSsid - ssid of saved networks[out]
     * @return success: true, failed: false
     */
    bool GetSavedNetworkSsidList(std::vector<std::string> &savedNetworkSsid);
    /**
     * @Description Get the ssid of saved hidden networks.
     *
     * @param hiddenNetworkSsid - ssid of hidden networks[out]
     * @return success: true, failed: false
     */
    bool GetHiddenNetworkSsidList(std::vector<std::string> &hiddenNetworkSsid);
    /**
     * @Description ScanForbidMap control mode specific implementation for specific scanning mode.
     *
     * @param isStaScene - Indicates whether the STA scenario is used.[in]
     * @param scanScene - scan scene[in][in]
     * @param scanMode - scan mode[in][in]
     * @return success: true, failed: false
     */
    bool AllowScanByForbidMap(int scanScene, ScanMode scanMode, time_t currentTime);
    /**
     * @Description Check whether the scan mode can be used during scanning under the forbid mode control.
     *
     * @param scanMode scan mode[in]
     * @return true - success
     * @return false  - failed
     */
    bool AllowScanDuringScanning(ScanMode scanMode) const;
    /**
     * @Description
     *
     * @param staScene sta scan scene[in]
     * @param scanMode scan mode[in]
     * @return true - success
     * @return false  - failed
     */
    bool AllowScanDuringStaScene(int staScene, ScanMode scanMode);
    /**
     * @Description Check whether the scan mode can be used during custom scene off under the forbid mode control.
     *
     * @param scanMode [in]
     * @return true - success
     * @return false  - failed
     */
    bool AllowScanDuringCustomScene(ScanMode scanMode);
    /**
     * @Description Check whether the scan mode can be used under the interval mode control.
     *
     * @param appId App type for external requests to scan.[in]
     * @param scanScene scan scene[in]
     * @param scanMode scna mode[in]
     * @return true - success
     * @return false  - failed
     */
    bool AllowExternScanByIntervalMode(int appId, int scanScene, ScanMode scanMode);
#ifdef SUPPORT_SCAN_CONTROL
    /**
     * @Description Determines whether to allow system scan based on scanInterval control mode.
     *
     * @param staScene - sta scene.[in]
     * @param interval - system scan interval[in]
     * @param count - Total number of times that the scanning interval is multiplied by 2[in]
     * @return success: true, failed: false
     */
    bool SystemScanByInterval(int staScene, int &interval, int &count);
#else
    /**
     * @Description Determines whether to allow system scan based on scanInterval control mode.
     *
     * @param expScanCount - Number of scan.[in]
     * @param interval - system scan interval[in]
     * @param count - Total number of times that the scanning interval is multiplied by 2[in]
     * @return success: true, failed: false
     */
    bool SystemScanByInterval(int &expScanCount, int &interval, int &count);
#endif
    /**
     * @Description Determines whether to allow pno scan based on scanInterval control mode.
     *
     * @param fixedScanCount pno scan count[in]
     * @param fixedScanTime pno scan time[in]
     * @param interval pno scan interval[in]
     * @param count pno scan max count[in]
     * @return true - success
     * @return false  - failed
     */
    bool PnoScanByInterval(int &fixedScanCount, time_t &fixedScanTime, int interval, int count);
    /**
     * @Description Determines whether to allow extern scan based on scanInterval control mode.
     *
     * @param appId ID of the app to be scanned[in]
     * @param singleAppForbid Stored External Scan Parameters[in]
     * @return true
     * @return false
     */
    bool ExternScanByInterval(int appId, SingleAppForbid &singleAppForbid);
    /**
     * @Description Determine whether external scanning of a single application can be distinguished.
     *
     * @param appId ID of the app to be scanned[in]
     * @param scanIntervalMode scan control policy parameters[in]
     * @return true
     * @return false
     */
    bool AllowSingleAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode);
    /**
     * @Description Check whether external scanning is allowed regardless of a single application.
     *
     * @param appId ID of the app to be scanned[in]
     * @param scanIntervalMode intervalMode scan control policy parameters[in]
     * @return true
     * @return false
     */
    bool AllowFullAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode);
    /**
     * @Description Determines whether external scanning is allowed in scanning control in INTERVAL_FIXED mode.
     *
     * @param fixedScanCount INTERVAL_FIXED intervalMode scan time[in]
     * @param fixedScanTime INTERVAL_FIXED intervalMode scan time[in]
     * @param interval scan interval[in]
     * @param count scan count[in]
     * @return true
     * @return false
     */
    bool AllowScanByIntervalFixed(int &fixedScanCount, time_t &fixedScanTime, int &interval, int &count);
    /**
     * @Description Determines whether external scanning is allowed in scanning control in INTERVAL_EXP mode.
     *
     * @param expScanCount INTERVAL_EXP intervalMode scan count[in]
     * @param interval scan interval[in]
     * @param count scan count[in]
     * @return true
     * @return false
     */
    bool AllowScanByIntervalExp(int &expScanCount, int &interval, int &count);
    /**
     * @Description Determines whether external scanning is allowed in scanning control in INTERVAL_CONTINUE mode.
     *
     * @param continueScanTime INTERVAL_CONTINUE intervalMode scan time[in]
     * @param lessThanIntervalCount INTERVAL_CONTINUE intervalMode scan count[in]
     * @param interval scan interval[in]
     * @param count scan count[in]
     * @return true
     * @return false
     */
    bool AllowScanByIntervalContinue(time_t &continueScanTime, int &lessThanIntervalCount, int &interval, int &count);
    /**
     * @Description Determines whether external scanning is allowed in scanning control in INTERVAL_BLOCKLIST mode.
     *
     * @param appId ID of the app to be scanned[in]
     * @param blockListScanTime INTERVAL_BLOCKLIST intervalMode scan time[in]
     * @param lessThanIntervalCount INTERVAL_BLOCKLIST intervalMode scan count[in]
     * @param interval scan interval[in]
     * @param count scan count[in]
     * @return true
     * @return false
     */
    bool AllowScanByIntervalBlocklist(
        int appId, time_t &blockListScanTime, int &lessThanIntervalCount, int &interval, int &count);

        /**
     * @Description Determines whether scanning is allowed by disable scan control.
     *
     * @return true: allow, false: not allowed.
     */
    bool AllowScanByDisableScanCtrl();
    /**
     * @Description Determines whether scanning is allowed in movingfreeze mode.
     *
     * @param appRunMode scan mode
     * @return true: allow, false: not allowed.
     */
    bool AllowScanByMovingFreeze(ScanMode appRunMode);
    /**
     * @Description Determines whether lp scan is allowed.
     *
     * @param scanType it is from ScanType[in]
     * @return true: allow, false: not allowed.
     */
    bool AllowLpScan(ScanType scanType);
    /**
     * @Description Determines whether scanning is allowed in hid2d state.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return true: allow, false: not allowed.
     */
    bool AllowScanByHid2dState(ScanType scanType, int &scanStyle);
    /**
     * @Description Determines whether scanning is allowed in ActionListen state.
     *
     * @return true: allow, false: not allowed.
     */
    bool AllowScanByActionListen();
    /**
     * @Description Determines whether scanning is allowed in Game Scene.
     *
     * @param scanType it is from ScanType[in]
     * @param scanStyle - Type of scan to trigger the WiFi chip[in]
     * @return true: allow, false: not allowed.
     */
    bool AllowScanByGameScene(ScanType scanType, int &scanStyle);
    /**
     * @Description Get interval time between currentMs and startTime.
     *
     * @return int64_t: millisecond difference between two time point.
     */
    int64_t GetIntervalTime(int64_t startTime);

    /**
     * @Description Is the app in the trustlist?
     *
     * @param trustList trustlist[in]
     * @param sceneId scene id[in]
     * @param appPackageName app package name[in]
     * @return true: in the trustlist, false: not in the trustlist.
     */
    bool IsPackageInTrustList(const std::string& trustList, int sceneId, const std::string &appPackageName) const;
    /* *
     * @Description all scan check at custom check.
     *
     * @param customIter custom iterator[in]
     * @param scanMode scene mode[in]
     * @return true: allow, false: not allowed.
     */
    bool AllowCustomSceneCheck(const std::map<int, time_t>::const_iterator &customIter, ScanMode scanMode);
    /* *
     * @Description Is app in the filter list.
     *
     * @param packageFilter packageFilter[in]
     * @return true: int the list, false: not in the list.
     */
    bool IsAppInFilterList(const std::vector<PackageInfo> &packageFilter) const;
    /* *
     * @Description adjust system scan interval when sta connected.
     *
     * @param interval scan interval[in]
     */
    void SystemScanConnectedPolicy(int &interval);
    /* *
     * @Description adjust system scan interval when sta disconnected.
     *
     * @param interval scan interval[in]
     * @param count adjust count[in]
     */
    void SystemScanDisconnectedPolicy(int &interval, int &count);

#ifndef OHOS_ARCH_LITE
    class WifiCountryCodeChangeObserver : public IWifiCountryCodeChangeListener {
    public:
        WifiCountryCodeChangeObserver(const std::string &name, StateMachine &stateMachineObj)
            : IWifiCountryCodeChangeListener(name, stateMachineObj) {}
        ~WifiCountryCodeChangeObserver() override = default;
        ErrCode OnWifiCountryCodeChanged(const std::string &wifiCountryCode) override;
        std::string GetListenerModuleName() override;
    };
    std::shared_ptr<IWifiCountryCodeChangeListener> m_scanObserver;
#endif

    /**
     * @Description Check whether a quick scan is required
     *
     * @param scan freq
     */
     void CheckNeedFastScan(std::vector<int> &scanFreqs);
     
     /**
     * @Description get freq from historical connection freq
     *
     * @param scan freq
     */
    void GetSavedNetworkFreq(std::vector<int> &scanFreqs);
};
}  // namespace Wifi
}  // namespace OHOS

#endif
