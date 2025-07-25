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
#ifndef OHOS_ISCAN_SERVICE_H
#define OHOS_ISCAN_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "iscan_service_callbacks.h"
#include "ienhance_service.h"

namespace OHOS {
namespace Wifi {
class IScanService {
public:
    virtual ~IScanService() = default;
    /**
     * @Description  Scan service initialization function.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode Init() = 0;
    /**
     * @Description  Stopping the Scan Service.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode UnInit() = 0;
    /**
     * @Description Processes interface service scan request.
     *
     * @param externFlag it is from an external scan[in]
     * @param scanType it is from ScanType
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode Scan(bool externFlag, ScanType scanType = ScanType::SCAN_DEFAULT) = 0;
    /**
     * @Description Processes interface service scan with param request.
     *
     * @param wifiScanParams Parameters in the scan request[in]
     * @param externFlag it is from an external scan[in]
     * @param scanType it is from ScanType
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode ScanWithParam(const WifiScanParams &wifiScanParams, bool externFlag,
        ScanType scanType = ScanType::SCAN_DEFAULT) = 0;
    /**
     * @Description Disable/Restore the scanning operation.
     *
     * * @param params - disable or not.
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode DisableScan(bool disable) = 0;
    /**
     * @Description Start/Stop pno scan
     *
     * @param isStartAction - true:start pno scan; false:stop pno scan
     * @param periodMs - pno scan interval
     * @param suspendReason - pno scan suspent reason
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) = 0;
    /**
     * @Description Processes interface service screen change request.
     *
     * @param screenState screen state[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnScreenStateChanged(int screenState) = 0;
    /**
     * @Description Processes interface service standby state change request.
     *
     * @param sleeping is sleeping[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnStandbyStateChanged(bool sleeping) = 0;
    /**
     * @Description Processes interface service sta status change request.
     *
     * @param staStatus sta status[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnClientModeStatusChanged(int staStatus, int networkId = INVALID_NETWORK_ID) = 0;
    /**
     * @Description Processes interface service appMode change request.
     *
     * @param appMode operate app mode[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnAppRunningModeChanged(ScanMode appRunMode) = 0;
    /**
     * @Description Updates the MovingFreeze state when the associated state changes.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnMovingFreezeStateChange() = 0;
    /**
     * @Description Processes interface service custom scene change request.
     *
     * @param customScene custom scene[in]
     * @param customSceneStatus Enter or exit the customized scenario[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnCustomControlStateChanged(int customScene, int customSceneStatus) = 0;
    /**
     * @Description Get custom scene state.
     *
     * @param sceneMap custom scene state map[out]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnGetCustomSceneState(std::map<int, time_t>& sceneMap) = 0;
    /**
     * @Description Processes interface service scan control info change request.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnControlStrategyChanged() = 0;
    /**
     * @Description Auto connect state change.
     *
     * @param success auto connect state[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode OnAutoConnectStateChanged(bool success) = 0;
    /**
     * @Description Registers the callback function of the scanning module to the interface service.
     *
     * @param scanSerivceCallbacks callback function
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode RegisterScanCallbacks(const IScanSerivceCallbacks &scanSerivceCallbacks) = 0;
    /**
     * @Description Set EnhanceService to Scan Service.
     *
     * @param enhanceService IEnhanceService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode SetEnhanceService(IEnhanceService *enhanceService) = 0;
    /**
     * @Description  SetNetworkInterfaceUpDown
     *
     * @Output: Return operating results to Interface Service after set iface up dwon
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode SetNetworkInterfaceUpDown(bool upDown) = 0;
    /**
     * @Description Reset scan interval.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode ResetScanInterval() = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
