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

#ifndef OHOS_WIFI_SCAN_INTERFACE_H
#define OHOS_WIFI_SCAN_INTERFACE_H

#include <map>
#include <mutex>
#include "define.h"
#include "iscan_service.h"
#include "scan_service.h"

namespace OHOS {
namespace Wifi {
class ScanInterface : public IScanService {
    FRIEND_GTEST(ScanInterface);
public:
    explicit ScanInterface(int instId = 0);
    ~ScanInterface();

    /**
     * @Description  Scan service initialization function.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode Init() override;
    /**
     * @Description  Stopping the Scan Service
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode UnInit() override;
    /**
     * @Description Processes interface service scan request.
     *
     * @param externFlag it is from an external scan[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode Scan(bool externFlag) override;
    /**
     * @Description Processes interface service scan with param request.
     *
     * @param wifiScanParams Parameters in the scan request[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode ScanWithParam(const WifiScanParams &wifiScanParams) override;
    /**
     * @Description Disable/Restore the scanning operation.
     *
     * * @param params - disable or not.
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode DisableScan(bool disable) override;
    /**
     * @Description Start/Stop pno scan
     *
     * @param isStartAction - true:start pno scan; false:stop pno scan
     * @param periodMs - pno scan interval
     * @param suspendReason - pno scan suspent reason
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) override;
    /**
     * @Description Processes interface service screen change request.
     *
     * @param screenState screen state[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnScreenStateChanged(int screenState) override;
    /**
     * @Description Processes interface service standby state change request.
     *
     * @param sleeping is sleeping[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnStandbyStateChanged(bool sleeping) override;
    /**
     * @Description Processes interface service sta status change request.
     *
     * @param staStatus sta status[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnClientModeStatusChanged(int staStatus) override;
    /**
     * @Description Processes interface service appMode change request.
     *
     * @param appMode operate app mode[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnAppRunningModeChanged(ScanMode appRunMode) override;
    /**
     * @Description Updates the MovingFreeze state when the associated state changes.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnMovingFreezeStateChange() override;
    /**
     * @Description Processes interface service custom scene change request.
     *
     * @param customScene custom scene[in]
     * @param customSceneStatus Enter or exit the customized scenario[in]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnCustomControlStateChanged(int customScene, int customSceneStatus) override;
    /**
     * @Description Get custom scene state.
     *
     * @param sceneMap custom scene state map[out]
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnGetCustomSceneState(std::map<int, time_t>& customSceneStateMap) override;
    /**
     * @Description Processes interface service scan control info change request.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode OnControlStrategyChanged() override;
    /**
     * @Description Registers the callback function of the scanning module to the interface service.
     *
     * @param scanSerivceCallbacks callback function
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode RegisterScanCallbacks(const IScanSerivceCallbacks &scanSerivceCallbacks) override;
    /**
     * @Description Set EnhanceService to Scan Service.
     *
     * @param enhanceService IEnhanceService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode SetEnhanceService(IEnhanceService* enhanceService) override;
    /**
     * @Description  SetNetworkInterfaceUpDown
     *
     * @Output: Return operating results to Interface Service after set iface up dwon
               successfully through callback function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    virtual ErrCode SetNetworkInterfaceUpDown(bool upDown) override;
private:
    ScanService *pScanService;
    IScanSerivceCallbacks mScanSerivceCallbacks;
    std::mutex mutex;
    int m_instId;
};
}  // namespace Wifi
}  // namespace OHOS

#endif
