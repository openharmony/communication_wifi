/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SCAN_MANAGER_H
#define OHOS_WIFI_SCAN_MANAGER_H

#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "iscan_service_callbacks.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {
class WifiScanManager {
public:
    WifiScanManager();
    ~WifiScanManager() = default;

    IScanSerivceCallbacks& GetScanCallback(void);
    void StopUnloadScanSaTimer(void);
    void StartUnloadScanSaTimer(void);
    void CheckAndStartScanService(int instId = 0);
    void CheckAndStopScanService(int instId = 0);
    void CloseScanService(int instId = 0);

private:
    void InitScanCallback(void);
    void DealScanOpenRes(int instId = 0);
    void DealScanCloseRes(int instId = 0);
    void DealScanFinished(int state, int instId = 0);
    void DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId = 0);
    void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId = 0);

private:
    IScanSerivceCallbacks mScanCallback;
    uint32_t unloadScanSaTimerId{0};
    std::mutex unloadScanSaTimerMutex;
};

}  // namespace Wifi
}  // namespace OHOS
#endif // OHOS_WIFI_SCAN_MANAGER_H