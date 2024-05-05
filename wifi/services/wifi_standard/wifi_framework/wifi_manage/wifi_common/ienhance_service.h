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
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
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
     * @return 1: DEFAULT, 2: WIFI6, 3: WIFI6_PLUS
     */
    virtual WifiCategory GetWifiCategory(
        std::vector<WifiInfoElem> infoElems, int chipsetCategory, int chipsetFeatrureCapability);
};
}  // namespace Wifi
}  // namespace OHOS
#endif