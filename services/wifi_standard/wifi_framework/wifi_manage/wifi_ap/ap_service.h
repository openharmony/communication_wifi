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
#ifndef OHOS_AP_SERVICE_H
#define OHOS_AP_SERVICE_H

#include "ap_define.h"
#include "wifi_internal_msg.h"
#include "wifi_settings.h"
#include "i_ap_service.h"
#include "i_ap_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class ApService {
private:
    /**
     * @Description  construction method.
     * @param None
     * @return None
     */
    ApService();

    /**
     * @Description  destructor method.
     * @param None
     * @return None
     */
    ~ApService();
    DISALLOW_COPY_AND_ASSIGN(ApService)
public:
    /**
     * @Description  Obtains a single g_instance.
     * @param None
     * @return Reference to singleton objects
     */
    static ApService &GetInstance();
    /**
     * @Description  Delete a single g_instance.
     * @param None
     * @return None
     */
    static void DeleteInstance();

    /**
     * @Description  open hotspot
     * @param None
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode EnableHotspot() const;

    /**
     * @Description  close hotspot
     * @param None
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode DisableHotspot() const;

    /**
     * @Description  set ap config
     * @param cfg - ap config
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode SetHotspotConfig(const HotspotConfig &cfg) const;

    /**
     * @Description  add block list
     * @param stationInfo - sta infos
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode AddBlockList(const StationInfo &stationInfo) const;

    /**
     * @Description  delete block list
     * @param stationInfo - sta infos
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode DelBlockList(const StationInfo &stationInfo) const;

    /**
     * @Description  Disconnect a specified STA
     * @param stationInfo - sta infos
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode DisconnetStation(const StationInfo &stationInfo) const;

    /**
     * @Description Sets the callback function for the state machine.
     *
     * @param callbacks - callbacks list.
     * @return ErrCode - success: WIFI_OPT_SUCCESS    failed: ERROR_CODE
     */
    ErrCode RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks);
};
}  // namespace Wifi
}  // namespace OHOS

#endif