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

#ifndef OHOS_WIFI_CONNECTIVITYHELPER_H
#define OHOS_WIFI_CONNECTIVITYHELPER_H

#include "wifi_log.h"
#include "wifi_settings.h"
#include "wifi_msg.h"
#include "wifi_error_no.h"
#include "wifi_idl_struct.h"
#include "wifi_sta_hal_interface.h"

namespace OHOS {
namespace Wifi {
static const int INVALID_LIST_SIZE = -1;
static const int WIFI_FEATURE_CONTROL_ROAMING = 0x800000;

class StaConnectivityHelper {
public:
    StaConnectivityHelper();
    ~StaConnectivityHelper();
    /**
     * @Description  Querying Firmware Information
     *
     * @Return: If the operation is successful, true is returned.
                If firmware roaming is supported but the valid roaming
                capability cannot be obtained, false is returned.
     */
    bool ObtainingFirmwareRoamingInfo();
    /**
     * @Description  Whether firmware roaming is supported
     *
     * @Return: bool
     */
    bool WhetherFirmwareRoamingIsSupported() const;
    /**
     * @Description  Obtains the maximum size supported by the BSSID blocklist firmware.
     *
     * @Return: If firmware roaming is not supported, INVALID_LIST_SIZE is returned.
               Otherwise, the maximum size supported by the BSSID blocklist firmware is returned.
     */
    int GetMaxNumBssidBlocklist() const;
    /**
     * @Description  Write Firmware Roaming Configuration to Firmware
     *
     * @param blocklistBssids - List of BSSIDs to Be Added to the Blocklist(in)
     * @Return: True if successful, false otherwise
     */
    bool SetFirmwareRoamingConfig(const std::vector<std::string> &blocklistBssids) const;

private:
    bool supportForFirmwareRoaming;
    int maxNumBssidBlocklist;
};
}  // namespace Wifi
}  // namespace OHOS
#endif