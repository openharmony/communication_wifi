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

#include "sta_connectivity_helper.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_CONNECTIVITY_HELPER"

namespace OHOS {
namespace Wifi {
StaConnectivityHelper::StaConnectivityHelper()
    : supportForFirmwareRoaming(false), maxNumBssidBlocklist(INVALID_LIST_SIZE)
{}
StaConnectivityHelper::~StaConnectivityHelper()
{
    LOGI("Enter StaConnectivityHelper::~StaConnectivityHelper.\n");
}

bool StaConnectivityHelper::ObtainingFirmwareRoamingInfo()
{
    LOGI("Enter StaConnectivityHelper::ObtainingFirmwareRoamingInfo.\n");

    unsigned int capabilities;
    if (WifiStaHalInterface::GetInstance().GetStaCapabilities(capabilities) == WIFI_IDL_OPT_OK) {
        if ((capabilities & WIFI_FEATURE_CONTROL_ROAMING) == 0) {
            LOGE("Firmware roaming is not supported.\n");
            return false;
        }
    }

    WifiIdlRoamCapability capability;
    if (WifiStaHalInterface::GetInstance().GetRoamingCapabilities(capability) == WIFI_IDL_OPT_OK) {
        if (capability.maxBlocklistSize > 0) {
            supportForFirmwareRoaming = true;
            maxNumBssidBlocklist = capability.maxBlocklistSize;
            LOGI("Get firmware roaming capabilities succeeded.\n");
            return true;
        }
        LOGE("Invalid firmware roaming capabilities.\n");
    }

    LOGE("Get firmware roaming capabilities failed.\n");
    return false;
}

bool StaConnectivityHelper::WhetherFirmwareRoamingIsSupported() const
{
    LOGI("Enter StaConnectivityHelper::WhetherFirmwareRoamingIsSupported.\n");
    return supportForFirmwareRoaming;
}

int StaConnectivityHelper::GetMaxNumBssidBlocklist() const
{
    LOGI("Enter StaConnectivityHelper::GetmaxNumBssidBlocklist.\n");
    return (supportForFirmwareRoaming) ? maxNumBssidBlocklist : INVALID_LIST_SIZE;
}

bool StaConnectivityHelper::SetFirmwareRoamingConfig(const std::vector<std::string> &blocklistBssids) const
{
    LOGI("Enter StaConnectivityHelper::SetFirmwareRoamingConfig.\n");
    if (!supportForFirmwareRoaming) {
        return false;
    }

    if (blocklistBssids.empty()) {
        return false;
    }

    if (static_cast<int>(blocklistBssids.size()) > maxNumBssidBlocklist) {
        return false;
    }

    WifiIdlRoamConfig capability;
    capability.blocklistBssids = blocklistBssids;
    if (WifiStaHalInterface::GetInstance().SetRoamConfig(capability) == WIFI_IDL_OPT_OK) {
        return true;
    }
    return false;
}
}  // namespace Wifi
}  // namespace OHOS