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
#include "wifi_chip_hal_interface.h"
#include <mutex>
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiChipHalInterface"

namespace OHOS {
namespace Wifi {
WifiChipHalInterface &WifiChipHalInterface::GetInstance(void)
{
    static WifiChipHalInterface inst;
    static int initFlag = 0;
    static std::mutex initMutex;
    if (initFlag == 0) {
        std::unique_lock<std::mutex> lock(initMutex);
        if (initFlag == 0) {
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
        }
    }
    return inst;
}

WifiErrorNo WifiChipHalInterface::GetWifiChipObject(int id, IWifiChip &chip)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetWifiChipObject(id, chip);
}

WifiErrorNo WifiChipHalInterface::GetChipIds(std::vector<int> &ids)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetChipIds(ids);
}

WifiErrorNo WifiChipHalInterface::GetUsedChipId(int &id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetUsedChipId(id);
}

WifiErrorNo WifiChipHalInterface::GetChipCapabilities(int &capabilities)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetChipCapabilities(capabilities);
}

WifiErrorNo WifiChipHalInterface::GetSupportedModes(std::vector<int> &modes)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetSupportedModes(modes);
}

WifiErrorNo WifiChipHalInterface::ConfigRunModes(int mode)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ConfigRunModes(mode);
}

WifiErrorNo WifiChipHalInterface::GetCurrentMode(int &mode)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetCurrentMode(mode);
}

WifiErrorNo WifiChipHalInterface::RegisterChipEventCallback(WifiChipEventCallback &callback)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RegisterChipEventCallback(callback);
}

WifiErrorNo WifiChipHalInterface::RequestFirmwareDebugInfo(std::string &debugInfo)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RequestFirmwareDebugInfo(debugInfo);
}

WifiErrorNo WifiChipHalInterface::IsSupportDbdc(bool &isSupport) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqIsSupportDbdc(isSupport);
}

WifiErrorNo WifiChipHalInterface::IsSupportCsa(bool &isSupport) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqIsSupportCsa(isSupport);
}

WifiErrorNo WifiChipHalInterface::IsSupportRadarDetect(bool &isSupport) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqIsSupportRadarDetect(isSupport);
}

WifiErrorNo WifiChipHalInterface::IsSupportDfsChannel(bool &isSupport) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqIsSupportDfsChannel(isSupport);
}

WifiErrorNo WifiChipHalInterface::IsSupportIndoorChannel(bool &isSupport) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqIsSupportIndoorChannel(isSupport);
}
}  // namespace Wifi
}  // namespace OHOS