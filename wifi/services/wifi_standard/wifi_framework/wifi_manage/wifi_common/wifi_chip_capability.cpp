/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "wifi_chip_capability.h"
#include <sstream>
#include "wifi_chip_hal_interface.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("ChipCapability");
ChipCapability& ChipCapability::GetInstance()
{
    static ChipCapability inst;
    return inst;
}

ChipCapability::ChipCapability()
{
    m_isInitialized = false;
    m_isSupportDbdc = false;
    m_isSupportCsa = false;
    m_isSupportRadarDetect = false;
    m_isSupportDfsChannel = false;
    m_isSupportIndoorChannel = false;
}

ChipCapability::~ChipCapability()
{
}

bool ChipCapability::InitializeChipCapability()
{
    WIFI_LOGI("Enter InitializeChipCapability");
    if (m_isInitialized) {
        WIFI_LOGI("ChipCapability has been initialized");
        return true;
    }

    m_isInitialized = true;
    WifiErrorNo ret = WIFI_IDL_OPT_FAILED;
    ret = WifiChipHalInterface::GetInstance().IsSupportDbdc(m_isSupportDbdc);
    if (ret != WIFI_IDL_OPT_OK) {
        m_isInitialized = false;
        WIFI_LOGE("Get IsSupportDbdc failed");
    }
    ret = WifiChipHalInterface::GetInstance().IsSupportCsa(m_isSupportCsa);
    if (ret != WIFI_IDL_OPT_OK) {
        m_isInitialized = false;
        WIFI_LOGE("Get IsSupportCsa failed");
    }
    ret = WifiChipHalInterface::GetInstance().IsSupportRadarDetect(m_isSupportRadarDetect);
    if (ret != WIFI_IDL_OPT_OK) {
        m_isInitialized = false;
        WIFI_LOGE("Get IsP2pSupportRadarDetect failed");
    }
    ret = WifiChipHalInterface::GetInstance().IsSupportDfsChannel(m_isSupportDfsChannel);
    if (ret != WIFI_IDL_OPT_OK) {
        m_isInitialized = false;
        WIFI_LOGE("Get IsP2pSupportDfsChannel failed");
    }
    ret = WifiChipHalInterface::GetInstance().IsSupportIndoorChannel(m_isSupportIndoorChannel);
    if (ret != WIFI_IDL_OPT_OK) {
        m_isInitialized = false;
        WIFI_LOGE("Get IsP2pSupportIndoorChannel failed");
    }
    ToString();
    return m_isInitialized;
}

bool ChipCapability::IsSupportDbdc(void)
{
    return m_isSupportDbdc;
}

bool ChipCapability::IsSupportCsa(void)
{
    return m_isSupportCsa;
}

bool ChipCapability::IsSupportRadarDetect(void)
{
    return m_isSupportRadarDetect;
}

bool ChipCapability::IsSupportDfsChannel(void)
{
    return m_isSupportDfsChannel;
}

bool ChipCapability::IsSupportIndoorChannel(void)
{
    return m_isSupportIndoorChannel;
}

std::string ChipCapability::ToString(void)
{
    std::stringstream ss;
    ss << "[WifiChipCap]:" << "\n";
    ss << "Dbdc = " << m_isSupportDbdc << "\n";
    ss << "Csa = " << m_isSupportCsa << "\n";
    ss << "RadarDetect = " << m_isSupportRadarDetect << "\n";
    ss << "DfsChannel = " << m_isSupportDfsChannel << "\n";
    ss << "IndoorChannel = " << m_isSupportIndoorChannel << "\n";
    WIFI_LOGI("%{public}s", ss.str().c_str());
    return ss.str();
}
}  // namespace Wifi
}  // namespace OHOS