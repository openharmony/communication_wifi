/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include "wifi_logger.h"
#include "wifi_pro_interface.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiPrWifiProInterfaceoService");

WifiProInterface::WifiProInterface(int32_t instId) : instId_(instId)
{
    WIFI_LOGI("Enter WifiProInterface");
}

WifiProInterface::~WifiProInterface()
{
    WIFI_LOGI("Enter ~WifiProInterface");
}

ErrCode WifiProInterface::InitWifiProService()
{
    WIFI_LOGI("Enter WifiProInterface::InitWifiProService");
    return WIFI_OPT_SUCCESS;
}

void WifiProInterface::InitCallback()
{
    using namespace std::placeholders;
    staCallback_.callbackModuleName = "WifiProService";
    staCallback_.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &linkedInfo, int32_t instId) {
        this->DealStaConnChanged(state, linkedInfo, instId);
    };
    staCallback_.OnStaRssiLevelChanged = [this](int32_t rssi, int32_t instId) {
        this->DealRssiLevelChanged(rssi, instId);
    };
}

void WifiProInterface::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int32_t instId)
{
    WIFI_LOGI("Enter WifiProInterface::DealStaConnChanged");
}

void WifiProInterface::DealRssiLevelChanged(int32_t rssi, int32_t instId)
{
    WIFI_LOGI("Enter WifiProInterface::DealRssiLevelChanged");
}

void WifiProInterface::DealScanResult(const std::vector<InterScanInfo> &results)
{
    WIFI_LOGI("Enter WifiProInterface::DealScanResult");
}

void WifiProInterface::DealQoeReport(const NetworkLagType &networkLagType, const NetworkLagInfo &networkLagInfo)
{
    WIFI_LOGI("Enter WifiProInterface::DealQoeReport");
}

StaServiceCallback WifiProInterface::GetStaCallback() const
{
    return staCallback_;
}

}  // namespace Wifi
}  // namespace OHOS
