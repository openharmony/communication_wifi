/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "wifi_msdp_state_listener.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "define.h"
#include "wifi_service_manager.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiMsdpStateListener");

void DeviceMovementCallback::OnMovementChanged(const Msdp::MovementDataUtils::MovementData &movementData)
{
    WIFI_LOGI("enter DeviceMovementCallback::OnMovementChanged type=%{public}d, value=%{public}d",
        movementData.type, movementData.value);
    if (movementData.type == Msdp::MovementDataUtils::MovementType::TYPE_STILL) {
        if (movementData.value == Msdp::MovementDataUtils::MovementValue::VALUE_ENTER) {
            WifiSettings::GetInstance().SetFreezeModeState(MODE_STATE_OPEN);
        } else {
            WifiSettings::GetInstance().SetFreezeModeState(MODE_STATE_CLOSE);
        }
    }
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService == nullptr) {
            WIFI_LOGE("scan service is NOT start!");
            return;
        }
        if (pScanService->OnMovingFreezeStateChange() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("OnMovingFreezeStateChange failed");
        }
    }
}
} // namespace Wifi
} // namespace OHOS
