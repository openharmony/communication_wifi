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

#include "wifi_msdp_state_listener.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "define.h"
#include "wifi_service_manager.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiMsdpStateListener");

DeviceMovementCallback::DeviceMovementCallback()
{
    movementChangeEventHandler = std::make_unique<WifiEventHandler>("WIFI_MOVEMENT_STATE_AWARE_THREAD");
}

DeviceMovementCallback::~DeviceMovementCallback()
{
    if (movementChangeEventHandler) {
        movementChangeEventHandler.reset();
    }
}

void DeviceMovementCallback::OnMovementChanged(const Msdp::MovementDataUtils::MovementData &movementData)
{
    WIFI_LOGI("enter DeviceMovementCallback::OnMovementChanged type=%{public}d, value=%{public}d",
        movementData.type, movementData.value);
    if (movementData.type == Msdp::MovementDataUtils::MovementType::TYPE_STILL) {
        if (movementData.value == Msdp::MovementDataUtils::MovementValue::VALUE_ENTER) {
            WifiConfigCenter::GetInstance().SetFreezeModeState(MODE_STATE_OPEN);
        } else {
            WifiConfigCenter::GetInstance().SetFreezeModeState(MODE_STATE_CLOSE);
        }
    }
    if (movementData.type == Msdp::MovementDataUtils::MovementType::TYPE_STAY) {
        HandleMovementChange();
    }
}

void DeviceMovementCallback::HandleMovementChange()
{
    WIFI_LOGI("HandleMovementChange enter");
    if (!movementChangeEventHandler) {
        WIFI_LOGE("%{public}s movementChangeEventHandler is null", __func__);
        return;
    }
    movementChangeEventHandler->PostAsyncTask([this]() {
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
    });
}
} // namespace Wifi
} // namespace OHOS
