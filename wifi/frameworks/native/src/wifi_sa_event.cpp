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

#include "../../interfaces/kits/c/wifi_device.h"
#include "wifi_scan.h"
#include "wifi_p2p.h"
#include "wifi_device.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_sa_event.h"

DEFINE_WIFILOG_LABEL("WifiAbilityStatusChange");

OHOS::sptr<WifiCDeviceEventCallback> wifiUDeviceCallback =
    OHOS::sptr<WifiCDeviceEventCallback>(new (std::nothrow) WifiCDeviceEventCallback());
OHOS::sptr<WifiCScanEventCallback> wifiUScanCallback =
    OHOS::sptr<WifiCScanEventCallback>(new (std::nothrow) WifiCScanEventCallback());
OHOS::sptr<WifiCHotspotEventCallback> wifiUHotspotCallback =
    OHOS::sptr<WifiCHotspotEventCallback>(new (std::nothrow) WifiCHotspotEventCallback());
OHOS::sptr<WifiP2pCEventCallback> wifiUP2pCallback =
    OHOS::sptr<WifiP2pCEventCallback>(new (std::nothrow) WifiP2pCEventCallback());

namespace OHOS {
namespace Wifi {
void WifiAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("WifiAbilityStatusChange OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    switch (systemAbilityId) {
        case WIFI_DEVICE_ABILITY_ID: {
            std::unique_ptr<WifiDevice> wifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
            if (wifiStaPtr == nullptr) {
                WIFI_LOGE("Register sta event get instance failed!");
                return;
            }
            ErrCode ret = wifiStaPtr->RegisterCallBack(wifiUDeviceCallback);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("Register sta event failed!");
                return;
            }
            break;
        }
        case WIFI_SCAN_ABILITY_ID: {
            std::unique_ptr<WifiScan> wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
            if (wifiScanPtr == nullptr) {
                WIFI_LOGE("Register scan event get instance failed!");
                return;
            }
            ErrCode ret = wifiScanPtr->RegisterCallBack(wifiUScanCallback);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("Register scan event failed!");
                return;
            }
            break;
        }
        case WIFI_HOTSPOT_ABILITY_ID: {
            std::unique_ptr<WifiHotspot> wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
            if (wifiHotspotPtr == nullptr) {
                WIFI_LOGE("Register hotspot event get instance failed!");
                return;
            }
            ErrCode ret = wifiHotspotPtr->RegisterCallBack(wifiUHotspotCallback);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("Register hotspot event failed!");
                return;
            }
            break;
        }
        case WIFI_P2P_ABILITY_ID: {
            std::unique_ptr<WifiP2p> wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
            if (wifiP2pPtr == nullptr) {
                WIFI_LOGE("Register p2p event get instance failed!");
                return;
            }
            ErrCode ret = wifiP2pPtr->RegisterCallBack(wifiUP2pCallback);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("Register p2p event failed!");
                return;
            }
            break;
        }
        default:
            WIFI_LOGI("WifiAbilityStatusChange OnAddSystemAbility unhandled sysabilityId:%{public}d", systemAbilityId);
            return;
    }
}

void WifiAbilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("OnRemoveSystemAbility: systemAbilityId:%{public}d!", systemAbilityId);
    return;
}

void WifiAbilityStatusChange::Init(int32_t systemAbilityId)
{
    WIFI_LOGI("Init: samgrProxy systemAbilityId:%{public}d!", systemAbilityId);
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    int32_t ret = samgrProxy->SubscribeSystemAbility(systemAbilityId, this);
    WIFI_LOGI("SubscribeSystemAbility:systemAbilityId:%{public}d, ret:%{public}d!", systemAbilityId, ret);
    return;
}
}
}

