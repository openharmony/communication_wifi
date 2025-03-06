/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CJ_WIFI_CALLBACK_H
#define CJ_WIFI_CALLBACK_H

#include <shared_mutex>

#include "ffi_structs.h"
#include "wifi_errcode.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_p2p.h"
#include "wifi_sa_event.h"

namespace OHOS::Wifi {

class CjWifiAbilityStatusChange : public WifiAbilityStatusChange {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
};

class CjEventRegister {
public:
    CjEventRegister()
    {
        int32_t ret;
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            return;
        }
        mSaStatusListener = new OHOS::Wifi::CjWifiAbilityStatusChange();
        if (mSaStatusListener == nullptr) {
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility((int32_t)WIFI_DEVICE_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_SCAN_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_HOTSPOT_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_P2P_ABILITY_ID, mSaStatusListener);
    }
    ~CjEventRegister() {}

    static CjEventRegister& GetInstance();

    int32_t Register(const std::string& type, void (*callback)());
    int32_t UnRegister(const std::string& type);
    ErrCode RegisterDeviceEvents(const std::vector<std::string>& event);
    ErrCode RegisterScanEvents(const std::vector<std::string>& event);
    ErrCode RegisterHotspotEvents(const std::vector<std::string>& event);
    ErrCode RegisterP2PEvents(const std::vector<std::string>& event);

private:
    OHOS::sptr<OHOS::ISystemAbilityStatusChange> mSaStatusListener = nullptr;
};
} // namespace OHOS::Wifi

#endif