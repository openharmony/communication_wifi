/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_TELEPHONY_UTILS_H
#define WIFI_TELEPHONY_UTILS_H

#include <string>
#include <cstdint>

#ifdef TELEPHONE_CORE_SERVICE_ENABLE
#include "sim_state_type.h"
#include "core_service_client.h"
#include "cellular_data_client.h"
#endif
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
namespace WifiTelephonyUtils {
#ifndef OHOS_ARCH_LITE
    int32_t GetDataSlotId(int32_t slotId);
    std::string GetImsi(int32_t slotId);
    std::string GetPlmn(int32_t slotId);
#endif
    std::string ConvertString(const std::u16string &wideText);
    int32_t GetDefaultId(int32_t slotId);
    int32_t GetSimCardState(int32_t slotId);
    bool IsMultiSimEnabled();
    bool IsSupportCardType(int32_t eapSubId);
    int32_t GetSlotId(int32_t eapSubId);
    enum class AuthType : uint8_t {
        SIM_TYPE,
        AKA_TYPE,
    };
    std::string SimAkaAuth(const std::string &nonce, AuthType authType, int32_t eapSubId);
} // WifiTelephonyUtils
} // Wifi
} // OHOS
#endif