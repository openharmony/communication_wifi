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

#include <locale>
#include <codecvt>
#include "wifi_telephony_utils.h"
#include "wifi_logger.h"
DEFINE_WIFILOG_LABEL("WifiTelephonyUtils");

namespace OHOS {
namespace Wifi {
namespace WifiTelephonyUtils {

#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    using namespace OHOS::Telephony;
#endif

std::string ConvertString(const std::u16string &wideText)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}.to_bytes(wideText);
}

std::string SimAkaAuth(const std::string &nonce, AuthType authType, int32_t eapSubId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    SimAuthenticationResponse response;
    Telephony::AuthType type;
    switch (authType) {
        case AuthType::SIM_TYPE:
            type = Telephony::AuthType::SIM_AUTH_EAP_SIM_TYPE;
            break;
        case AuthType::AKA_TYPE:
            type = Telephony::AuthType::SIM_AUTH_EAP_AKA_TYPE;
            [[fallthrough]];
        default:
            break;
    }
    WIFI_LOGD("StaStateMachine::SimAkaAuth in, authType:%{public}d, nonce:%{private}s", type, nonce.c_str());
    auto slotId = CoreServiceClient::GetInstance().GetSlotId(eapSubId);
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(slotId, type, nonce, response);
    if (result != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StaStateMachine::SimAkaAuth: errCode=%{public}d", result);
        return "";
    }
    return response.response;
#else
    WIFI_LOGW("telephony subsystem is disabled, sim auth is not supported");
    return "";
#endif
}

#ifndef OHOS_ARCH_LITE
int32_t GetDataSlotId(int32_t slotId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    int32_t simCount = CoreServiceClient::GetInstance().GetMaxSimCount();
    if (slotId >= 0 && slotId < simCount) {
        WIFI_LOGI("slotId: %{public}d, simCount:%{public}d", slotId, simCount);
        return slotId;
    }
    auto slotDefaultID = CellularDataClient::GetInstance().GetDefaultCellularDataSlotId();
    if ((slotDefaultID < 0) || (slotDefaultID >= simCount)) {
        WIFI_LOGE("failed to get default slotId, slotId:%{public}d, simCount:%{public}d", slotDefaultID, simCount);
        return -1;
    }
    WIFI_LOGI("slotDefaultID: %{public}d, simCount:%{public}d", slotDefaultID, simCount);
    return slotDefaultID;
#else
    WIFI_LOGW("telephony subsystem is disabled, query slotId is not supported");
    return -1;
#endif
}

std::string GetImsi(int32_t slotId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    std::u16string imsi;
    int32_t errCode = CoreServiceClient::GetInstance().GetIMSI(slotId, imsi);
    if (errCode != 0) {
        WIFI_LOGE("failed to get imsi, errCode: %{public}d", errCode);
        return "";
    }
    return ConvertString(imsi);
#else
    WIFI_LOGW("telephony subsystem is disabled, query imsi is not supported");
    return "";
#endif
}

std::string GetPlmn(int32_t slotId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    std::u16string plmn;
    int32_t errCode = CoreServiceClient::GetInstance().GetSimOperatorNumeric(slotId, plmn);
    if (errCode != 0) {
        WIFI_LOGE("failed to get plmn, errCode: %{public}d", errCode);
        return "";
    }
    return ConvertString(plmn);
#else
    WIFI_LOGW("telephony subsystem is disabled, query plmn is not supported");
    return "";
#endif
}
#endif

int32_t GetDefaultId(int32_t slotId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    WIFI_LOGI("StaStateMachine::GetDefaultId in, slotId: %{public}d", slotId);
    constexpr int32_t WIFI_INVALID_SIM_ID = 0;
    if (slotId == WIFI_INVALID_SIM_ID) {
        return GetDataSlotId(slotId);
    }
    return slotId;
#else
    WIFI_LOGW("telephony subsystem is disabled, query defaultId is not supported");
    return -1;
#endif
}

int32_t GetSimCardState(int32_t slotId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    WIFI_LOGI("StaStateMachine::GetSimCardState in, slotId: %{public}d", slotId);
    slotId = GetDefaultId(slotId);
    WIFI_LOGI("slotId: %{public}d", slotId);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    int32_t result = CoreServiceClient::GetInstance().GetSimState(slotId, simState);
    if (result != Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StaStateMachine::GetSimCardState result:%{public}d, simState:%{public}d", result, simState);
        return static_cast<int32_t>(simState);
    }
    WIFI_LOGI("StaStateMachine::GetSimCardState out, simState:%{public}d", simState);
    return static_cast<int32_t>(simState);
#else
    WIFI_LOGW("telephony subsystem is disabled, query sim card state is not supported");
    return -1;
#endif
}

bool IsMultiSimEnabled()
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    int32_t simCount = CoreServiceClient::GetInstance().GetMaxSimCount();
    WIFI_LOGI("StaStateMachine::IsMultiSimEnabled simCount:%{public}d", simCount);
    if (simCount > 1) {
        return true;
    }
#endif
    return false;
}

int32_t GetSlotId(int32_t eapSubId)
{
    int32_t slotId;
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    slotId = CoreServiceClient::GetInstance().GetSlotId(eapSubId);
#else
    slotId = -1;
#endif
    return slotId;
}

bool IsSupportCardType(int32_t eapSubId)
{
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    CardType cardType;
    int32_t ret =  CoreServiceClient::GetInstance().GetCardType(
        CoreServiceClient::GetInstance().GetSlotId(eapSubId), cardType);
    if (ret != 0) {
        WIFI_LOGE("failed to get cardType: %{public}d", ret);
        return false;
    }
    if (cardType == CardType::SINGLE_MODE_SIM_CARD) {
        WIFI_LOGE("invalid cardType: %{public}d", cardType);
        return false;
    }
    return true;
#else
    WIFI_LOGW("telephony subsystem is disabled, sim card is not supported");
    return false;
#endif
}
} // WifiTelephonyUtils
} // Wifi
} // OHOS