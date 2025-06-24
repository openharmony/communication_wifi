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

#include "ohos.wifiManager.proj.hpp"
#include "ohos.wifiManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "wifi_errorcode_taihe.h"
#include "wifi_logger.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiIdlErrorCode");
std::map<int32_t, int32_t> WifiIdlErrorCode::errCodeMap_ = {
    { ErrCode::WIFI_OPT_SUCCESS, WifiTaiheErrCode::WIFI_ERRCODE_SUCCESS },
    { ErrCode::WIFI_OPT_FAILED, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_NOT_SUPPORTED, WifiTaiheErrCode::WIFI_ERRCODE_NOT_SUPPORTED },
    { ErrCode::WIFI_OPT_INVALID_PARAM, WifiTaiheErrCode::WIFI_ERRCODE_INVALID_PARAM },
    { ErrCode::WIFI_OPT_FORBID_AIRPLANE, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_FORBID_POWSAVING, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_PERMISSION_DENIED, WifiTaiheErrCode::WIFI_ERRCODE_PERMISSION_DENIED },
    { ErrCode::WIFI_OPT_NON_SYSTEMAPP, WifiTaiheErrCode::WIFI_ERRCODE_NON_SYSTEMAPP },
    { ErrCode::WIFI_OPT_OPEN_FAIL_WHEN_CLOSING, WifiTaiheErrCode::WIFI_ERRCODE_OPEN_FAIL_WHEN_CLOSING },
    { ErrCode::WIFI_OPT_OPEN_SUCC_WHEN_OPENED, WifiTaiheErrCode::WIFI_ERRCODE_CLOSE_FAIL_WHEN_OPENING },
    { ErrCode::WIFI_OPT_CLOSE_FAIL_WHEN_OPENING, WifiTaiheErrCode::WIFI_ERRCODE_CLOSE_FAIL_WHEN_OPENING },
    { ErrCode::WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_STA_NOT_OPENED, WifiTaiheErrCode::WIFI_ERRCODE_WIFI_NOT_OPENED },
    { ErrCode::WIFI_OPT_SCAN_NOT_OPENED, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_AP_NOT_OPENED, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_INVALID_CONFIG, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_P2P_NOT_OPENED, WifiTaiheErrCode::WIFI_ERRCODE_WIFI_NOT_OPENED },
    { ErrCode::WIFI_OPT_P2P_MAC_NOT_FOUND, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_P2P_ERR_MAC_FORMAT, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_P2P_ERR_INTENT, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_P2P_ERR_SIZE_NW_NAME, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
    { ErrCode::WIFI_OPT_MOVING_FREEZE_CTRL, WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED },
};

std::map<int32_t, std::string> WifiIdlErrorCode::errMsgMap_ {
    { WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED, "Operation failed." },
    { WifiTaiheErrCode::WIFI_ERRCODE_WIFI_NOT_OPENED, "Wi-Fi STA disabled." },
    { WifiTaiheErrCode::WIFI_ERRCODE_PERMISSION_DENIED, "Permission denied." },
    { WifiTaiheErrCode::WIFI_ERRCODE_NON_SYSTEMAPP, "non-system application." },
    { WifiTaiheErrCode::WIFI_ERRCODE_INVALID_PARAM, "Parameter error." },
    { WifiTaiheErrCode::WIFI_ERRCODE_NOT_SUPPORTED, "Capability not supported." },
    { WifiTaiheErrCode::WIFI_ERRCODE_OPEN_FAIL_WHEN_CLOSING, "Operation failed because the service is being closed." },
    { WifiTaiheErrCode::WIFI_ERRCODE_CLOSE_FAIL_WHEN_OPENING, "Operation failed because the service is being opened." },
};

int32_t WifiIdlErrorCode::GetErrCode(const int32_t errCodeIn, const int32_t sysCap = 0)
{
    auto iter = errCodeMap_.find(errCodeIn);
    if (iter == errCodeMap_.end()) {
        return WifiTaiheErrCode::WIFI_ERRCODE_OPERATION_FAILED + sysCap;
    }
    if (iter->second == WifiTaiheErrCode::WIFI_ERRCODE_PERMISSION_DENIED ||
        iter->second == WifiTaiheErrCode::WIFI_ERRCODE_INVALID_PARAM ||
        iter->second == WifiTaiheErrCode::WIFI_ERRCODE_NOT_SUPPORTED ||
        iter->second == WifiTaiheErrCode::WIFI_ERRCODE_NON_SYSTEMAPP) {
        return iter->second;
    }
    return iter->second + sysCap;
}

std::string WifiIdlErrorCode::GetErrMsg(const int32_t errCodeIn, int sysCap)
{
    if (errCodeIn == ErrCode::WIFI_OPT_SUCCESS) {
        return "";
    }

    int32_t errCode = GetErrCode(errCodeIn, sysCap);
    auto iter = errMsgMap_.find(errCode);
    if (iter != errMsgMap_.end()) {
        std::string errMessage = "BussinessError ";
        errMessage.append(std::to_string(errCode)).append(": ").append(iter->second);
        return errMessage;
    }
    return "Inner error.";
}

void WifiIdlErrorCode::TaiheSetBusinessError(const char* funcName,
    const int32_t errCodeIn, int sysCap)
{
    int32_t err = GetErrCode(errCodeIn, sysCap);
    std::string errMsg = GetErrMsg(errCodeIn, sysCap);
    WIFI_LOGE("sunjunyu %{public}s error %{public}d, %{public}s", funcName, err, errMsg.c_str());
    taihe::set_business_error(err, errMsg);
}
}  // namespace Wifi
}  // namespace OHOS
