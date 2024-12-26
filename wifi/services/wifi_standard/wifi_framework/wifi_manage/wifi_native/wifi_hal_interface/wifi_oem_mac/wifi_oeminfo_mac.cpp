/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_oeminfo_mac.h"
#include <dlfcn.h>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiOeminfoMac");

static constexpr int PC_NV_PHYNUM_MAC_WIFI_NUMBER = 193;
static constexpr const char* DLOPEN_LIBFACSIGNEDAPI_PATH = "libfacsignedapi_shared.so";
static constexpr const char* OEM_INFO_FUNC_NAME = "ReadSignedValueNvmeOeminfo";
static constexpr const char* CLEAR_SSL_FUNC_NAME = "OPENSSL_thread_stop";

WifiOeminfoMac::WifiOeminfoMac()
{
    WIFI_LOGI("enter WifiOeminfoMac");
}

WifiOeminfoMac::~WifiOeminfoMac()
{
    WIFI_LOGI("enter ~WifiOeminfoMac");
}

int WifiOeminfoMac::GetOeminfoMac(std::string &constantWifiMac)
{
    constantWifiMac = "";
    void* handler = nullptr;
    if (!OpenFacsignedapiLib(&handler)) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }
    char nvMac[NV_MACADDR_LENGTH] = {0};
    int ret = WifiOeminfoMacFromNv(nvMac, handler);
    if (ret != GET_MAC_SUCCESS) {
        WIFI_LOGE("mac read from nv fail");
        CloseFacsignedapiLib(&handler);
        return ret;
    }
    CloseFacsignedapiLib(&handler);

    MacDataTolower(nvMac);
    if (!ValidateAddr(nvMac)) {
        WIFI_LOGE("mac read from nv is invalid");
        return GET_MAC_ERROR_MAC_INVALID;
    }
    char macBuf[REAL_MACADDR_LENGTH];
    if (Char2Str(nvMac, macBuf) < 0) {
        WIFI_LOGE("Char2Str fail");
        return GET_MAC_ERROR_C_TO_STR_FAIL;
    }
    constantWifiMac = macBuf;
    WIFI_LOGI("get nv mac success");
    return GET_MAC_SUCCESS;
}

bool WifiOeminfoMac::OpenFacsignedapiLib(void **handler)
{
    *handler = dlopen(DLOPEN_LIBFACSIGNEDAPI_PATH, RTLD_LAZY);
    if (*handler == nullptr) {
        WIFI_LOGE("failed to dlopen libfacsignedapi_share.so, reason %{public}s", dlerror());
        return false;
    }
    return true;
}

void WifiOeminfoMac::CloseFacsignedapiLib(void **handler)
{
    if (*handler == nullptr) {
        WIFI_LOGE("handler is NULL, no need close");
        return;
    }

    CLEAR_OPEN_SSL_FUN dlClearOpenSsl =
        reinterpret_cast<CLEAR_OPEN_SSL_FUN>(dlsym(*handler, CLEAR_SSL_FUNC_NAME));
    if (dlClearOpenSsl == nullptr) {
        WIFI_LOGE("failed to dlsym FacStopOpenSSLThread");
        return;
    }

    dlClearOpenSsl();
    dlclose(*handler);
    *handler = nullptr;
}

int WifiOeminfoMac::WifiOeminfoMacFromNv(char (&nvMacBuf)[NV_MACADDR_LENGTH], void *handler)
{
    if (handler == nullptr) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }

    READ_OEMINFO_FUN dlReadOemInfo = reinterpret_cast<READ_OEMINFO_FUN>(dlsym(handler, OEM_INFO_FUNC_NAME));
    if (dlReadOemInfo == nullptr) {
        WIFI_LOGE("failed to dlsym ReadSignedValueNvmeOeminfo");
        return GET_MAC_ERROR_DLSYM_FAIL;
    }

    int ret = dlReadOemInfo(PC_NV_PHYNUM_MAC_WIFI_NUMBER, nvMacBuf, NV_MACADDR_LENGTH - 1);
    if (ret != 0) {
        WIFI_LOGE("read nv mac fail");
        return GET_MAC_ERROR_READ_NV_FAIL;
    }

    WIFI_LOGI("read nv mac success");
    return GET_MAC_SUCCESS;
}

bool WifiOeminfoMac::CharToBeJudged(char c)
{
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

int WifiOeminfoMac::Char2Str(const char (&srcStr)[NV_MACADDR_LENGTH], char (&destStr)[REAL_MACADDR_LENGTH])
{
    return sprintf_s(destStr, REAL_MACADDR_LENGTH, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        srcStr[0], srcStr[1], srcStr[2], srcStr[3], srcStr[4], srcStr[5], // copy nv mac to real mac
        srcStr[6], srcStr[7], srcStr[8], srcStr[9], srcStr[10], srcStr[11]); // copy nv mac to real mac
}

void WifiOeminfoMac::MacDataTolower(char (&nvMacBuf)[NV_MACADDR_LENGTH])
{
    for (int i = 0; i < NV_MACADDR_LENGTH - 1; i++) {
        if (nvMacBuf[i] >= 'A' && nvMacBuf[i] <= 'F') {
            nvMacBuf[i] = std::tolower(nvMacBuf[i]);
        }
    }
}

bool WifiOeminfoMac::ValidateAddr(char (&nvMacBuf)[NV_MACADDR_LENGTH])
{
    int i = 0;

    char c = nvMacBuf[i];
    while (c != '\0' && i < NV_MACADDR_LENGTH) {
        if (!CharToBeJudged(c)) {
            WIFI_LOGE("error mac address from nv, invalid addr number");
            return false;
        }
        c = nvMacBuf[++i];
    }
    return true;
}

} // Wifi
} // OHOS