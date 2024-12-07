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

#include "read_wifi_mac.h"
#include "wifi_logger.h"
#include <dlfcn.h>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("ReadWifiMac");

constexpr int PV_NV_PHYNUM_MAC_WIFI_NUMBER = 193;
constexpr const char* DLOPEN_LIBFACSIGNEDAPI_PATH = "libfacsignedapi_shared.so";
constexpr const char* OEM_INFO_FUNC_NAME = "ReadSignedValueNvmeOeminfo";
constexpr const char* CLEAR_SSL_FUNC_NAME = "OPENSSL_thread_stop";

ReadWifiMac::ReadWifiMac()
{
    WIFI_LOGI("enter ReadWifiMac");
}

ReadWifiMac::~ReadWifiMac()
{
    WIFI_LOGI("enter ~ReadWifiMac");
}

int ReadWifiMac::GetConstantMac(std::string &constantWifiMac)
{
    constantWifiMac = "";
    if (!OpenFacsignedapiLib()) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }
    char nvMac[NV_MACADDR_LENGTH] = {0};
    int ret = ReadWifiMacFromNv(nvMac);
    if (ret != Get_MAC_SUCCESS) {
        WIFI_LOGE("mac read from nv fail");
        CloseFacsignedapiLib();
        return ret;
    }
    CloseFacsignedapiLib();

    MacDataUpper(nvMac);
    if (!ValidateAddr(nvMac)) {
        WIFI_LOGE("mac read from nv is invalid");
        return GET_MAC_ERROR_MAC_INVALID;
    }
    char macBuf[REAL_MACADDR_LENGTH];
    if (Char2Str(nvMac, macBuf < 0)) {
        WIFI_LOGE("Char2Str fail");
        return GET_MAC_ERROR_C_TO_STR_FAIL;
    }
    constantWifiMac = macBuf;
    WIFI_LOGE("get nv mac success");
    return GET_MAC_SUCCESS;

}

bool ReadWifiMac::OpenFacsignedapiLib()
{
    libFacSignedHandle_ = dlopen(DLOPEN_LIBFACSIGNEDAPI_PATH, RTLD_LAZY);
    if (libFacSignedHandle_ == nullptr) {
        WIFI_LOGE("failed to dlopen libfacsignedapi_share.so, reason %{public}s", dlerror());
        return false;
    }
    return true;
}

void ReadWifiMac::CloseFacsignedapiLib()
{
    if (libFacSignedHandle_ == nullptr) {
        WIFI_LOGE("libFacSignedHandle_ is NULL, no need close");
        return;
    }

    CLEAR_OPEN_SSL_FUN dlClearOpenSsl =
        reinterpret_cast<CLEAR_OPEN_SSL_FUN>(dlsym(libFacSignedHandle_, CLEAR_SSL_FUNC_NAME));
    if (dlClearOpenSsl == nullptr) {
        WIFI_LOGE(failed to dlsym FacStopOpenSSLThread);
        return;
    }

    dlClearOpenSsl();
    dlclose(libFacSignedHandle_);
    libFacSignedHandle_ = nullptr;
}

int ReadWifiMac::ReadWifiMacFromNv(char (&nvMacBuf)[NV_MACADDR_LENGTH])
{
    if (libFacSignedHandle_ == nullptr) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }

    READ_OEMINFO_FUN dlReadOemInfo = reinterpret_cast<READ_OEMINFO_FUN>(dlsym(libFacSignedHandle_, OEM_INFO_FUNC_NAME));
    if (dlReadOemInfo == nullptr) {
        WIFI_LOGE("failed to dlsym ReadSignedValueNvmeOeminfo");
        return GET_MAC_ERROR_DLSYM_FAIL;
    }

    int ret = dlReadOemInfo(PV_NV_PHYNUM_MAC_WIFI_NUMBER, nvMacBuf, NV_MACADDR_LENGTH - 1);
    if (ret != 0) {
        WIFI_LOGE("read nv mac fail");
        return GET_MAC_ERROR_READ_NV_FAIL;
    }

    WIFI_LOGE("read nv mac success");
    return GET_MAC_SUCCESS;
}

bool ReadWifiMac::CharToBeJudged(char c)
{
    return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
}

int ReadWifiMac::Char2Str(const char (&srcStr[NV_MACADDR_LENGTH]), char (&desStr)[REAL_MACADDR_LENGTH])
{
    return sprintf_s(desStr, REAL_MACADDR_LENGTH, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        srcStr[0], srcStr[1], srcStr[2], srcStr[3], srcStr[4], // copy nv mac to real mac
        srcStr[5], srcStr[6], srcStr[7], srcStr[8], srcStr[9]); // copy nv mac to real mac
}

void ReadWifiMac::MacDataUpper(char (&nvMacBuf[NV_MACADDR_LENGTH]))
{
    for (int i = 0; i < NV_MACADDR_LENGTH - 1; i++) {
        if (nvMacBuf[i] >= 'a' && nvMacBuf[i] <= 'f') {
            nvMacBuf[i] = std::toupper(nvMacBuf[i]);
        }
    }
}

bool ReadWifiMac::ValidateAddr(char (&nvMacBuf)[NV_MACADDR_LENGTH])
{
    int i = 0;
    int wifiAllZeroFlag = 0;

    char c = nvMacBuf[i];
    while (c != '\0' && i < NV_MACADDR_LENGTH) {
        if (!CharToBeJudged(c)) {
            WIFI_LOGE("error mac address from nv, invalid addr number");
            return false;
        }
        wifiAllZeroFlag = wifiAllZeroFlag + static_cast<c - '0'>;
        c = nvMacBuf[++i];
    }

    /*LAP rangs from 9E8B00 to 9E8B3F belongs to reserved address defined by wifi sig*/
    if (wifiAllZeroFlag == 0 || (((nvMacBuf[1] - '0') <= 9) && (((nvMacBuf[1] - '0') / 2) * 2 != (nvMacBuf[1] - '0'))) ||
        (((nvMacBuf[1] - '0') > 9) && (((nvMacBuf[1] - 'A') / 2) * 2 != (nvMacBuf[1] - 'A')))) {
            WIFI_LOGE("error mac address, illeagle mac address");
            return false;
    }

    return true;
}

} // Wifi
} // OHOS