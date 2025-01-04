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

int WifiOeminfoMac::GetOeminfoMac(std::string &wifiOemMac)
{
    wifiOemMac = "";
    void* handle = nullptr;
    auto libraryUtilsPtr = std::make_unique<WifiLibraryUtils>(DLOPEN_LIBFACSIGNEDAPI_PATH, handle, true);
    if (!libraryUtilsPtr) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }
    std::string macFromOem;
    int ret = WifiOeminfoMacFromNv(macFromOem, libraryUtilsPtr);
    if (ret != GET_MAC_SUCCESS) {
        WIFI_LOGE("mac read from nv fail");
        ClearOpenSsl(libraryUtilsPtr);
        return ret;
    }
    ClearOpenSsl(libraryUtilsPtr);

    MacDataTolower(macFromOem);
    if (!FormatStrToMac(macFromOem, ":")) {
        WIFI_LOGE("FormatStrToMac fail");
        return GET_MAC_ERROR_MAC_INVALID;
    }
    wifiOemMac = macFromOem;
    WIFI_LOGI("get nv mac success");
    return GET_MAC_SUCCESS;
}

void WifiOeminfoMac::ClearOpenSsl(std::unique_ptr<WifiLibraryUtils> &libraryUtilsPtr)
{
    if (libraryUtilsPtr == nullptr) {
        WIFI_LOGE("handler is NULL, no need clear");
        return;
    }

    CLEAR_OPEN_SSL_FUN dlClearOpenSsl =
        reinterpret_cast<CLEAR_OPEN_SSL_FUN>(libraryUtilsPtr->GetFunction(CLEAR_SSL_FUNC_NAME));
    if (dlClearOpenSsl == nullptr) {
        WIFI_LOGE("failed to dlsym FacStopOpenSSLThread");
        return;
    }

    dlClearOpenSsl();
}

int WifiOeminfoMac::WifiOeminfoMacFromNv(std::string &macFromOem, std::unique_ptr<WifiLibraryUtils> &libraryUtilsPtr)
{
    if (libraryUtilsPtr == nullptr) {
        return GET_MAC_ERROR_LOAD_SO_FAIL;
    }

    READ_OEMINFO_FUN dlReadOemInfo =
        reinterpret_cast<READ_OEMINFO_FUN>(libraryUtilsPtr->GetFunction(OEM_INFO_FUNC_NAME));
    if (dlReadOemInfo == nullptr) {
        WIFI_LOGE("failed to dlsym ReadSignedValueNvmeOeminfo");
        return GET_MAC_ERROR_DLSYM_FAIL;
    }

    char oemMac[OEMINFO_MACADDR_LENGTH] = {0};
    int ret = dlReadOemInfo(PC_NV_PHYNUM_MAC_WIFI_NUMBER, oemMac, OEMINFO_MACADDR_LENGTH - 1);
    if (ret != 0) {
        WIFI_LOGE("read nv mac fail");
        return GET_MAC_ERROR_READ_NV_FAIL;
    }

    macFromOem = oemMac;
    WIFI_LOGI("read nv mac success");
    return GET_MAC_SUCCESS;
}

bool WifiOeminfoMac::CheckCharOfMac(char c)
{
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

bool WifiOeminfoMac::FormatStrToMac(std::string &macFromOem, const std::string &delimiter)
{
    if (macFromOem.size() != OEMINFO_MACADDR_LENGTH - 1) {
        WIFI_LOGE("mac str length is illegal");
        return false;
    }

    for (int i = 0; i < OEMINFO_MACADDR_LENGTH - 1; i++) {
        if (!CheckCharOfMac(macFromOem[i])) {
            WIFI_LOGE("mac char %{public}c is illegal", macFromOem[i]);
            return false;
        }
    }

    int byteOfUnsignedChar = 2;
    for (int i = UNSIGNED_CHAR_MACADDR_LENGTH - 1; i > 0; i--) {
        macFromOem.insert(byteOfUnsignedChar * i, delimiter);
    }

    return true;
}

void WifiOeminfoMac::MacDataTolower(std::string &macFromOem)
{
    for (int i = 0; i < OEMINFO_MACADDR_LENGTH - 1; i++) {
        if (macFromOem[i] >= 'A' && macFromOem[i] <= 'F') {
            macFromOem[i] = std::tolower(macFromOem[i]);
        }
    }
}

} // Wifi
} // OHOS