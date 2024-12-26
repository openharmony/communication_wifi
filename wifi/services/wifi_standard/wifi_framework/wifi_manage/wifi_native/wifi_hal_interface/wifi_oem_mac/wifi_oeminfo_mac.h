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

#ifndef WIFI_OEMINFO_MAC_H
#define WIFI_OEMINFO_MAC_H

#include <string>
#include <dlfcn.h>
#include "securec.h"

namespace OHOS {
namespace Wifi {
constexpr int REAL_MACADDR_LENGTH = 18; // length of mac string, eg "11:22:33:44:55:66"
constexpr int NV_MACADDR_LENGTH = 13; // length of mac string  without ':'
class WifiOeminfoMac {
public:
    enum ErrType {
        GET_MAC_SUCCESS,
        GET_MAC_ERROR_LOAD_SO_FAIL,
        GET_MAC_ERROR_DLSYM_FAIL,
        GET_MAC_ERROR_READ_NV_FAIL,
        GET_MAC_ERROR_MAC_INVALID,
        GET_MAC_ERROR_C_TO_STR_FAIL,
    };
    WifiOeminfoMac();
    ~WifiOeminfoMac();
    int GetOeminfoMac(std::string &constantWifiMac);

private:
    bool OpenFacsignedapiLib(void **handler);
    void CloseFacsignedapiLib(void **handler);
    int WifiOeminfoMacFromNv(char (&nvMacBuf)[NV_MACADDR_LENGTH], void *handler);
    bool ValidateAddr(char (&nvMacBuf)[NV_MACADDR_LENGTH]);
    bool CharToBeJudged(char c);
    void MacDataTolower(char (&nvMacBuf)[NV_MACADDR_LENGTH]);
    int Char2Str(const char (&srcStr)[NV_MACADDR_LENGTH], char (&destStr)[REAL_MACADDR_LENGTH]);

private:
    using READ_OEMINFO_FUN = int (*) (int, char*, int);
    using CLEAR_OPEN_SSL_FUN = void (*) (void);
};

}
}
#endif // READ_OEM_MAC_H