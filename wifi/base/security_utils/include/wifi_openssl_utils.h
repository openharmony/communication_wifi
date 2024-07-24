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

#ifndef WIFI_OPENSSL_AES_H
#define WIFI_OPENSSL_AES_H

#include <cstdint>

namespace OHOS {
namespace Wifi {

#define MAX_KEY_LEN 32
#define AES_IV_LEN 12

typedef struct AesCipherInfo {
    int aesType;
    uint8_t iv[AES_IV_LEN];
    uint8_t key[MAX_KEY_LEN];
} AesCipherInfo;

class WifiOpensslUtils {
public:
    WifiOpensslUtils();
    ~WifiOpensslUtils();
    static WifiOpensslUtils& GetInstance();

public:
    int OpensslAesEncrypt(const uint8_t *plainText, int plainTextLen, struct AesCipherInfo *info,
        uint8_t *cipherText, int *cipherTextLen);
    
    int OpensslAesDecrypt(const uint8_t *cipherText, int cipherTextLen, struct AesCipherInfo *info,
        uint8_t *plainText, int *plainTextLen);
};

}
}

#endif // WIFI_OPENSSL_AES_H
