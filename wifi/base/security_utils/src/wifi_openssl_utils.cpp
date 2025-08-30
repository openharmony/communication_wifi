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

#include "wifi_openssl_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "common.h"
#include "log.h"

#undef LOG_TAG
#define LOG_TAG "WifiOpensslUtils"

namespace OHOS {
namespace Wifi {

#define AES_GCM_128 2
#define AES_GCM_256 3
#define AES_GCM_TAG_LEN 4

WifiOpensslUtils &WifiOpensslUtils::GetInstance()
{
    static WifiOpensslUtils gWifiOpensslUtils;
    return gWifiOpensslUtils;
}

WifiOpensslUtils::WifiOpensslUtils()
{
    LOGI("%{public}s create success", __func__);
}

WifiOpensslUtils::~WifiOpensslUtils()
{
    LOGI("%{public}s destory success", __func__);
}

EVP_CIPHER *GetAesCipher(int aesType)
{
    EVP_CIPHER *cipher = nullptr;
    LOGD("%{public}s aesType %{public}d !", __func__, aesType);
    switch (aesType) {
        case AES_GCM_128 :
            cipher = const_cast<EVP_CIPHER *>(EVP_aes_128_gcm());
            break;
        case AES_GCM_256 :
            cipher = const_cast<EVP_CIPHER *>(EVP_aes_256_gcm());
            break;
        default:
            cipher = const_cast<EVP_CIPHER *>(EVP_aes_128_gcm());
    }
    return cipher;
}

int WifiOpensslUtils::OpensslAesEncrypt(const uint8_t *plainText, int plainTextLen,
    struct AesCipherInfo *info, uint8_t *cipherText, int *cipherTextLen)
{
    LOGI("enter %{public}s", __func__);
    int res = -1;
    if (plainText == nullptr || plainTextLen == 0 || info == nullptr ||
        cipherText == nullptr || cipherTextLen == nullptr) {
        LOGE("%{public}s param is illegal", __func__);
        return res;
    }

    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    const EVP_CIPHER *cipher = GetAesCipher(info->aesType);
    uint8_t tag[AES_GCM_TAG_LEN];

    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        goto err;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, nullptr) != 1) {
        goto err;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, info->key, info->iv) != 1) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen) != 1) {
        goto err;
    }
    *cipherTextLen = len;

    if (EVP_EncryptFinal_ex(ctx, cipherText + len, &len) != 1) {
        goto err;
    }
    *cipherTextLen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, static_cast<void *>(tag)) != 1) {
        goto err;
    }

    if (memcpy_s(cipherText + *cipherTextLen, AES_GCM_TAG_LEN, tag, AES_GCM_TAG_LEN) != 0) {
        LOGE("%{public}s: Aes Encrypt memcpy_s failed !", __func__);
        goto err;
    }
    *cipherTextLen += AES_GCM_TAG_LEN;
    res = 0;
err:
    OPENSSL_cleanse(tag, AES_GCM_TAG_LEN);
    if (ctx != nullptr) {
        LOGE("%{public}s: Aes Encrypt encrypt res %{public}d !", __func__, res);
        EVP_CIPHER_CTX_free(ctx);
    }
    return res;
}

int WifiOpensslUtils::OpensslAesDecrypt(const uint8_t *cipherText, int cipherTextLen,
    struct AesCipherInfo *info, uint8_t *plainText, int *plainTextLen)
{
    LOGI("enter %{public}s", __func__);
    int res = -1;
    if (cipherText == nullptr || cipherTextLen == 0 || info == nullptr ||
        plainText == nullptr || plainTextLen == nullptr ||
        cipherTextLen <= AES_GCM_TAG_LEN) {
        LOGE("%{public}s param is illegal", __func__);
        return res;
    }

    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    const EVP_CIPHER *cipher = GetAesCipher(info->aesType);

    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        LOGI("%{public}s: Aes decrypt new ctx fail!", __func__);
        goto err;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        LOGI("%{public}s: Aes decrypt init fail!", __func__);
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, nullptr) != 1) {
        LOGI("%{public}s: Aes decrypt set iv len fail!", __func__);
        goto err;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, info->key, info->iv) != 1) {
        LOGI("%{public}s: Aes decrypt set key & iv fail!", __func__);
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
        static_cast<void *>(const_cast<uint8_t *>(cipherText + (cipherTextLen - AES_GCM_TAG_LEN)))) != 1) {
        LOGI("%{public}s: Aes decrypt tag fail!", __func__);
        goto err;
    }

    if (EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen - AES_GCM_TAG_LEN) != 1) {
        LOGI("%{public}s: Aes decrypt start decrypt fail!", __func__);
        goto err;
    }
    *plainTextLen = len;

    if (EVP_DecryptFinal_ex(ctx, plainText + len, &len) != 1) {
        LOGI("%{public}s: Aes decrypt final fail!", __func__);
        goto err;
    }
    *plainTextLen += len;

    res = 0;
err:
    if (ctx != nullptr) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return res;
}

}
}
