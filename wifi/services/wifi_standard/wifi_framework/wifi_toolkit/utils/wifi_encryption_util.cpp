/*
 * Copyright (C) 2022-2022 Huawei Device Co., Ltd.
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
#include "wifi_encryption_util.h"
#include <iterator>
#include <sstream>
#include "wifi_logger.h"
#include "wifi_global_func.h"
DEFINE_WIFILOG_LABEL("WifiConfigEncryption");
namespace OHOS {
namespace Wifi {
int32_t SetUpHks()
{
    int32_t ret = HksInitialize();
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("wifi encryption init failed");
    }
    return ret;
}

int32_t GetKey(const WifiEncryptionInfo &wifiEncryptionInfo, const struct HksParamSet *genParamSet)
{
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    int32_t keyExist = HksKeyExist(&authId, nullptr);
    if (keyExist == HKS_ERROR_NOT_EXIST) {
        int32_t ret = HksGenerateKey(&authId, genParamSet, nullptr);
        if (ret != HKS_SUCCESS) {
            WIFI_LOGE("generate key failed");
            return ret;
        } else {
            return ret;
        }
    }else if (keyExist != HKS_SUCCESS) {
        WIFI_LOGE("search key failed");
        return keyExist;
    }
    return keyExist;
}

int32_t WifiEncryption(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &inputString,
    EncryptedData &encryptedData)
{
    if (inputString.length() == 0) {
        return HKS_SUCCESS;
    }
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    struct HksBlob plainText = { inputString.length(), (uint8_t *)&inputString[0] };

    uint8_t nonce[NONCE_SIZE] = {0};
    struct HksBlob randomIV = {NONCE_SIZE, nonce};
    int32_t ret =HksGenerateRandom(NULL, &randomIV);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("wifi encryption generate IV failed");
        return ret;
    }
    struct HksParam IVParam[] = {
        { .tag = HKS_TAG_NONCE, .blob = { .size = NONCE_SIZE, .data = nonce } },
    };

    struct HksParamSet *encryParamSet = nullptr;
    HksInitParamSet(&encryParamSet);
    HksAddParams(encryParamSet, g_genParam, sizeof(g_genParam) / sizeof(HksParam));
    HksAddParams(encryParamSet, IVParam, sizeof(IVParam) / sizeof(HksParam));
    HksBuildParamSet(&encryParamSet);

    ret = GetKey(wifiEncryptionInfo, encryParamSet);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("wifi encryption failed");
        return ret;
    }

    uint8_t cipherBuf[AES_COMMON_SIZE] = {0};
    HksBlob cipherData = {
        .size = AES_COMMON_SIZE,
        .data = cipherBuf
    };

    ret = HksEncrypt(&authId, encryParamSet, &plainText, &cipherData);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("Hks encryption failed");
        return ret;
    }

    encryptedData.encryptedPassword = ConvertArrayToHex(cipherBuf, cipherData.size);
    encryptedData.IV = ConvertArrayToHex(nonce, NONCE_SIZE);
    HksFreeParamSet(&encryParamSet);
    return ret;
}

int32_t WifiDecryption(const WifiEncryptionInfo &wifiEncryptionInfo, const EncryptedData &encryptedData,
    std::string &decryptedData)
{
    if (encryptedData.encryptedPassword.size() == 0) {
        return HKS_SUCCESS;
    }
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    uint8_t cipherBuf[AES_COMMON_SIZE] = {0};
    int length = AES_COMMON_SIZE;
    int retStrToArrat = HexStringToVec(encryptedData.encryptedPassword, cipherBuf, AES_COMMON_SIZE, length);
    if (retStrToArrat != 0) {
        return HKS_FAILURE;
    }

    uint8_t nonce[NONCE_SIZE] = {0};
    int lengthIV = NONCE_SIZE;
    retStrToArrat = HexStringToVec(encryptedData.IV, nonce, NONCE_SIZE, lengthIV);
        if (retStrToArrat != 0) {
        return HKS_FAILURE;
    }
    struct HksParam IVParam[] = {
        { .tag = HKS_TAG_NONCE, .blob = { .size = NONCE_SIZE, .data = nonce } },
    };

    struct HksBlob cipherData = { length, cipherBuf };
    struct HksParamSet *decryParamSet = nullptr;

    HksInitParamSet(&decryParamSet);
    HksAddParams(decryParamSet, g_genParam, sizeof(g_genParam) / sizeof(HksParam));
    HksAddParams(decryParamSet, IVParam, sizeof(IVParam) / sizeof(HksParam));
    HksBuildParamSet(&decryParamSet);

    int ret = HksKeyExist(&authId, nullptr);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("wifi decryption key not exist");
        return ret;
    }
    uint8_t plainBuff[AES_COMMON_SIZE] = {0};
    HksBlob plainText = {
        .size = AES_COMMON_SIZE,
        .data = plainBuff
    };

    ret = HksDecrypt(&authId, decryParamSet, &cipherData, &plainText);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("Hks decryption failed");
        return ret;
    }

    std::string temp(plainText.data, plainText.data + plainText.size);
    decryptedData = temp;
    HksFreeParamSet(&decryParamSet);
    return ret;
}
} // namespace Wifi
} // namespace OHOS