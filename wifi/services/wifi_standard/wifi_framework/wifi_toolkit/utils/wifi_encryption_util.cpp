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

#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#include <iterator>
#include <sstream>
#include "wifi_logger.h"
#include "wifi_global_func.h"
DEFINE_WIFILOG_LABEL("WifiConfigEncryption");
namespace OHOS {
namespace Wifi {

struct HksParam g_genParam[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = AAD_SIZE, .data = (uint8_t *)AAD } },
};

struct HksParam g_genAes256Param[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
    { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

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
    int32_t keyExist = HksKeyExist(&authId, genParamSet);
    if (keyExist == HKS_ERROR_NOT_EXIST) {
        int32_t ret = HksGenerateKey(&authId, genParamSet, nullptr);
        if (ret != HKS_SUCCESS) {
            WIFI_LOGE("generate key failed");
            return ret;
        } else {
            return ret;
        }
    } else if (keyExist != HKS_SUCCESS) {
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
    int32_t ret = HksGenerateRandom(NULL, &randomIV);
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
    uint32_t length = AES_COMMON_SIZE;
    int32_t retStrToArrat = HexStringToVec(encryptedData.encryptedPassword, cipherBuf, AES_COMMON_SIZE, length);
    if (retStrToArrat != 0) {
        return HKS_FAILURE;
    }

    uint8_t nonce[NONCE_SIZE] = {0};
    uint32_t lengthIV = NONCE_SIZE;
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

    int32_t ret = HksKeyExist(&authId, decryParamSet);
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

int32_t UpdateAndFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    uint32_t inDataSize = inData->size;
    uint32_t handledInDataSize = 0;
    uint32_t handledOutDataSize = 0;
    uint8_t *handledOutData = outData->data;
    struct HksBlob inDataSeg = *inData;
    struct HksBlob outDataSeg = { MAX_UPDATE_SIZE, nullptr };

    while (handledInDataSize < inDataSize) {
        uint32_t aesDataLen = std::min(MAX_UPDATE_SIZE, (inDataSize - handledInDataSize));
        inDataSeg.size = aesDataLen;
        outDataSeg.size = MAX_UPDATE_SIZE + AEAD_SIZE;
        outDataSeg.data = (uint8_t *)malloc(outDataSeg.size);
        if (outDataSeg.data == nullptr) {
            WIFI_LOGE("UpdateAndFinish malloc failed.");
            return HKS_FAILURE;
        }

        int32_t hksResult = 0;
        if (handledInDataSize + aesDataLen < inDataSize) {
            hksResult = HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg);
        } else {
            hksResult = HksFinish(handle, paramSet, &inDataSeg, &outDataSeg);
        }
        if (hksResult != HKS_SUCCESS) {
            WIFI_LOGE("UpdateAndFinish do HksUpdate or HksFinish failed: %{public}d.", hksResult);
            free(outDataSeg.data);
            return HKS_FAILURE;
        }

        if (handledOutDataSize + outDataSeg.size > outData->size) {
            WIFI_LOGE("UpdateAndFinish outData->size is too small.");
            free(outDataSeg.data);
            return HKS_FAILURE;
        }
        if (memcpy_s(handledOutData, outDataSeg.size, outDataSeg.data, outDataSeg.size) != EOK) {
            WIFI_LOGE("UpdateAndFinish memcpy_s failed.");
            free(outDataSeg.data);
            return HKS_FAILURE;
        }

        handledOutData += outDataSeg.size;
        handledOutDataSize += outDataSeg.size;
        inDataSeg.data += aesDataLen;
        handledInDataSize += aesDataLen;
        free(outDataSeg.data);
        outDataSeg.data = nullptr;
    }
    outData->size = handledOutDataSize;
    return HKS_SUCCESS;
}

int32_t ImportKey(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &key)
{
    WIFI_LOGI("ImportKey enter.");
    uint8_t aesKey[AES_COMMON_SIZE] = { 0 };
    uint32_t length = 0;
    if (HexStringToVec(key, aesKey, AES_COMMON_SIZE, length) != 0) {
        WIFI_LOGE("ImportKey HexStringToVec failed.");
        return HKS_FAILURE;
    }

    struct HksBlob hksKey = { length, aesKey };
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    struct HksParam purposeParam[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *encryParamSet = nullptr;
    HksInitParamSet(&encryParamSet);
    HksAddParams(encryParamSet, g_genAes256Param, sizeof(g_genAes256Param) / sizeof(HksParam));
    HksAddParams(encryParamSet, purposeParam, sizeof(purposeParam) / sizeof(HksParam));
    HksBuildParamSet(&encryParamSet);

    int32_t keyExist = HksKeyExist(&authId, encryParamSet);
    if (keyExist == HKS_ERROR_NOT_EXIST) {
        int32_t ret = HksImportKey(&authId, encryParamSet, &hksKey);
        if (memset_s(aesKey, sizeof(aesKey), 0, sizeof(aesKey)) != EOK) {
            WIFI_LOGE("ImportKey memset_s return error!");
            return HKS_FAILURE;
        }
        if (ret != HKS_SUCCESS) {
            WIFI_LOGE("ImportKey failed: %{public}d.", ret);
        }
        return ret;
    } else if (keyExist == HKS_SUCCESS) {
        WIFI_LOGI("ImportKey key is exist, donot need import key.");
        return HKS_SUCCESS;
    }
    WIFI_LOGE("ImportKey HksKeyExist check failed: %{public}d.", keyExist);
    return keyExist;
}

int32_t DeleteKey(const WifiEncryptionInfo &wifiEncryptionInfo)
{
    WIFI_LOGI("DeleteKey enter.");
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    struct HksParam purposeParam[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *encryParamSet = nullptr;
    HksInitParamSet(&encryParamSet);
    HksAddParams(encryParamSet, g_genAes256Param, sizeof(g_genAes256Param) / sizeof(HksParam));
    HksAddParams(encryParamSet, purposeParam, sizeof(purposeParam) / sizeof(HksParam));
    HksBuildParamSet(&encryParamSet);

    int32_t keyExist = HksKeyExist(&authId, encryParamSet);
    if (keyExist == HKS_SUCCESS) {
        int32_t ret = HksDeleteKey(&authId, encryParamSet);
        if (ret != HKS_SUCCESS) {
            WIFI_LOGE("DeleteKey failed: %{public}d.", ret);
        }
        return ret;
    } else if (keyExist == HKS_ERROR_NOT_EXIST) {
        WIFI_LOGI("DeleteKey key is not exist, donot need delete key.");
        return HKS_SUCCESS;
    }
    WIFI_LOGE("DeleteKey HksKeyExist check failed: %{public}d.", keyExist);
    return keyExist;
}

int32_t EncryptParamSet(struct HksParamSet **encryParamSet, const WifiEncryptionInfo &wifiEncryptionInfo,
    const EncryptedData &encryptedData)
{
    uint8_t nonce[AES_256_NONCE_SIZE] = { 0 };
    uint32_t nonceLength = 0;
    if (HexStringToVec(encryptedData.IV, nonce, AES_256_NONCE_SIZE, nonceLength) != 0) {
        WIFI_LOGE("EncryptParamSet HexStringToVec failed.");
        return HKS_FAILURE;
    }
    struct HksBlob encryptNonce = { nonceLength, nonce };
    struct HksParam encryptParam[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_NONCE, .blob = { .size = encryptNonce.size, .data = encryptNonce.data } },
    };

    HksInitParamSet(encryParamSet);
    HksAddParams(*encryParamSet, g_genAes256Param, sizeof(g_genAes256Param) / sizeof(HksParam));
    HksAddParams(*encryParamSet, encryptParam, sizeof(encryptParam) / sizeof(HksParam));
    HksBuildParamSet(encryParamSet);

    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    int32_t ret = HksKeyExist(&authId, *encryParamSet);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("EncryptParamSet Key is not exist.");
        return ret;
    }
    return HKS_SUCCESS;
}

int32_t DecryptParamSet(struct HksParamSet **decryParamSet, const WifiEncryptionInfo &wifiEncryptionInfo,
    const EncryptedData &encryptedData)
{
    uint8_t nonce[AES_256_NONCE_SIZE] = { 0 };
    uint32_t nonceLength = 0;
    if (HexStringToVec(encryptedData.IV, nonce, AES_256_NONCE_SIZE, nonceLength) != 0) {
        WIFI_LOGE("DecryptParamSet HexStringToVec failed.");
        return HKS_FAILURE;
    }
    struct HksBlob decryptNonce = { nonceLength, nonce };
    uint32_t cipherLength = encryptedData.encryptedPassword.length();
    uint8_t *cipherBuf = reinterpret_cast<uint8_t*>(const_cast<char*>(encryptedData.encryptedPassword.c_str()));
    struct HksBlob decryptAead = { AEAD_SIZE, cipherBuf + cipherLength - AEAD_SIZE };
    struct HksParam encryptParam[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_NONCE, .blob = { .size = decryptNonce.size, .data = decryptNonce.data } },
        { .tag = HKS_TAG_AE_TAG, .blob = { .size = decryptAead.size, .data = decryptAead.data } },
    };

    HksInitParamSet(decryParamSet);
    HksAddParams(*decryParamSet, g_genAes256Param, sizeof(g_genAes256Param) / sizeof(HksParam));
    HksAddParams(*decryParamSet, encryptParam, sizeof(encryptParam) / sizeof(HksParam));
    HksBuildParamSet(decryParamSet);

    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    int32_t ret = HksKeyExist(&authId, *decryParamSet);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("DecryptParamSet Key is not exist.");
        return ret;
    }
    return HKS_SUCCESS;
}

int32_t WifiLoopEncrypt(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &inputString,
    EncryptedData &encryptedData)
{
    if (inputString.length() == 0) {
        WIFI_LOGI("WifiLoopEncrypt inputString is nullptr.");
        return HKS_SUCCESS;
    }

    struct HksParamSet *encryParamSet = nullptr;
    int32_t ret = EncryptParamSet(&encryParamSet, wifiEncryptionInfo, encryptedData);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopEncrypt EncryptParamSet failed: %{public}d.", ret);
        return ret;
    }

    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handle };
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    ret = HksInit(&authId, encryParamSet, &handleEncrypt, nullptr);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopEncrypt HksInit failed: %{public}d.", ret);
        return ret;
    }

    struct HksBlob inData = { inputString.length(), (uint8_t *)&inputString[0] };
    uint8_t *cipherBuf = (uint8_t *)malloc(inputString.length() + AEAD_SIZE);
    if (cipherBuf == nullptr) {
        WIFI_LOGE("WifiLoopEncrypt malloc failed.");
        return HKS_FAILURE;
    }
    struct HksBlob outData = { inputString.length() + AEAD_SIZE, cipherBuf };
    ret = UpdateAndFinish(&handleEncrypt, encryParamSet, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopEncrypt UpdateAndFinish failed: %{public}d.", ret);
        free(cipherBuf);
        return ret;
    }

    std::string temp(outData.data, outData.data + outData.size);
    encryptedData.encryptedPassword = temp;
    HksFreeParamSet(&encryParamSet);
    free(cipherBuf);
    return ret;
}

int32_t WifiLoopDecrypt(const WifiEncryptionInfo &wifiEncryptionInfo, const EncryptedData &encryptedData,
    std::string &decryptedData)
{
    if (encryptedData.encryptedPassword.length() == 0) {
        WIFI_LOGI("WifiLoopDecrypt encryptedData is nullptr.");
        return HKS_SUCCESS;
    }

    struct HksParamSet *decryParamSet = nullptr;
    int32_t ret = DecryptParamSet(&decryParamSet, wifiEncryptionInfo, encryptedData);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopEncrypt DecryptParamSet failed: %{public}d.", ret);
        return ret;
    }

    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handle };
    struct HksBlob authId = wifiEncryptionInfo.keyAlias;
    ret = HksInit(&authId, decryParamSet, &handleDecrypt, nullptr);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopDecrypt HksInit failed: %{public}d.", ret);
        return ret;
    }

    uint32_t cipherLength = encryptedData.encryptedPassword.length();
    uint8_t *cipherBuf = reinterpret_cast<uint8_t*>(const_cast<char*>(encryptedData.encryptedPassword.c_str()));
    struct HksBlob inData = { cipherLength - AEAD_SIZE, cipherBuf };
    uint8_t *plainBuf = (uint8_t *)malloc(cipherLength);
    if (plainBuf == nullptr) {
        WIFI_LOGE("WifiLoopDecrypt malloc failed.");
        return HKS_FAILURE;
    }
    struct HksBlob outData = { cipherLength, plainBuf };
    ret = UpdateAndFinish(&handleDecrypt, decryParamSet, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        WIFI_LOGE("WifiLoopDecrypt UpdateAndFinish failed: %{public}d.", ret);
        free(plainBuf);
        return ret;
    }
    std::string temp(outData.data, outData.data + outData.size - AEAD_SIZE);
    if (memset_s(outData.data, outData.size, 0, outData.size) != EOK) {
        WIFI_LOGE("WifiLoopDecrypt memset_s return error!");
        free(plainBuf);
        return HKS_FAILURE;
    }
    decryptedData = temp;
    std::fill(temp.begin(), temp.end(), 0);
    HksFreeParamSet(&decryParamSet);
    free(plainBuf);
    return ret;
}

}  // namespace Wifi
}  // namespace OHOS
#endif