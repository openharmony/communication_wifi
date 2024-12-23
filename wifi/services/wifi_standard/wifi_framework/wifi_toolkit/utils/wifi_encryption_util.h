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
#ifndef OHOS_WIFI_CONFIG_HKS_H
#define OHOS_WIFI_CONFIG_HKS_H
#if defined(FEATURE_ENCRYPTION_SUPPORT) || defined(SUPPORT_LOCAL_RANDOM_MAC)
#include <string>
#include <vector>
#include "hks_api.h"
#include "hks_type.h"
#include "hks_param.h"

namespace OHOS {
namespace Wifi {
constexpr uint32_t AES_COMMON_SIZE = 2048 + 16;
constexpr uint32_t AAD_SIZE = 16;
constexpr uint32_t NONCE_SIZE = 16;
constexpr uint32_t AEAD_SIZE = 16;
constexpr uint32_t AES_256_NONCE_SIZE = 32;
constexpr uint32_t MAX_UPDATE_SIZE = 64 * 1024;

const uint8_t AAD[AAD_SIZE] = {0};

class EncryptedData final {
public:
    std::string encryptedPassword = "";
    std::string IV = "";
    EncryptedData(const std::string password, const std::string inputIV)
    {
        encryptedPassword = password;
        IV = inputIV;
    }
    EncryptedData() {}
    ~EncryptedData() {}
};

class WifiEncryptionInfo {
public:
    std::string fileName;
    static constexpr char WIFI_ENCRY_KEY[] = "WifiEncryHksAes";
    struct HksBlob keyAlias;
    void SetFile(const std::string file)
    {
        fileName = WIFI_ENCRY_KEY + file;
        keyAlias = { fileName.length(), (uint8_t *)&fileName[0] };
    }
    explicit WifiEncryptionInfo(const std::string file)
    {
        SetFile(file);
    }
    WifiEncryptionInfo() {}
    ~WifiEncryptionInfo() {}
};

/**
 * @Description  Set up Huks service
 */
int32_t SetUpHks();

/**
 * @Description  Generate new or get existed GCM-AES key based on input encryptionInfo and genParamSet
 * @param keyAlias  - keyAlias info
 * @param genParamSet - generate params
 * @return HKS_SUCCESS - find key, others - find key failed
 */
int32_t GetKeyByAlias(struct HksBlob *keyAlias, const struct HksParamSet *genParamSet);

/**
 * @Description  Encrypt inputString using GCM-AES based on input encryptionInfo
 * @param wifiEncryptionInfo  - keyAlias info
 * @param inputString - plaint string that needs to be encrypted
 * @param encryptedData - encrypted result with encrypted string and IV value
 * @return HKS_SUCCESS - encryption success, others - encryption failed
 */
int32_t WifiEncryption(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &inputString,
    EncryptedData &encryptedData);

/**
 * @Description  Decrypt encryptedData using GCM-AES based on input encryptionInfo
 * @param wifiEncryptionInfo  - keyAlias info
 * @param encryptedData - encrypted result with encrypted string and IV value
 * @param decryptedData - string after decryption
 * @return HKS_SUCCESS - decryption success, others - decryption failed
 */
int32_t WifiDecryption(const WifiEncryptionInfo &wifiEncryptionInfo, const EncryptedData &encryptedData,
    std::string &decryptedData);

/**
 * @Description  Import GCM-AES key based on input encryptionInfo and default genParamSet
 * @param wifiEncryptionInfo  - keyAlias info
 * @param key - GCM-AES key(Hex string)
 * @return HKS_SUCCESS - Import key success, others - Import key failed
 */
int32_t ImportKey(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &key);

/**
 * @Description  Delete existed GCM-AES key based on input encryptionInfo and default genParamSet
 * @param wifiEncryptionInfo  - keyAlias info
 * @return HKS_SUCCESS - Delete key success, others - Delete key failed
 */
int32_t DeleteKey(const WifiEncryptionInfo &wifiEncryptionInfo);

/**
 * @Description  Encrypt inputString using GCM-AES based on input encryptionInfo
 * Used for encryptedData is biger than 100k
 * @param wifiEncryptionInfo  - keyAlias info
 * @param inputString - plaint string that needs to be encrypted
 * @param encryptedData - encrypted result with encrypted string and IV value
 * @return HKS_SUCCESS - encryption success, others - encryption failed
 */
int32_t WifiLoopEncrypt(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &inputString,
    EncryptedData &encryptedData);

/**
 * @Description  Decrypt encryptedData using GCM-AES based on input encryptionInfo
 * Used for encryptedData is biger than 100k
 * @param wifiEncryptionInfo  - keyAlias info
 * @param encryptedData - encrypted result with encrypted string and IV value
 * @param decryptedData - string after decryption
 * @return HKS_SUCCESS - decryption success, others - decryption failed
 */
int32_t WifiLoopDecrypt(const WifiEncryptionInfo &wifiEncryptionInfo, const EncryptedData &encryptedData,
    std::string &decryptedData);

/**
 * @Description  Generate MacRandomization Secret
 * @param keyName - keyAlias name
 * @param data  - data for hmac sha256
 * @param outPlant - hashed vector
 * @return HKS_SUCCESS - hmac sha256 success, others - failed
 */
int32_t WifiGenerateMacRandomizationSecret(const std::string &keyName,
    const std::string &data, std::vector<uint8_t> &outPlant);
}
}
#endif
#endif