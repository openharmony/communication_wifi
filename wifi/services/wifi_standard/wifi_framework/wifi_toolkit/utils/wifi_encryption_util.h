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

#ifndef OHOS_WIFI_CONFIG_HKS_H
#define OHOS_WIFI_CONFIG_HKS_H
#include <string>
#include <vector>
#include "hks_api.h"
#include "hks_type.h"
#include "hks_param.h"

namespace OHOS {
namespace Wifi {
constexpr uint32_t AES_COMMON_SIZE = 256;
constexpr uint32_t AAD_SIZE = 16;
constexpr uint32_t NONCE_SIZE = 16;

const uint8_t AAD[AAD_SIZE] = {0};

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
    { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = AAD_SIZE, .data = (uint8_t *)AAD } },
};

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

int32_t SetUpHks();

int32_t GetKey(const WifiEncryptionInfo &wifiEncryptionInfo, const struct HksParamSet *genParamSet);

int32_t WifiEncryption(const WifiEncryptionInfo &wifiEncryptionInfo, const std::string &inputString,
    EncryptedData &encryptedData);

int32_t WifiDecryption(const WifiEncryptionInfo &wifiEncryptionInfo, const EncryptedData &encryptedData,
    std::string &decryptedData);
}
}
#endif