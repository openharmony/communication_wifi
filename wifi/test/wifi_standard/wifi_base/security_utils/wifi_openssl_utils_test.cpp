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

#include <gtest/gtest.h>
#include "wifi_openssl_utils.h"
#include "common.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

#define PLAIN_TEXT_LEN 10
#define CIPHER_TEXT_MAX_LEN 50
#define KEY_LEN 16
#define AES_TYPE 2
#define AES_GCM_TAG_LEN 4

class WifiOpensslUtilsTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pWifiOpensslUtilsOpt = std::make_unique<WifiOpensslUtils>();
    }
    virtual void TearDown()
    {}

public:
    std::unique_ptr<WifiOpensslUtils> pWifiOpensslUtilsOpt;
};

uint8_t plainText[PLAIN_TEXT_LEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
const uint8_t key[KEY_LEN] = {0xa8, 0x2b, 0xce, 0x21, 0xa8, 0x2b, 0xce, 0x21, 0xa8, 0x2b, 0xce,
    0x21, 0xa8, 0x2b, 0xce, 0x21};
const uint8_t iv[AES_IV_LEN] = {0xa8, 0x2b, 0xce, 0x21, 0xa8, 0x2b, 0xce, 0x21, 0xa8, 0x2b, 0xce, 0x21};
uint8_t cipherText[CIPHER_TEXT_MAX_LEN] = {0x40, 0x16, 0x28, 0x3e, 0x96, 0xd9, 0x43, 0x29, 0x4d, 0x2c,
    0x0a, 0xca, 0x38, 0xcc};

HWTEST_F(WifiOpensslUtilsTest, OpensslAesEncryptTest1, TestSize.Level1)
{
    int cipherTextLen = 0;
    uint8_t newCipherText[CIPHER_TEXT_MAX_LEN];
    AesCipherInfo info;
    info.aesType = AES_TYPE;
    memcpy_s(info.key, MAX_KEY_LEN, key, KEY_LEN);
    memcpy_s(info.iv, AES_IV_LEN, iv, AES_IV_LEN);
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesEncrypt(plainText, PLAIN_TEXT_LEN,
        &info, newCipherText, &cipherTextLen), 0);
    EXPECT_NE(cipherTextLen, CIPHER_TEXT_MAX_LEN);
    for (int i = 0; i < cipherTextLen; i++) {
        EXPECT_EQ(newCipherText[i], cipherText[i]);
    }
}

HWTEST_F(WifiOpensslUtilsTest, OpensslAesDecryptTest1, TestSize.Level1)
{
    int cipherTextLen = 0;
    uint8_t newCipherText[CIPHER_TEXT_MAX_LEN];
    AesCipherInfo info;
    info.aesType = AES_TYPE;
    memcpy_s(info.key, MAX_KEY_LEN, key, KEY_LEN);
    memcpy_s(info.iv, AES_IV_LEN, iv, AES_IV_LEN);
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesEncrypt(plainText, PLAIN_TEXT_LEN,
        &info, newCipherText, &cipherTextLen), 0);
    EXPECT_NE(cipherTextLen, CIPHER_TEXT_MAX_LEN);
    for (int i = 0; i < cipherTextLen; i++) {
        EXPECT_EQ(newCipherText[i], cipherText[i]);
    }
    
    int decryptedPlainTextLen = 0;
    uint8_t newPlainText[PLAIN_TEXT_LEN];
 
    // 测试cipherText为空指针的情况
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(nullptr, cipherTextLen,
        &info, newPlainText, &decryptedPlainTextLen), -1);
 
    // 测试info为空指针的情况
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, cipherTextLen,
        nullptr, newPlainText, &decryptedPlainTextLen), -1);
 
    // 测试plainText为空指针的情况
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, cipherTextLen,
        &info, nullptr, &decryptedPlainTextLen), -1);
 
    // 测试plainTextLen为空指针的情况
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, cipherTextLen,
        &info, newPlainText, nullptr), -1);
 
    // 测试cipherTextLen为0的情况
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, 0,
        &info, newPlainText, &decryptedPlainTextLen), -1);
    
    // 测试cipherTextLen小于AES_GCM_TAG_LEN的情况
    for (int i = 0; i <= AES_GCM_TAG_LEN; i++) {
        EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, i,
            &info, newPlainText, &decryptedPlainTextLen), -1);
    }
 
    // 解密后校验
    EXPECT_EQ(pWifiOpensslUtilsOpt->OpensslAesDecrypt(newCipherText, cipherTextLen,
        &info, newPlainText, &decryptedPlainTextLen), 0);
    EXPECT_EQ(decryptedPlainTextLen, PLAIN_TEXT_LEN);
    for (int i = 0; i < decryptedPlainTextLen; i++) {
        EXPECT_EQ(newPlainText[i], plainText[i]);
    }
}

}  // namespace Wifi
}  // namespace OHOS
