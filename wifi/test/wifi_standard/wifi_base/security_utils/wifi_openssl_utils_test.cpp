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
    EXPECT_EQ(cipherTextLen, CIPHER_TEXT_MAX_LEN);
    for (int i = 0; i < cipherTextLen; i++) {
        EXPECT_EQ(newCipherText[i], cipherText[i]);
    }
}

}  // namespace Wifi
}  // namespace OHOS
