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
#include "wifi_encryption_util_test.h"
#include "wifi_encryption_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

static struct HksParam g_genParam[] = {
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

HWTEST_F(WifiEncryptionUtilFuncTest, GetKey_001, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestKey");
    struct HksParamSet *testParamSet = nullptr;
    EXPECT_TRUE(HksInitParamSet(&testParamSet) == HKS_SUCCESS);
    EXPECT_TRUE(HksAddParams(testParamSet, g_genParam, sizeof(g_genParam) / sizeof(HksParam)) == HKS_SUCCESS);
    EXPECT_TRUE(HksBuildParamSet(&testParamSet) == HKS_SUCCESS);
    struct HksBlob authId = testEncryptionInfo.keyAlias;
    EXPECT_TRUE(GetKeyByAlias(&authId, testParamSet) == HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiEncryption_002, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestEncryption");
    EncryptedData encryResult;
    const std::string inputString = "12345678";
    EXPECT_TRUE(WifiEncryption(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiEncryption_003, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestEncryption");
    EncryptedData encryResult;
    const std::string inputString = "";
    EXPECT_TRUE(WifiEncryption(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);
    EXPECT_TRUE(inputString.compare(encryResult.encryptedPassword) == 0);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiDecryption_004, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestDecryption");
    EncryptedData encryResult;
    const std::string inputString = "12345678";
    EXPECT_TRUE(WifiEncryption(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);
    std::string decryptedData = "";
    EXPECT_TRUE(WifiDecryption(testEncryptionInfo, encryResult, decryptedData) == HKS_SUCCESS);
    EXPECT_TRUE(inputString.compare(decryptedData) == 0);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiDecryption_005, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestDecryption");
    EncryptedData encryResult;
    encryResult.encryptedPassword = "";
    std::string decryptedData = "";
    EXPECT_TRUE(WifiDecryption(testEncryptionInfo, encryResult, decryptedData) == HKS_SUCCESS);
    EXPECT_TRUE(decryptedData.compare("") == 0);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiDecryptionFailed_006, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestDecryption");
    EncryptedData encryResult;
    encryResult.encryptedPassword = "1234567";
    std::string decryptedData = "";
    EXPECT_TRUE(WifiDecryption(testEncryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);
    EXPECT_TRUE(decryptedData.compare("") == 0);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiDecryptionFailed_007, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestDecryption");
    EncryptedData encryResult;
    encryResult.encryptedPassword = "12345678";
    encryResult.encryptedPassword = "1234567";
    std::string decryptedData = "";
    EXPECT_TRUE(WifiDecryption(testEncryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);
    EXPECT_TRUE(decryptedData.compare("") == 0);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiDecryption_008, TestSize.Level1)
{
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestEncryption008");
    EncryptedData encryResult;
    const std::string inputString = "12345678";
    EXPECT_TRUE(WifiEncryption(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);
    std::string decryptedData = "";
    WifiEncryptionInfo testDecryptionInfo;
    testDecryptionInfo.SetFile("TestDecryption008");
    EXPECT_TRUE(WifiDecryption(testDecryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, ImportKeyAndDeleteKey_009, TestSize.Level1)
{
    // 0001020304050607080910000102030405060708091000010203040506070809 : 64 bit
    std::string key = "0001020304050607080910000102030405060708091000010203040506070809";
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestImportKeyAndDeleteKey009");
    EXPECT_TRUE(ImportKey(testEncryptionInfo, key) == HKS_SUCCESS);
    EXPECT_TRUE(ImportKey(testEncryptionInfo, key) == HKS_SUCCESS);
    EXPECT_TRUE(DeleteKey(testEncryptionInfo) == HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, ImportKeyAndDeleteKey_010, TestSize.Level1)
{
    // 000102030405060708091000010203040506070809100001020304050607080 : 63 bit
    std::string key = "000102030405060708091000010203040506070809100001020304050607080";
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestImportKeyAndDeleteKey010");
    EXPECT_TRUE(ImportKey(testEncryptionInfo, key) != HKS_SUCCESS);
    EXPECT_TRUE(DeleteKey(testEncryptionInfo) == HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiLoopEncrypt_011, TestSize.Level1)
{
    // 0001020304050607080910000102030405060708091000010203040506070809 : 64 bit
    std::string key = "0001020304050607080910000102030405060708091000010203040506070809";
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestWifiLoopEncrypt011");
    EXPECT_TRUE(ImportKey(testEncryptionInfo, key) == HKS_SUCCESS);

    EncryptedData encryResult;
    std::string inputString = "";
    EXPECT_TRUE(WifiLoopEncrypt(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);

    inputString = "12345678";
    // 000000000000000000000000000000000000000000000000000000000000000000 : 66 bit
    encryResult.IV = "000000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_TRUE(WifiLoopEncrypt(testEncryptionInfo, inputString, encryResult) != HKS_SUCCESS);

    encryResult.IV = "";
    EXPECT_TRUE(WifiLoopEncrypt(testEncryptionInfo, inputString, encryResult) != HKS_SUCCESS);

    // 0000000000000000000000000000000000000000000000000000000000000000 : 64 bit
    encryResult.IV = "0000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_TRUE(WifiLoopEncrypt(testEncryptionInfo, inputString, encryResult) == HKS_SUCCESS);

    std::string decryptedData;
    encryResult.IV = "";
    EXPECT_TRUE(WifiLoopDecrypt(testEncryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);

    // 1111111111111111111111111111111111111111111111111111111111111111 : 64 bit
    encryResult.IV = "1111111111111111111111111111111111111111111111111111111111111111";
    EXPECT_TRUE(WifiLoopDecrypt(testEncryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);
    EXPECT_TRUE(inputString.compare(decryptedData) != 0);

    // 0000000000000000000000000000000000000000000000000000000000000000 : 64 bit
    encryResult.IV = "0000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_TRUE(WifiLoopDecrypt(testEncryptionInfo, encryResult, decryptedData) == HKS_SUCCESS);
    EXPECT_TRUE(inputString.compare(decryptedData) == 0);
    EXPECT_TRUE(DeleteKey(testEncryptionInfo) == HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiLoopEncrypt_012, TestSize.Level1)
{
    // 0001020304050607080910000102030405060708091000010203040506070809 : 64 bit
    std::string key = "0001020304050607080910000102030405060708091000010203040506070809";
    WifiEncryptionInfo testEncryptionInfo;
    testEncryptionInfo.SetFile("TestWifiLoopEncrypt012");

    EncryptedData encryResult;
    std::string inputString = "12345678";
    EXPECT_TRUE(WifiLoopEncrypt(testEncryptionInfo, inputString, encryResult) != HKS_SUCCESS);
}

HWTEST_F(WifiEncryptionUtilFuncTest, WifiLoopDecrypt_013, TestSize.Level1)
{
    // 0001020304050607080910000102030405060708091000010203040506070809 : 64 bit
    std::string key = "0001020304050607080910000102030405060708091000010203040506070809";
    WifiEncryptionInfo testDecryptionInfo;
    testDecryptionInfo.SetFile("TestWifiLoopDecrypt013");
    std::string decryptedData;
    EncryptedData encryResult;
    encryResult.encryptedPassword = "";
    EXPECT_TRUE(WifiLoopDecrypt(testDecryptionInfo, encryResult, decryptedData) == HKS_SUCCESS);

    encryResult.encryptedPassword = "12345678";
    // 000000000000000000000000000000000000000000000000000000000000000000 : 66 bit
    encryResult.IV = "000000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_TRUE(WifiLoopDecrypt(testDecryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);

    // 0000000000000000000000000000000000000000000000000000000000000000 : 64 bit
    encryResult.IV = "0000000000000000000000000000000000000000000000000000000000000000";
    EXPECT_TRUE(WifiLoopDecrypt(testDecryptionInfo, encryResult, decryptedData) != HKS_SUCCESS);
}
}  // namespace Wifi
}  // namespace OHOS
#endif