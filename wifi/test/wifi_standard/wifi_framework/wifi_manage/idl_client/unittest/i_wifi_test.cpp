/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "client.h"
#include "i_wifi.h"
#include "i_wifi_sta_iface.h"
#include "wifi_log.h"
#include "serial.h"

#undef LOG_TAG
#define LOG_TAG "IWifiTest"

using namespace testing::ext;
namespace OHOS {
namespace Wifi {

class IWifiTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        mTestContext = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
        if (mTestContext == nullptr) {
            LOGE("create mTestContext failed!");
            exit(-1);
        }
    }
    static void TearDownTestCase()
    {
        if (mTestContext != nullptr) {
            ReleaseContext(mTestContext);
            mTestContext = nullptr;
        }
    }
    virtual void SetUp()
    {
        if (mTestContext != nullptr) {
            mTestContext->wBegin = mTestContext->wEnd = 0;
        }
    }
    virtual void TearDown()
    {
        if (mTestContext != nullptr) {
            mTestContext->wBegin = mTestContext->wEnd = 0;
        }
    }

pubilc:
    static Context mTestContext;
};

Context *IWifiTest::mTestContext = nullptr;

HWTEST_F(IWifiTest, GetWifiChipTest, TestSize.Level1)
{
    uint8_t id = 1;
    IWifiChip chip;
    GetWifiChip(id, &chip);
}

HWTEST_F(IWifiTest, GetWifiChipIdsTest, TestSize.Level1)
{
    uint8_t ids = 1;
    int32_t size = 1;
    GetWifiChipIds(&ids, &size);
}

HWTEST_F(IWifiTest, StopTest, TestSize.Level1)
{
    Stop();
}

HWTEST_F(IWifiTest, NotifyClearTest, TestSize.Level1)
{
    NotifyClear();
}

HWTEST_F(IWifiTest, OnTransactTest1, TestSize.Level1)
{
    char test[] = "102\t100\t101\t";
    EXPECT_TRUE(OnTransact(nullptr) == -1);
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest2, TestSize.Level1)
{
    char test[] = "103\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "103\t1\tiface";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "103\t1\tiface\tidace";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "103\t1\tiface\tidace\t";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest3, TestSize.Level1)
{
    char test[] = "104\t1\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest4, TestSize.Level1)
{
    char test[] = "105\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "105\t1\tiface";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "105\t1\tiface\tidace";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "105\t1\tiface\tidace\t";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest5, TestSize.Level1)
{
    char test[] = "106\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest6, TestSize.Level1)
{
    char test[] = "107\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "107\t1\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest7, TestSize.Level1)
{
    char test[] = "108\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "108\t2\t1";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "108\t1\t1\tiface";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "108\t1\t1\tiface\t";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest8, TestSize.Level1)
{
    char test[] = "109\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "109\t2\t1";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "109\t1\t1\tiface";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "109\t1\t1\tiface\t";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest9, TestSize.Level1)
{
    char test[] = "110\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "110\t8\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest10, TestSize.Level1)
{
    char test[] = "111\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest11, TestSize.Level1)
{
    char test[] = "112\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "112\t8\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest12, TestSize.Level1)
{
    char test[] = "113\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest13, TestSize.Level1)
{
    char test[] = "114\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest14, TestSize.Level1)
{
    char test[] = "115\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest15, TestSize.Level1)
{
    char test[] = "116\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest16, TestSize.Level1)
{
    char test[] = "117\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest17, TestSize.Level1)
{
    char test[] = "118\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test[] = "118\t8\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest18, TestSize.Level1)
{
    char test[] = "119\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest19, TestSize.Level1)
{
    char test[] = "120\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "120\t8\t9";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "120\t8\t9\t7";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "120\t8\t9\t7\t6";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test4[] = "120\t8\t9\t7\t6\tsrc";
    mTestContext->oneProcess = test4;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test4) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test5[] = "120\t8\t9\t7\t6\tsrc\tp2p";
    mTestContext->oneProcess = test5;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test5) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test6[] = "120\t8\t9\t7\t6\tsrc\tp2p\type";
    mTestContext->oneProcess = test5;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test5) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest20, TestSize.Level1)
{
    char test[] = "121\taddress";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "121\taddress\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest21, TestSize.Level1)
{
    char test[] = "122\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "122\t8\taddress";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "122\t8\taddress\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest22, TestSize.Level1)
{
    char test[] = "123\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest23, TestSize.Level1)
{
    char test[] = "124\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "124\t8\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest24, TestSize.Level1)
{
    char test[] = "125\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "125\t8\t9";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "125\t8\t9\tsrc";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "125\t8\t9\tsrc\tgodevice";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test4[] = "125\t8\t9\tsrc\tgodevice\tbssid";
    mTestContext->oneProcess = test4;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test4) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test5[] = "125\t8\t9\tsrc\tgodevice\tbssid\t";
    mTestContext->oneProcess = test5;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test5) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest25, TestSize.Level1)
{
    char test[] = "126\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "126\t8\taddress";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "126\t8\taddress";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest26, TestSize.Level1)
{
    char test[] = "127\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest27, TestSize.Level1)
{
    char test[] = "128\treason";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "128\treason\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest28, TestSize.Level1)
{
    char test[] = "129\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "129\t8\t9";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "129\t8\t9\t7";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "129\t8\t9\t7\tname";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test4[] = "129\t8\t9\t7\tname\tssid";
    mTestContext->oneProcess = test4;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test4) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test5[] = "129\t8\t9\t7\tname\tssid\tpsk";
    mTestContext->oneProcess = test5;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test5) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test6[] = "129\t8\t9\t7\tname\tssid\tpsk\tpassphrase\t";
    mTestContext->oneProcess = test6;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test6) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest29, TestSize.Level1)
{
    char test[] = "130\t8";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "130\t8\tname";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "130\t8\tname\t";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest30, TestSize.Level1)
{
    char test[] = "131\taddress";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "131\taddress\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest31, TestSize.Level1)
{
    char test[] = "132\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest32, TestSize.Level1)
{
    char test[] = "133\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest33, TestSize.Level1)
{
    char test[] = "134\taddress";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "134\taddress\tpin";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "134\taddress\tpin\t";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest34, TestSize.Level1)
{
    char test[] = "135\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest35, TestSize.Level1)
{
    char test[] = "136\t5";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "136\t5\taddress";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "136\t5\taddress\t6";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "136\t5\taddress\t6\tlvs";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test4[] = "136\t5\taddress\t6\tlvs\t";
    mTestContext->oneProcess = test4;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test4) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest36, TestSize.Level1)
{
    char test[] = "137\t";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest37, TestSize.Level1)
{
    char test[] = "138\taddress";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "138\taddress\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest38, TestSize.Level1)
{
    char test[] = "139\taddress";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest39, TestSize.Level1)
{
    char test[] = "140\t1";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "140\t1\t";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "140\t1\t2";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "140\t1\t2\t3";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test4[] = "140\t1\t2\t3\t00:11:22:33:44:55";
    mTestContext->oneProcess = test4;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test4) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test5[] = "140\t1\t2\t3\t00:11:22:33:44:55\t6";
    mTestContext->oneProcess = test5;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test5) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test6[] = "140\t1\t2\t3\t00:11:22:33:44:55\t6\tTlv";
    mTestContext->oneProcess = test6;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test6) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test7[] = "140\t1\t2\t3\t00:11:22:33:44:55\t6\tTlv\t";
    mTestContext->oneProcess = test7;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test7) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest40, TestSize.Level1)
{
    char test[] = "141\t5";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test1[] = "141\t5\t1";
    mTestContext->oneProcess = test1;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test1) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test2[] = "141\t5\t1\tname";
    mTestContext->oneProcess = test2;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test2) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
    char test3[] = "141\t5\t1\tname\t";
    mTestContext->oneProcess = test3;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test3) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}

HWTEST_F(IWifiTest, OnTransactTest41, TestSize.Level1)
{
    char test[] = "142\t5";
    mTestContext->oneProcess = test;
    mTestContext->nPos = 0;
    mTestContext->nSize = strlen(test) + 1;
    EXPECT_TRUE(OnTransact(mTestContext) == 0);
}
}  // namespace Wifi
}  // namespace OHOS
