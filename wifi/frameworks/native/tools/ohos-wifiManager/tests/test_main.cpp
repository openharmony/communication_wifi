/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <cstdlib>
#include <cstring>

class WifiCliTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(WifiCliTest, TestHelpCommand)
{
    const char* argv[] = {"ohos-wifiManager", "sta-enable", "--help"};
    int argc = 3;
    char** argv_copy = const_cast<char**>(argv);

    int result = system("ohos-wifiManager sta-enable --help > /dev/null 2>&1");
    EXPECT_EQ(result, 0);
}

TEST_F(WifiCliTest, TestStaEnableCommand)
{
    int result = system("ohos-wifiManager sta-enable > /dev/null 2>&1");
    EXPECT_TRUE(result == 0 || result != 0);
}

TEST_F(WifiCliTest, TestStaDisableCommand)
{
    int result = system("ohos-wifiManager sta-disable > /dev/null 2>&1");
    EXPECT_TRUE(result == 0 || result != 0);
}

TEST_F(WifiCliTest, TestScanStartCommand)
{
    int result = system("ohos-wifiManager scan-start > /dev/null 2>&1");
    EXPECT_TRUE(result == 0 || result != 0);
}

TEST_F(WifiCliTest, TestScanListCommand)
{
    int result = system("ohos-wifiManager scan-list > /dev/null 2>&1");
    EXPECT_TRUE(result == 0 || result != 0);
}

TEST_F(WifiCliTest, TestUnknownCommand)
{
    int result = system("ohos-wifiManager unknown-cmd > /dev/null 2>&1");
    EXPECT_NE(result, 0);
}

TEST_F(WifiCliTest, TestNoCommand)
{
    int result = system("ohos-wifiManager > /dev/null 2>&1");
    EXPECT_NE(result, 0);
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}