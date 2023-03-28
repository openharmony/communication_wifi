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
#include <wifi_dumper.h>
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDumperTest");
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string ARGS_HELP = "-h";

class WifiDumperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pWifiDumper = std::make_unique<WifiDumper>();
    }

    virtual void TearDown()
    {
        pWifiDumper.reset();
    }
    
    static void BasicDumpFuncTest(std::string& result)
    {
        WIFI_LOGI("BasicDumpFuncTest result is: %{public}s", result.c_str());
    }

public:
    std::unique_ptr<WifiDumper> pWifiDumper;
};
/**
 * @tc.name: DeviceDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, DeviceDump001, TestSize.Level1)
{
    WIFI_LOGI("DeviceDump001 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->DeviceDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: DeviceDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, DeviceDump002, TestSize.Level1)
{
    WIFI_LOGI("DeviceDump002 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->DeviceDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: DeviceDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, DeviceDump003, TestSize.Level1)
{
    WIFI_LOGI("DeviceDump003 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->DeviceDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: ScanDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump001, TestSize.Level1)
{
    WIFI_LOGI("ScanDump001 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->ScanDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: ScanDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump002, TestSize.Level1)
{
    WIFI_LOGI("ScanDump002 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->ScanDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: ScanDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump003, TestSize.Level1)
{
    WIFI_LOGI("ScanDump003 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->ScanDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: P2pDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump001, TestSize.Level1)
{
    WIFI_LOGI("P2pDump001 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->P2pDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: P2pDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump002, TestSize.Level1)
{
    WIFI_LOGI("P2pDump002 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->P2pDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: P2pDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump003, TestSize.Level1)
{
    WIFI_LOGI("P2pDump003 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->P2pDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: HotspotDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump001, TestSize.Level1)
{
    WIFI_LOGI("HotspotDump001 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->HotspotDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: HotspotDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump002, TestSize.Level1)
{
    WIFI_LOGI("HotspotDump002 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->HotspotDump(BasicDumpFuncTest, vecArgs, result));
}
/**
 * @tc.name: HotspotDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump003, TestSize.Level1)
{
    WIFI_LOGI("HotspotDump003 enter");
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(pWifiDumper->HotspotDump(BasicDumpFuncTest, vecArgs, result));
}
}
}