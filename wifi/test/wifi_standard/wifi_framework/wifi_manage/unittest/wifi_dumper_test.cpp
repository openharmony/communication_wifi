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
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(DeviceDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: DeviceDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, DeviceDump002, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(DeviceDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: DeviceDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, DeviceDump003, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(DeviceDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: ScanDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump001, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(ScanDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: ScanDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump002, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(ScanDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: ScanDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, ScanDump003, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(ScanDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: P2pDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump001, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(P2pDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: P2pDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump002, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(P2pDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: P2pDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, P2pDump003, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(P2pDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: HotspotDump001
 * @tc.desc: test vecArgs is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump001, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    std::string result = "";
    EXPECT_TRUE(HotspotDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: HotspotDump002
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is not ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump002, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back("abc");
    std::string result = "";
    EXPECT_TRUE(HotspotDump(BasicDumpFuncTest, vecArgs, result))
}
/**
 * @tc.name: HotspotDump003
 * @tc.desc: test vecArgs is not empty but vecArgs[0] is ARGS_HELP
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiDumperTest, HotspotDump003, TestSize.Level1)
{
    std::function<void(std::string&)> saBasicDumpFunc = BasicDumpFuncTest;
    std::vector<std::string> vecArgs;
    vecArgs.push_back(ARGS_HELP);
    std::string result = "";
    EXPECT_TRUE(HotspotDump(BasicDumpFuncTest, vecArgs, result))
}




/*
bool WifiDumper::HotspotDump(std::function<void(std::string&)> saBasicDumpFunc,
    const std::vector<std::string>& vecArgs, std::string& result)
{
    PrintArgs(vecArgs);
    result.clear();
    if (!vecArgs.empty() && vecArgs[0] == ARGS_HELP) {
        result = ShowHotspotDumpUsage();
        return true;
    }

    saBasicDumpFunc(result);
    return true;
}
namespace OHOS {
namespace Wifi {
class WifiDumper {
public:
    bool DeviceDump(std::function<void(std::string&)> saBasicDumpFunc,
        const std::vector<std::string> &vecArgs, std::string &result);

    bool ScanDump(std::function<void(std::string&)> saBasicDumpFunc,
        const std::vector<std::string> &vecArgs, std::string &result);

    bool P2pDump(std::function<void(std::string&)> saBasicDumpFunc,
        const std::vector<std::string> &vecArgs, std::string &result);

    bool HotspotDump(std::function<void(std::string&)> saBasicDumpFunc,
        const std::vector<std::string> &vecArgs, std::string &result);

private:
    std::string ShowDeviceDumpUsage() const;
    std::string ShowScanDumpUsage() const;
    std::string ShowP2pDumpUsage() const;
    std::string ShowHotspotDumpUsage() const;
    void PrintArgs(const std::vector<std::string>& vecArgs);
};
}  // namespace Wifi
}  // namespace OHOS
#endif
*/