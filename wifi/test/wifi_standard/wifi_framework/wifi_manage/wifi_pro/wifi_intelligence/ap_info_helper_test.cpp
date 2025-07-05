/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include <ap_info_helper.h>
#include <string>
#include <vector>
#include <gmock/gmock.h>


using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifiTest";

class ApInfoHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        helper = std::make_unique<ApInfoHelper>();
    }

    virtual void TearDown()
    {
    }
public:
    std::unique_ptr<ApInfoHelper> helper;
};

HWTEST_F(ApInfoHelperTest, Init_Success_test, TestSize.Level1)
{
    int32_t result = helper->Init();
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(ApInfoHelperTest, IsCellIdExitTest, TestSize.Level1)
{
    ApInfoData apInfoData;
    CellInfoData cellInfoData;
    cellInfoData.cellId = 1;
    apInfoData.cellInfos.push_back(cellInfoData);
    helper->apInfos_.push_back(apInfoData);
    EXPECT_EQ(helper->IsCellIdExit(cellInfoData.cellId), true);
}

HWTEST_F(ApInfoHelperTest, GetMonitorDatasTest, TestSize.Level1)
{
    ApInfoData datas;
    CellInfoData cellInfoData;
    cellInfoData.cellId = "1";
    datas.cellInfos.push_back(cellInfoData);
    helper->apInfos_.push_back(datas);
    helper->GetMonitorDatas(cellInfoData.cellId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ApInfoHelperTest, GetAllApInfosTest, TestSize.Level1)
{
    helper->wifiDataBaseUtils_ = nullptr;
    EXPECT_FALSE(helper->GetAllApInfos());
    helper->wifiDataBaseUtils_ = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    EXPECT_FALSE(helper->GetAllApInfos());
}

HWTEST_F(ApInfoHelperTest, AddApInfoTest1, TestSize.Level1)
{
    std::string cellId = "1";
    int32_t networkId = 1;
    helper->apInfos_.clear();
    int32_t size = helper->apInfos_.size();
    EXPECT_EQ(size, 0);
    helper->AddApInfo(cellId, networkId);
}
HWTEST_F(ApInfoHelperTest, GetOldestApInfoDataTest, TestSize.Level1)
{
    ApInfoData data;
    helper->apInfos_ = {};
    EXPECT_EQ(helper->GetOldestApInfoData(data), -1);
}
}
}