/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "wifi_sensor_scene.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

static std::string g_errLog = "wifiSensorTest";

class WifiSensorSceneTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiSensorSceneTest, InitCallbackTest01, TestSize.Level1)
{
    WifiSensorScene::GetInstance().InitCallback();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, ReportLinkedQualityTest01, TestSize.Level1)
{
    WifiSensorScene::GetInstance().ReportLinkedQuality(-60, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, ReportLinkedQualityTest02, TestSize.Level1)
{
    WifiSensorScene::GetInstance().ReportLinkedQuality(-73, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, ReportLinkedQualityTest03, TestSize.Level1)
{
    WifiSensorScene::GetInstance().ReportLinkedQuality(-80, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, ReportLinkedQualityTest04, TestSize.Level1)
{
    WifiSensorScene::GetInstance().ReportLinkedQuality(-86, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, ReportLinkedQualityTest05, TestSize.Level1)
{
    WifiSensorScene::GetInstance().ReportLinkedQuality(-90, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, GetMinRssiThresTest01, TestSize.Level1)
{
    WifiSensorScene::GetInstance().GetMinRssiThres(2480);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, GetMinRssiThresTest02, TestSize.Level1)
{
    WifiSensorScene::GetInstance().GetMinRssiThres(5180);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, SensorEnhCallbackTest01, TestSize.Level1)
{
    WifiSensorScene::GetInstance().scenario_ = -1;
    WifiSensorScene::GetInstance().SensorEnhCallback(-1);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, SensorEnhCallbackTest02, TestSize.Level1)
{
    WifiSensorScene::GetInstance().scenario_ = -1;
    WifiSensorScene::GetInstance().SensorEnhCallback(1);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, SensorEnhCallbackTest03, TestSize.Level1)
{
    WifiSensorScene::GetInstance().scenario_ = -1;
    WifiSensorScene::GetInstance().SensorEnhCallback(0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, RegisterSensorEnhCallbackTestNotReg, TestSize.Level1)
{
    WifiSensorScene::GetInstance().RegisterSensorEnhCallback();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, RegisterSensorEnhCallbackTestAlreadyReg, TestSize.Level1)
{
    WifiSensorScene::GetInstance().isCallbackReg_ = true;
    WifiSensorScene::GetInstance().RegisterSensorEnhCallback();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
    EXPECT_TRUE(WifiSensorScene::GetInstance().isCallbackReg_);
}

HWTEST_F(WifiSensorSceneTest, IsOutdoorSceneTest01, TestSize.Level1)
{
    WifiSensorScene::GetInstance().IsOutdoorScene();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, OnConnectivityChangedTestWiFiConn, TestSize.Level1)
{
    WifiSensorScene::GetInstance().OnConnectivityChanged(1, 1);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);

    WifiSensorScene::GetInstance().OnConnectivityChanged(1, 3);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSensorSceneTest, OnConnectivityChangedTestCellConn, TestSize.Level1)
{
    WifiSensorScene::GetInstance().OnConnectivityChanged(0, 1);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);

    WifiSensorScene::GetInstance().OnConnectivityChanged(0, 3);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

}
}