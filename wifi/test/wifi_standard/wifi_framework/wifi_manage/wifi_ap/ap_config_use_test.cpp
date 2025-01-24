/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "operator_overload.h"
#include "ap_config_use.h"
#include "mock_wifi_ap_hal_interface.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "wifi_ap_msg.h"
#include "wifi_logger.h"
#include "wifi_global_func.h"
#include "wifi_msg.h"
#include "wifi_p2p_msg.h"
#include "wifi_country_code_manager.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifitest";
DEFINE_WIFILOG_LABEL("ApConfigUseTest");

class ApConfigUse_Test : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_apConfigUse = std::make_unique<ApConfigUse>();
    }
    virtual void TearDown() {}

    std::unique_ptr<ApConfigUse> m_apConfigUse;
};

HWTEST_F(ApConfigUse_Test, UpdateApChannelConfigTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateApChannelConfigTest enter");
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetChannel(1);
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, 0))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    WifiP2pLinkedInfo p2pLinkedInfo;
    p2pLinkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(p2pLinkedInfo), Return(0)));

    m_apConfigUse->UpdateApChannelConfig(apConfig);
}

HWTEST_F(ApConfigUse_Test, GetChannelFromDrvOrXmlByBandTest, TestSize.Level1)
{
    WIFI_LOGI("GetChannelFromDrvOrXmlByBandTest enter");
    std::vector<int> freq2G = {2412, 2417, 2422};
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApIfaceName()).WillRepeatedly(Return("wifitest"));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(freq2G), Return(WifiErrorNo::WIFI_HAL_OPT_OK)));
    std::vector<int> channels = m_apConfigUse->GetChannelFromDrvOrXmlByBand(BandType::BAND_2GHZ);
    for (int c : channels) {
        EXPECT_TRUE(IsValid24GChannel(c));
    }

    std::vector<int> freq5G = {5180, 5200, 5220};
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(freq5G), Return(WifiErrorNo::WIFI_HAL_OPT_OK)));
    channels = m_apConfigUse->GetChannelFromDrvOrXmlByBand(BandType::BAND_5GHZ);
    for (int c : channels) {
        EXPECT_TRUE(IsValid5GChannel(c));
    }
}

HWTEST_F(ApConfigUse_Test, GetBestChannelFor2GTest, TestSize.Level1)
{
    WIFI_LOGI("GetBestChannelFor2GTest enter");
    int channel = m_apConfigUse->GetBestChannelFor2G();
    WIFI_LOGI("GetBestChannelFor2GTest channel=%{public}d", channel);
    EXPECT_TRUE(IsValid24GChannel(channel));
}

HWTEST_F(ApConfigUse_Test, GetBestChannelFor5GTest, TestSize.Level1)
{
    WIFI_LOGI("GetBestChannelFor5GTest enter");
    std::vector<int> frequencies = {5180, 5200, 5220};
    HotspotConfig apConfig;
    apConfig.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(frequencies), Return(WifiErrorNo::WIFI_HAL_OPT_OK)));
    int channel = m_apConfigUse->GetBestChannelFor5G(apConfig);
    WIFI_LOGI("GetBestChannelFor5GTest channel=%{public}d", channel);
}

HWTEST_F(ApConfigUse_Test, GetBestChannelFor5G160MTest, TestSize.Level1)
{
    WIFI_LOGI("GetBestChannelFor5G160MTest enter");
    std::vector<int> frequencies = {5180, 5200, 5220};
    HotspotConfig apConfig;
    apConfig.SetBandWidth(AP_BANDWIDTH_160);
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(frequencies), Return(WifiErrorNo::WIFI_HAL_OPT_OK)));
    int channel = m_apConfigUse->GetBestChannelFor5G(apConfig);
    WIFI_LOGI("GetBestChannelFor5GTest channel=%{public}d", channel);
    EXPECT_EQ(channel, AP_CHANNEL_5G_160M_DEFAULT);
}

HWTEST_F(ApConfigUse_Test, FilterIndoorChannelTest, TestSize.Level1)
{
    WIFI_LOGI("FilterIndoorChannelTest enter");
    std::vector<int> channels = {36, 40, 44, 48, 52, 56};
    WifiCountryCodeManager::GetInstance().m_wifiCountryCode = "CN";
    m_apConfigUse->FilterIndoorChannel(channels);
    std::vector<int> channels1 = {};
    m_apConfigUse->FilterIndoorChannel(channels1);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(ApConfigUse_Test, Filter165ChannelTest, TestSize.Level1)
{
    WIFI_LOGI("Filter165ChannelTest enter");
    std::vector<int> channels = {36, 165};
    m_apConfigUse->Filter165Channel(channels);

    // 165 need to be filtered
    EXPECT_TRUE(channels.size() == 1);
    EXPECT_TRUE(channels[0] == 36);
    std::vector<int> channels1 = {36, 165};
    m_apConfigUse->Filter165Channel(channels1);
}

HWTEST_F(ApConfigUse_Test, JudgeDbacWithP2pTest, TestSize.Level1)
{
    WIFI_LOGI("JudgeDbacWithP2pTest enter");
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);

    WifiP2pLinkedInfo p2pLinkedInfo;
    p2pLinkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(p2pLinkedInfo), Return(0)))
        .WillRepeatedly(Return(0));
    WifiP2pGroupInfo wifiP2pGroupInfo;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetCurrentP2pGroupInfo())
        .WillOnce(DoAll(Return(wifiP2pGroupInfo)));
    m_apConfigUse->JudgeDbacWithP2p(apConfig);
}
} // namespace Wifi
} // namespace OHOS