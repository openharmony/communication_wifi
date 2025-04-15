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

#include "select_network_data_report_test.h"
#include "sta_sm_ext.h"
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

constexpr uint16_t TEST_FREQUENCY_2_4G = 2412;
constexpr uint16_t TEST1_FREQUENCY_5G = 5180;
constexpr uint16_t TEST2_FREQUENCY_5G = 5200;
constexpr uint16_t WIFI_BAND = 2;

HWTEST_F(WifiDataReportServiceTest, InitReportApAllInfo, TestSize.Level1)
{
    mWifiDataReportService_.disConnFlag_ = true;
    mWifiDataReportService_.InitReportApAllInfo();
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == false);
    EXPECT_TRUE(mWifiDataReportService_.lastPushTime_.empty());
}

HWTEST_F(WifiDataReportServiceTest, GetUint32FromExt, TestSize.Level1)
{
    std::vector<uint8_t> ext = {0x01, 0x02, 0x03, 0x04};
    uint32_t result = mWifiDataReportService_.GetUint32FromExt(ext, 0);
    EXPECT_EQ(result, 0x04030201);
}

HWTEST_F(WifiDataReportServiceTest, ConvertUint8ToUint16, TestSize.Level1)
{
    std::vector<uint8_t> uint8Vec = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint16_t> result = mWifiDataReportService_.ConvertUint8ToUint16(uint8Vec);
    std::vector<uint16_t> expected = {(0x02 << 8) | 0x01, (0x04 << 8) | 0x03};
    EXPECT_EQ(result, expected);
}

HWTEST_F(WifiDataReportServiceTest, UpdateForegroundBundleName, TestSize.Level1)
{
    WifiCrowdsourcedDetailInfo apDetailInfo;
    apDetailInfo.appName = "Aiwifi";
    mWifiDataReportService_.UpdateForegroundBundleName(apDetailInfo);
    EXPECT_TRUE(apDetailInfo.appName != "Aiwifi");
}

HWTEST_F(WifiDataReportServiceTest, UpdateCrowdsourcedDetailInfo, TestSize.Level1)
{
    WifiCrowdsourcedDetailInfo apDetailInfo;
    WifiLinkedInfo info;
    WifiDeviceConfig apDeviceInfo;
    apDeviceInfo.isPortal = 0;
    info.ssid = "TestSSID";
    info.bssid = "01:02:03:04:05:06";
    info.ifHiddenSSID = 1;
    info.wifiStandard = 1;
    info.maxSupportedRxLinkSpeed = 1;
    info.maxSupportedTxLinkSpeed = 1;
    apDeviceInfo.channel = 0;
    info.supportedWifiCategory = WifiCategory::WIFI6;
    info.isMloConnected = 1;
    info.isDataRestricted = 1;
    mWifiDataReportService_.UpdateCrowdsourcedDetailInfo(apDetailInfo, info, apDeviceInfo);
    EXPECT_TRUE(apDetailInfo.ssid == info.ssid);
    EXPECT_TRUE(apDetailInfo.bssid == info.bssid);
    EXPECT_TRUE(apDetailInfo.isHiddenSSID == info.ifHiddenSSID);
    EXPECT_TRUE(apDetailInfo.wifiStandard == info.wifiStandard);
    EXPECT_TRUE(apDetailInfo.maxSupportedRxLinkSpeed == info.maxSupportedRxLinkSpeed);
    EXPECT_TRUE(apDetailInfo.maxSupportedTxLinkSpeed == info.maxSupportedTxLinkSpeed);
    EXPECT_TRUE(apDetailInfo.channelWidth == apDeviceInfo.channel);
    EXPECT_TRUE(apDetailInfo.supportedWifiCategory == info.supportedWifiCategory);
    EXPECT_TRUE(apDetailInfo.isMloConnected == info.isMloConnected);
    EXPECT_TRUE(apDetailInfo.apMobile == info.isDataRestricted);
    EXPECT_TRUE(apDetailInfo.isPortal == apDeviceInfo.isPortal);
}

HWTEST_F(WifiDataReportServiceTest, ParseSignalPollInfo, TestSize.Level1)
{
    WifiSignalPollInfo info;
    info.txrate = 1;
    info.rxrate = 1;
    info.chloadSelf = 1;
    info.snr = 1;
    WifiCrowdsourcedQoeInfo parseInfo;
    mWifiDataReportService_.ParseSignalPollInfo(parseInfo, info);
    EXPECT_TRUE(parseInfo.txRate == info.txrate);
    EXPECT_TRUE(parseInfo.rxRate == info.rxrate);
    EXPECT_TRUE(parseInfo.chloadSelf == info.chloadSelf);
    EXPECT_TRUE(parseInfo.snr == info.snr);
}

HWTEST_F(WifiDataReportServiceTest, UpdateApConnEventTimepInfo, TestSize.Level1)
{
    mWifiDataReportService_.UpdateApConnEventTimepInfo(ConnTimeType::STA_CONN_START);
    mWifiDataReportService_.UpdateApConnEventTimepInfo(ConnTimeType::STA_DHCP_SUC);
    mWifiDataReportService_.UpdateApConnEventTimepInfo(ConnTimeType::STA_DISCONN_SUC);
    EXPECT_TRUE(mWifiDataReportService_.connEventTimepInfo_.timepConnStart != 0);
    EXPECT_TRUE(mWifiDataReportService_.connEventTimepInfo_.timepDhcpSuc != 0);
    EXPECT_TRUE(mWifiDataReportService_.connEventTimepInfo_.timepDisconnSuc != 0);
}

HWTEST_F(WifiDataReportServiceTest, IsAdjacentChannel, TestSize.Level1)
{
    EXPECT_FALSE(mWifiDataReportService_.IsAdjacentChannel(TEST_FREQUENCY_2_4G, TEST1_FREQUENCY_5G, WIFI_BAND));
    EXPECT_TRUE(mWifiDataReportService_.IsAdjacentChannel(TEST2_FREQUENCY_5G, TEST1_FREQUENCY_5G, WIFI_BAND));
}

HWTEST_F(WifiDataReportServiceTest, ReportApConnEventInfo, TestSize.Level1)
{
    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_SUC_START, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == false);

    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_DISCONNECTED, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == true);
    mWifiDataReportService_.InitReportApAllInfo();

    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_WRONG_PASSWORD, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == true);
    mWifiDataReportService_.InitReportApAllInfo();

    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_AUTHENTICATION_FAILURE, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == true);
    mWifiDataReportService_.InitReportApAllInfo();

    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_FULL, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == true);
    mWifiDataReportService_.InitReportApAllInfo();

    mWifiDataReportService_.ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_REJECTION, 0);
    EXPECT_TRUE(mWifiDataReportService_.disConnFlag_ == true);
}

HWTEST_F(WifiDataReportServiceTest, ReportQoeInfo, TestSize.Level1)
{
    WifiSignalPollInfo info;
    info.txrate = 1;
    mWifiDataReportService_.ReportQoeInfo(info, ConnReportReason::CONN_SUC_KEEP, 0);
    EXPECT_TRUE(mWifiDataReportService_.historyData_.size() == 1);
}

}
}