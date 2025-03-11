/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
    mWifiDataReportService->apAllInfo.apDetailInfo.apMobile = 1;
    mWifiDataReportService->InitReportApAllInfo();
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.apMobile == -1);
    EXPECT_TRUE(mWifiDataReportService->lastPushTime.empty());
}

HWTEST_F(WifiDataReportServiceTest, GetUint32FromExt, TestSize.Level1)
{
    std::vector<uint8_t> ext = {0x01, 0x02, 0x03, 0x04};
    uint32_t result = mWifiDataReportService->GetUint32FromExt(ext, 0);
    EXPECT_EQ(result, 0x04030201);
}

HWTEST_F(WifiDataReportServiceTest, ConvertUint8ToUint16, TestSize.Level1)
{
    std::vector<uint8_t> uint8Vec = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint16_t> result = mWifiDataReportService->ConvertUint8ToUint16(uint8Vec);
    std::vector<uint16_t> expected = {(0x02 << 8) | 0x01, (0x04 << 8) | 0x03};
    EXPECT_EQ(result, expected);
}

HWTEST_F(WifiDataReportServiceTest, UpdateAppBundleNameInfo, TestSize.Level1)
{
    std::string appName = "Aiwifi";
    mWifiDataReportService->UpdateAppBundleNameInfo(appName);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.appName == appName);
}

HWTEST_F(WifiDataReportServiceTest, UpdateApLinkedInfo, TestSize.Level1)
{
    WifiLinkedInfo info;
    info.ssid = "TestSSID";
    info.bssid = "01:02:03:04:05:06";
    info.ifHiddenSSID = 1;
    info.wifiStandard = 1;
    info.maxSupportedRxLinkSpeed = 1;
    info.maxSupportedTxLinkSpeed = 1;
    info.channelWidth = WifiChannelWidth::WIDTH_80MHZ;
    info.supportedWifiCategory = WifiCategory::WIFI6;
    info.isMloConnected = 1;
    info.isDataRestricted = 1;
    mWifiDataReportService->UpdateApLinkedInfo(info);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.ssid == info.ssid);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.bssid == info.bssid);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.isHiddenSSID == info.ifHiddenSSID);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.wifiStandard == info.wifiStandard);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.maxSupportedRxLinkSpeed == info.maxSupportedRxLinkSpeed);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.maxSupportedTxLinkSpeed == info.maxSupportedTxLinkSpeed);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.channelWidth == info.channelWidth);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.supportedWifiCategory == info.supportedWifiCategory);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.isMloConnected == info.isMloConnected);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.apMobile == info.isDataRestricted);
}

HWTEST_F(WifiDataReportServiceTest, UpdateApSignalPollInfo, TestSize.Level1)
{
    WifiSignalPollInfo info;
    mWifiDataReportService->UpdateApSignalPollInfo(info);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apQoeInfo.txRate == info.txrate);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apQoeInfo.rxRate == info.rxrate);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apQoeInfo.chloadSelf == info.chloadSelf);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apQoeInfo.snr == info.snr);
}

HWTEST_F(WifiDataReportServiceTest, UpdateApConnEventTimepInfo, TestSize.Level1)
{
    mWifiDataReportService->UpdateApConnEventTimepInfo(ConnTimeType::STA_CONN_START);
    mWifiDataReportService->UpdateApConnEventTimepInfo(ConnTimeType::STA_DHCP_SUC);
    mWifiDataReportService->UpdateApConnEventTimepInfo(ConnTimeType::STA_DISCONN_SUC);
    EXPECT_TRUE(mWifiDataReportService->connEventTimepInfo.timepConnStart != 0);
    EXPECT_TRUE(mWifiDataReportService->connEventTimepInfo.timepDhcpSuc != 0);
    EXPECT_TRUE(mWifiDataReportService->connEventTimepInfo.timepDisconnSuc != 0);
}

HWTEST_F(WifiDataReportServiceTest, IsAdjacentChannel, TestSize.Level1)
{
    EXPECT_FALSE(mWifiDataReportService->IsAdjacentChannel(TEST_FREQUENCY_2_4G, TEST1_FREQUENCY_5G, WIFI_BAND));
    EXPECT_TRUE(mWifiDataReportService->IsAdjacentChannel(TEST2_FREQUENCY_5G, TEST1_FREQUENCY_5G, WIFI_BAND));
}

HWTEST_F(WifiDataReportServiceTest, ReportApConnEventInfo, TestSize.Level1)
{
    IEnhanceService *enhanceService_ = nullptr;
    WifiLinkedInfo info;
    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_SUC_START,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_SUC_START);

    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_DISCONNECTED,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_DISCONNECTED);
    mWifiDataReportService->InitReportApAllInfo();

    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_WRONG_PASSWORD,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_WRONG_PASSWORD);
    mWifiDataReportService->InitReportApAllInfo();

    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_AUTHENTICATION_FAILURE,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_AUTHENTICATION_FAILURE);
    mWifiDataReportService->InitReportApAllInfo();

    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_DHCP_FAILURE,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_DHCP_FAILURE);
    mWifiDataReportService->InitReportApAllInfo();

    mWifiDataReportService->apAllInfo.apDetailInfo.connFailedCount = CONN_FAILED_COUNT_THRESHOLD;
    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_FULL,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_ASSOCIATION_FULL);
    mWifiDataReportService->InitReportApAllInfo();

    mWifiDataReportService->apAllInfo.apDetailInfo.connFailedCount = CONN_FAILED_COUNT_THRESHOLD;
    mWifiDataReportService->ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_REJECTION,
        info, 1, 0, enhanceService_);
    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.reason == ConnReportReason::CONN_ASSOCIATION_REJECTION);

    EXPECT_TRUE(mWifiDataReportService->apAllInfo.apDetailInfo.disConnFlag == true);
}

HWTEST_F(WifiDataReportServiceTest, ReportQoeInfo, TestSize.Level1)
{
    IEnhanceService *enhanceService_ = nullptr;
    WifiSignalPollInfo info;
    mWifiDataReportService->apAllInfo.apDetailInfo.bssid = "01:02:03:04:05:06";
    mWifiDataReportService->ReportQoeInfo(info, enhanceService_);
    auto it = mWifiDataReportService->lastPushTime.find(mWifiDataReportService->apAllInfo.apDetailInfo.bssid);
    EXPECT_NE(it, mWifiDataReportService->lastPushTime.end());
}

}
}