#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include "ip_qos_monitor.h"
#include "wifi_netlink.h"
#include "wifi_logger.h"

using namespace OHOS::Wifi;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

class IpQosMonitorTest : public testing::Test {
public:
    void SetUp() override
    {}

    void TearDown() override
    {}
    void OnTcpReportMsgCompleteTest(const std::vector<int64_t> &elems, const int32_t cmd, const int32_t mInstId)
    {
        LOGI("enter OnTcpReportMsgCompleteTest");
    }
};

HWTEST_F(IpQosMonitorTest, TestStartMonitor, TestSize.Level1)
{
    int32_t arg = 0;
    IpQosMonitor::GetInstance().StartMonitor(arg);
}

HWTEST_F(IpQosMonitorTest, TestQueryPackets, TestSize.Level1)
{
    int32_t arg = 0;
    using namespace std::placeholders;
    WifiNetLinkCallbacks mWifiNetLinkCallbacks;
    mWifiNetLinkCallbacks.OnTcpReportMsgComplete =
        std::bind(&IpQosMonitorTest::OnTcpReportMsgCompleteTest, this, _1, _2, _3);
    WifiNetLink::GetInstance().InitWifiNetLink(mWifiNetLinkCallbacks);
    IpQosMonitor::GetInstance().QueryPackets(arg);
}

HWTEST_F(IpQosMonitorTest, TestHandleTcpReportMsgComplete, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3};
    int32_t cmd = 0;
    IpQosMonitor::GetInstance().HandleTcpReportMsgComplete(elems, cmd);
}

HWTEST_F(IpQosMonitorTest, TestParseTcpReportMsg, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3};
    int32_t cmd = 123;
    IpQosMonitor::GetInstance().ParseTcpReportMsg(elems, cmd);
}

HWTEST_F(IpQosMonitorTest, TestHandleTcpPktsResp, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3};
    IpQosMonitor::GetInstance().HandleTcpPktsResp(elems);
}

HWTEST_F(IpQosMonitorTest, TestAllowSelfCureNetwork, TestSize.Level1)
{
    int32_t currentRssi = 123;
    IpQosMonitor::GetInstance().AllowSelfCureNetwork(currentRssi);
}

HWTEST_F(IpQosMonitorTest, TestParseNetworkInternetGood, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3};
    IpQosMonitor::GetInstance().ParseNetworkInternetGood(elems);
}