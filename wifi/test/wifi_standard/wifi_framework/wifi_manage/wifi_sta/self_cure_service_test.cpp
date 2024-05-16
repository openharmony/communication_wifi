

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "self_cure_service.h"
#include "wifi_logger.h"
#include "self_cure_common.h"
#include "wifi_internal_msg.h"

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
class SelfCureServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureService = std::make_unique<SelfCureService>();
    }

    virtual void TearDown()
    {
        pSelfCureService.reset();
    }

    std::unique_ptr<SelfCureService> pSelfCureService;

    void InitSelfCureServiceTest()
    {
        pSelfCureService->InitSelfCureService();
    }

    void RegisterSelfCureServiceCallbackTest()
    {
        std::vector<SelfCureServiceCallback> callbacks;
        pSelfCureService->RegisterSelfCureServiceCallback(callbacks);
    }

    void HandleRssiLevelChangedTest()
    {
        int rssi = MIN_VAL_LEVEL_4;
        pSelfCureService->HandleRssiLevelChanged(rssi);
    }

    void HandleP2pConnChangedTest()
    {
        WifiP2pLinkedInfo info;
        pSelfCureService->HandleP2pConnChanged(info);
    }

    void HandleStaConnChangedTest()
    {
        OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }
};

HWTEST_F(SelfCureServiceTest, InitSelfCureServiceTest, TestSize.Level1)
{
    InitSelfCureServiceTest();
}

HWTEST_F(SelfCureServiceTest, RegisterSelfCureServiceCallbackTest, TestSize.Level1)
{
    RegisterSelfCureServiceCallbackTest();
}

HWTEST_F(SelfCureServiceTest, HandleRssiLevelChangedTest, TestSize.Level1)
{
    HandleRssiLevelChangedTest();
}

HWTEST_F(SelfCureServiceTest, HandleP2pConnChangedTest, TestSize.Level1)
{
    HandleP2pConnChangedTest();
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest, TestSize.Level1)
{
    HandleStaConnChangedTest();
}

} // namespace Wifi
} // namespace OHOS