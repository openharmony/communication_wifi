/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "wifi_hid2d_service_utils.h"
#include "mock_wifi_hid2d_service_utils.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
std::string gcMac;
std::string serverIp;
class WifiHid2dServiceUtilsTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pIpPool.reset(new IpPool);
        pSharedLinkManager.reset(new SharedLinkManager);
    }
    virtual void TearDown()
    {
        pIpPool.reset();
        pSharedLinkManager.reset();
    }

public:
    std::unique_ptr<IpPool> pIpPool;
    std::unique_ptr<SharedLinkManager> pSharedLinkManager;
};

HWTEST_F(WifiHid2dServiceUtilsTest, InitIpPool, TestSize.Level1)
{
    pIpPool->GetIp(gcMac);
    EXPECT_EQ(pIpPool->InitIpPool(serverIp), true);
}

HWTEST_F(WifiHid2dServiceUtilsTest, SetGroupUid, TestSize.Level1)
{
    pSharedLinkManager->ClearSharedLinkCount();
    int callingUid = 1;
    pSharedLinkManager->SetGroupUid(callingUid);
    int getCallingUid;
    pSharedLinkManager->GetGroupUid(getCallingUid);
    EXPECT_EQ(getCallingUid, callingUid);
    pSharedLinkManager->SetGroupUid(callingUid + 1);
    pSharedLinkManager->GetGroupUid(getCallingUid);
    EXPECT_EQ(getCallingUid, callingUid);
    pSharedLinkManager->ClearSharedLinkCount();
    pSharedLinkManager->GetGroupUid(getCallingUid);
    EXPECT_EQ(getCallingUid, -1);
}

HWTEST_F(WifiHid2dServiceUtilsTest, IncreaseSharedLink, TestSize.Level1)
{
    pSharedLinkManager->ClearSharedLinkCount();
    int callingUid = 1;
    int count = 1;
    pSharedLinkManager->SetGroupUid(callingUid);
    pSharedLinkManager->IncreaseSharedLink();
    EXPECT_EQ(pSharedLinkManager->GetSharedLinkCount(), count);
    pSharedLinkManager->IncreaseSharedLink(callingUid);
    EXPECT_EQ(pSharedLinkManager->GetSharedLinkCount(), count + 1);
    pSharedLinkManager->DecreaseSharedLink(callingUid);
    EXPECT_EQ(pSharedLinkManager->GetSharedLinkCount(), count);
    pSharedLinkManager->ClearSharedLinkCount();
    EXPECT_EQ(pSharedLinkManager->GetSharedLinkCount(), 0);
}
}
}
