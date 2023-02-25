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
#include <gmock/gmock.h>
#include "securec.h"
#include "if_config.h"

using namespace testing::ext;
namespace OHOS {
namespace Wifi {
class IfconfigTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(IfconfigTest, AddIpAddr_Fail1, TestSize.Level1)
{
    std::string ifName = "";
    std::string ipAddr = "";
    std::string mask = "";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV4);
    IfConfig::GetInstance().AddIpAddr(ifName, ipAddr, mask, ipType);
}

HWTEST_F(IfconfigTest, AddIpAddr_Success, TestSize.Level1)
{
    std::string ifName = "";
    std::string ipAddr = "";
    std::string mask = "";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV6);
    IfConfig::GetInstance().AddIpAddr(ifName, ipAddr, mask, ipType);
}

HWTEST_F(IfconfigTest, SetProxy_Fail1, TestSize.Level1)
{
    bool isAuto = false;
    IfConfig::GetInstance().SetProxy(isAuto, "proxy", "8080", "  ", "pac");
}

HWTEST_F(IfconfigTest, SetProxy_Success, TestSize.Level1)
{
    bool isAuto = true;
    IfConfig::GetInstance().SetProxy(isAuto, "proxy", "8080", "  ", "pac");
}
}  // namespace Wifi
}  // namespace OHOS


