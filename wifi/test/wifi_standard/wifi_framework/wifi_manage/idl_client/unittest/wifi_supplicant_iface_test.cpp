/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "../../..//services/wifi_standard/wifi_framework/wifi_manage/idl_client/idl_interface/i_wifi_supplicant_iface.h"
#include "../../..//services/wifi_standard/wifi_framework/wifi_manage/idl_client/idl_interface/i_wifi_public_func.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define BUFSIZE 1
#define NETWORKID 1
#define ENABLE 1
#define CODESIZE 1

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiSupplicantifaceTest : public testing::Test{
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};

    void RpcClientCallTest()
    {
        RpcClient* client = nullptr;
        char* func = nullptr;
        RpcClientCall(client, func);
    }

    void StartSupplicantTest()
    {
        StartSupplicant();
    }

	void StopSupplicantTest()
    {
        StopSupplicant();
    }

    void ConnectSupplicantTest()
    {
        ConnectSupplicant();
    }

    void DisconnectSupplicantTest()
    {
        DisconnectSupplicant();
    }

    void RequestToSupplicantTest()
    {
        char* buf = nullptr;
        int32_t bufsize = BUFSIZE;
        RequestToSupplicant((unsigned char*)buf, bufsize);
    }

    void RegisterSupplicantEventCallbackTest()
    {
        ISupplicantEventCallback callback;
        RegisterSupplicantEventCallback(callback);
    }

    void ConnectTest()
    {
        int networkId = NETWORKID;
        Connect(networkId);
    }

    void ReconnectTest()
    {
        Reconnect();
    }

    void DisconnectTest()
    {
        Disconnect();
    }

    void SetPowerSaveTest()
    {
        int enable = ENABLE;
        SetPowerSave(enable);
    }

    void WpaSetCountryCodeTest()
    {
        char* countryCode = nullptr;
        WpaSetCountryCode(countryCode);
    }

    void WpaGetCountryCodeTest()
    {
        char* countryCode = nullptr;
        int codesize = CODESIZE;
        WpaGetCountryCode(countryCode, codesize);
    }
};	

HWTEST_F(WifiSupplicantifaceTest, RpcClientCallTest, TestSize.Level1)
{
    RpcClientCallTest();
}

HWTEST_F(WifiSupplicantifaceTest, StartSupplicantTest, TestSize.Level1)
{
    StartSupplicantTest();
}

HWTEST_F(WifiSupplicantifaceTest, StopSupplicantTest, TestSize.Level1)
{
    StopSupplicantTest();
}

HWTEST_F(WifiSupplicantifaceTest, ConnectSupplicantTest, TestSize.Level1)
{
    ConnectSupplicantTest();
}

HWTEST_F(WifiSupplicantifaceTest, DisconnectSupplicantTest, TestSize.Level1)
{
    DisconnectSupplicantTest();
}

HWTEST_F(WifiSupplicantifaceTest, RequestToSupplicantTest, TestSize.Level1)
{
    RequestToSupplicantTest();
}

HWTEST_F(WifiSupplicantifaceTest, ConnectTest, TestSize.Level1)
{
    ConnectTest();
}

HWTEST_F(WifiSupplicantifaceTest, ReconnectTest, TestSize.Level1)
{
    ReconnectTest();
}

HWTEST_F(WifiSupplicantifaceTest, DisconnectTest, TestSize.Level1)
{
    DisconnectTest();
}

HWTEST_F(WifiSupplicantifaceTest, SetPowerSaveTest, TestSize.Level1)
{
    SetPowerSaveTest();
}

HWTEST_F(WifiSupplicantifaceTest, WpaSetCountryCodeTest, TestSize.Level1)
{
    WpaSetCountryCodeTest();
}

HWTEST_F(WifiSupplicantifaceTest, WpaGetCountryCodeTest, TestSize.Level1)
{
    WpaGetCountryCodeTest();
}

}  // namespace Wifi
}  // namespace OHOS
