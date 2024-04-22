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
#include "wifi_internal_event_dispatcher_test.h"
#include "wifi_internal_event_dispatcher.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
/**
 * @tc.name: Events notify test
 * @tc.desc: Events notify test function.
 * @tc.type: FUNC
 * @tc.require: issueI5LC60
 */
HWTEST_F(WifiInternalEventDispatcherTest, ThreadTest, TestSize.Level1)
{
    WifiInternalEventDispatcher instance;
    WifiEventCallbackMsg msg;
    msg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_RSSI_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_JOIN;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_STREAM_DIRECTION;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = WIFI_CBK_MSG_WPS_STATE_CHANGE;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
    msg.msgCode = 0xffff;
    WifiInternalEventDispatcher::GetInstance().Run(instance, msg);
}

HWTEST_F(WifiInternalEventDispatcherTest, InitExitTest, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, WifiInternalEventDispatcher::GetInstance().Init());
    sleep(1);
    WifiInternalEventDispatcher::GetInstance().Exit();
}

HWTEST_F(WifiInternalEventDispatcherTest, SendSystemNotify, TestSize.Level1)
{
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().SendSystemNotifyMsg());
}

HWTEST_F(WifiInternalEventDispatcherTest, AddStaCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    sptr<IWifiDeviceCallBack> callback;
    int pid = 0;
    EXPECT_EQ(3, WifiInternalEventDispatcher::GetInstance().AddStaCallback(remote, callback, pid,
        EVENT_STA_POWER_STATE_CHANGE, 0));
}

HWTEST_F(WifiInternalEventDispatcherTest, RemoveStaCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().RemoveStaCallback(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, SetSingleStaCallbackSuccess, TestSize.Level1)
{
    sptr<IWifiDeviceCallBack> callback;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().SetSingleStaCallback(callback,
        EVENT_STA_POWER_STATE_CHANGE));
}

HWTEST_F(WifiInternalEventDispatcherTest, GetSingleStaCallback, TestSize.Level1)
{
    EXPECT_EQ(nullptr, WifiInternalEventDispatcher::GetInstance().GetSingleStaCallback());
}

HWTEST_F(WifiInternalEventDispatcherTest, HasStaRemote, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_FALSE(WifiInternalEventDispatcher::GetInstance().HasStaRemote(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, AddScanCallback, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    sptr<IWifiScanCallback> callback;
    int pid = 0;
    EXPECT_EQ(WIFI_OPT_INVALID_PARAM, WifiInternalEventDispatcher::GetInstance().AddScanCallback(remote, callback, pid,
        EVENT_STA_SCAN_STATE_CHANGE, 0));
}

HWTEST_F(WifiInternalEventDispatcherTest, RemoveScanCallback, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_EQ(WIFI_OPT_SUCCESS, WifiInternalEventDispatcher::GetInstance().RemoveScanCallback(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, SetSingleScanCallbackSuccess, TestSize.Level1)
{
    sptr<IWifiScanCallback> callback;
    EXPECT_EQ(WIFI_OPT_SUCCESS, WifiInternalEventDispatcher::GetInstance().SetSingleScanCallback(callback,
        EVENT_STA_SCAN_STATE_CHANGE));
}

HWTEST_F(WifiInternalEventDispatcherTest, GetSingleScanCallbackSuccess, TestSize.Level1)
{
    EXPECT_EQ(nullptr, WifiInternalEventDispatcher::GetInstance().GetSingleScanCallback());
}

HWTEST_F(WifiInternalEventDispatcherTest, HasScanRemoteFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_EQ(false, WifiInternalEventDispatcher::GetInstance().HasScanRemote(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, AddHotspotCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    sptr<IWifiHotspotCallback> callback;
    int id = 0;
    EXPECT_EQ(3, WifiInternalEventDispatcher::GetInstance().AddHotspotCallback(remote, callback,
        EVENT_HOTSPOT_STATE_CHANGE, id));
}

HWTEST_F(WifiInternalEventDispatcherTest, RemoveHotspotCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    int id = 0;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().RemoveHotspotCallback(remote, id));
}

HWTEST_F(WifiInternalEventDispatcherTest, SetSingleHotspotSuccess, TestSize.Level1)
{
    sptr<IWifiHotspotCallback> callback;
    int id = 0;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().SetSingleHotspotCallback(callback, id));
}

HWTEST_F(WifiInternalEventDispatcherTest, GetSingleHotspotCallback, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(nullptr, WifiInternalEventDispatcher::GetInstance().GetSingleHotspotCallback(id));
}

HWTEST_F(WifiInternalEventDispatcherTest, HasHotspotRemoteFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    int id = 0;
    EXPECT_EQ(false, WifiInternalEventDispatcher::GetInstance().HasHotspotRemote(remote, id));
}

HWTEST_F(WifiInternalEventDispatcherTest, SetSingleP2pCallback, TestSize.Level1)
{
    sptr<IWifiP2pCallback> callback;
    EXPECT_FALSE(WifiInternalEventDispatcher::GetInstance().SetSingleP2pCallback(callback));
}

HWTEST_F(WifiInternalEventDispatcherTest, AddP2pCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    sptr<IWifiP2pCallback> callback;
    EXPECT_EQ(3, WifiInternalEventDispatcher::GetInstance().AddP2pCallback(remote, callback, 123, EVENT_P2P_STATE_CHANGE, 0));
}

HWTEST_F(WifiInternalEventDispatcherTest, RemoveP2pCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().RemoveP2pCallback(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, ExitFail, TestSize.Level1)
{
    WifiInternalEventDispatcher::GetInstance().Exit();
}
}  // namespace Wifi
}  // namespace OHOS