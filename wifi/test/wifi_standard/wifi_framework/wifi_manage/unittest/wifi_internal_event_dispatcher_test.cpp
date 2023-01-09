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
#include "permission_def.h"

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
    WifiEventCallbackMsg msg;
    msg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_RSSI_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_JOIN;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_STREAM_DIRECTION;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = WIFI_CBK_MSG_WPS_STATE_CHANGE;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(1);
    msg.msgCode = 0xffff;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(msg));
    sleep(2);
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
    EXPECT_EQ(1, WifiInternalEventDispatcher::GetInstance().AddStaCallback(remote, callback, pid));
}

HWTEST_F(WifiInternalEventDispatcherTest, RemoveStaCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().RemoveStaCallback(remote));
}

HWTEST_F(WifiInternalEventDispatcherTest, GetSingleStaCallbackSuccess, TestSize.Level1)
{
    sptr<IWifiDeviceCallBack> callback;
    EXPECT_EQ(0, WifiInternalEventDispatcher::GetInstance().SetSingleStaCallback(callback));
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
    EXPECT_EQ(true, WifiInternalEventDispatcher::GetInstance().AddHotspotCallback(remote, callback, id));
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

HWTEST_F(WifiInternalEventDispatcherTest, HasHotspotRemoteFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    int id = 0;
    EXPECT_EQ(false, WifiInternalEventDispatcher::GetInstance().HasHotspotRemote(remote, id));
}

HWTEST_F(WifiInternalEventDispatcherTest, AddP2pCallbackFail, TestSize.Level1)
{
    sptr<IRemoteObject> remote;
    sptr<IWifiP2pCallback> callback;
    EXPECT_EQ(1, WifiInternalEventDispatcher::GetInstance().AddP2pCallback(remote, callback));
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