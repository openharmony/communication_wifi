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
#ifndef OHOS_AP_SERVICE_H
#define OHOS_AP_SERVICE_H

#include "ap_define.h"
#include "wifi_internal_msg.h"
#include "wifi_message_queue.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
class ApService {
public:
    /**
     * @Description  Obtains a single g_instance.
     * @param None
     * @return Reference to singleton objects
     */
    static ApService &GetInstance();
    /**
     * @Description  Delete a single g_instance.
     * @param None
     * @return None
     */
    static void DeleteInstance();

    /**
     * @Description  Called after the AP dynamic library file is loaded.
     * @param mqUp - message queue to response
     * @return 0: success    -1: failed
     */
    int Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp);
    /**
     * @Description  Called when public module send message to AP
     * @param msg - delivered message
     * @return 0: success    -1: failed
     */
    int PushMsg(const WifiRequestMsgInfo *msg) const;

    /**
     * @Description  Called before the AP dynamic library file is uninstalled.
     * @param None
     * @return None
     */
    int UnInit(void) const;

    /**
     * @Description  Broadcasting the AP module status change
     * @param state - current status
     * @return None
     */
    void OnApStateChange(const ApState &state) const;

    /**
     * @Description  A new STA connection is reported.
     * @param info - detailed information about the connected STA
     * @return None
     */
    void OnHotspotStaJoin(const StationInfo &info) const;

    /**
     * @Description  Broadcasting the STA disconnection information.
     * @param info - detailed information about the disconnected STA
     * @return None
     */
    void OnHotspotStaLeave(const StationInfo &info) const;

private:
    ApService();
    ~ApService() = default;
    DISALLOW_COPY_AND_ASSIGN(ApService)

    /**
     * @Description  Sending response messages to the Service Management Module
     * @param upMsg - structure of response messages
     * @return None
     */
    void BroadcastMsg(const WifiResponseMsgInfo &upMsg) const;

    /**
     * @Description  open hotspot
     * @param None
     * @return None
     */
    void EnableHotspot() const;

    /**
     * @Description  close hotspot
     * @param None
     * @return None
     */
    void DisableHotspot() const;

    /**
     * @Description  set ap config
     * @param cfg - ap config
     * @return None
     */
    void SetHotspotConfig(const HotspotConfig &cfg) const;

    /**
     * @Description  add block list
     * @param stationInfo - sta infos
     * @return None
     */
    void AddBlockList(const StationInfo &stationInfo) const;

    /**
     * @Description  delete block list
     * @param stationInfo - sta infos
     * @return None
     */
    void DelBlockList(const StationInfo &stationInfo) const;

    /**
     * @Description  Disconnect a specified STA
     * @param stationInfo - sta infos
     * @return None
     */
    void DisconnetStation(const StationInfo &stationInfo) const;

private:
    WifiMessageQueue<WifiResponseMsgInfo> *mMsgQueueUp;
};
}  // namespace Wifi
}  // namespace OHOS

#endif