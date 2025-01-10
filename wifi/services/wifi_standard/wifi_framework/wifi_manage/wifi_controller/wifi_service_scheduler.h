/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SERVICE_SCHEDULER_H
#define OHOS_WIFI_SERVICE_SCHEDULER_H

#include <string>
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "sta_service_callback.h"
#include "iscan_service_callbacks.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service_callbacks.h"
#endif
#ifdef FEATURE_P2P_SUPPORT
#include "ip2p_service_callbacks.h"
#endif
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"
#include "wifi_service_manager.h"
#include "state.h"

namespace OHOS {
namespace Wifi {
class WifiServiceScheduler {
public:
    static WifiServiceScheduler &GetInstance();
    explicit WifiServiceScheduler();
    ~WifiServiceScheduler();
    ErrCode AutoStartStaService(int instId, std::string &staIfName, int type = 0);
    ErrCode AutoStartWifi2Service(int instId, std::string &staIfName);
    ErrCode AutoStopStaService(int instId, int type = 0);
    ErrCode AutoStopWifi2Service(int instId);
    ErrCode AutoStartScanOnly(int instId, std::string &staIfName);
    ErrCode AutoStopScanOnly(int instId, bool setIfaceDown);
    ErrCode AutoStartSemiStaService(int instId, std::string &staIfName);
    ErrCode AutoStartApService(int instId, std::string &softApIfName);
    ErrCode AutoStopApService(int instId);
    void DispatchWifiOpenRes(OperateResState state, int instId);
    void DispatchWifi2OpenRes(OperateResState state, int instId);
    void DispatchWifiSemiActiveRes(OperateResState state, int instId);
    void DispatchWifiCloseRes(OperateResState state, int instId);
    void DispatchWifi2CloseRes(OperateResState state, int instId);
    void ClearStaIfaceNameMap(int instId);
    void ClearP2pIfaceNameMap(int instId);
    void ClearSoftApIfaceNameMap(int instId);
    void SelfcureResetSta(int instId);

private:
    void BroadCastWifiStateChange(WifiState state, int instId);
    ErrCode PreStartWifi(int instId, std::string &staIfName);
    ErrCode PostStartWifi(int instId);
    ErrCode PostStartWifi2(int instId);
    ErrCode InitStaService(IStaService *pService, int instId);
    ErrCode StartWifiStaService(int instId);
    ErrCode StartDependentService(int instId);
    void HandleGetStaFailed(int instId);
#ifdef FEATURE_WIFI_PRO_SUPPORT
    ErrCode StartWifiProService(int instId);
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    ErrCode StartSelfCureService(int instId);
#endif
    ErrCode TryToStartApService(int instId);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    void StaIfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);
    void P2pIfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);
    void SoftApIfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);
    void OnRssiReportCallback(int index, int antRssi);
    void OnNetlinkReportCallback(int type, const std::vector<uint8_t>& recvMsg);
#endif
    std::map<int, std::string> staIfaceNameMap;
    std::map<int, std::string> softApIfaceNameMap;
    std::mutex mutex;
};
}
}
#endif