/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_P2P_MANAGER_H
#define OHOS_WIFI_P2P_MANAGER_H

#ifdef FEATURE_P2P_SUPPORT
#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "ip2p_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class WifiP2pManager {
public:
    WifiP2pManager();
    ~WifiP2pManager() = default;

    IP2pServiceCallbacks& GetP2pCallback(void);
    ErrCode AutoStartP2pService();
    ErrCode AutoStopP2pService();
    void StopUnloadP2PSaTimer(void);
    void StartUnloadP2PSaTimer(void);
    void CloseP2pService(void);

private:
    void InitP2pCallback(void);
    void DealP2pStateChanged(P2pState bState);
    void DealP2pPeersChanged(const std::vector<WifiP2pDevice> &vPeers);
    void DealP2pServiceChanged(const std::vector<WifiP2pServiceInfo> &vServices);
    void DealP2pConnectionChanged(const WifiP2pLinkedInfo &info);
    void DealP2pThisDeviceChanged(const WifiP2pDevice &info);
    void DealP2pDiscoveryChanged(bool bState);
    void DealP2pGroupsChanged(void);
    void DealP2pActionResult(P2pActionCallback action, ErrCode code);
    void DealConfigChanged(CfgType type, char* data, int dataLen);
    void DealP2pGcJoinGroup(const GcInfo &info);
    void DealP2pGcLeaveGroup(const GcInfo &info);
    void IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);

private:
    IP2pServiceCallbacks mP2pCallback;
    uint32_t unloadP2PSaTimerId{0};
    std::mutex unloadP2PSaTimerMutex;
    std::string ifaceName{""};
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_P2P_MANAGER_H