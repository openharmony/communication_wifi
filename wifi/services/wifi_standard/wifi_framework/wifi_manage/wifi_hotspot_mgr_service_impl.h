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

#ifndef OHOS_WIFI_HOTSPOT_MGR_SERVICE_IMPL_H
#define OHOS_WIFI_HOTSPOT_MGR_SERVICE_IMPL_H

#include <file_ex.h>
#include "iremote_object.h"
#include "system_ability.h"
#include "wifi_errcode.h"
#include "wifi_hotspot_mgr_stub.h"
#include "wifi_hotspot_stub.h"

namespace OHOS {
namespace Wifi {
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class WifiHotspotMgrServiceImpl : public SystemAbility, public WifiHotspotMgrStub {
    DECLARE_SYSTEM_ABILITY(WifiHotspotMgrServiceImpl);
public:
    WifiHotspotMgrServiceImpl();
    virtual ~WifiHotspotMgrServiceImpl();
    static sptr<WifiHotspotMgrServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
    sptr<IRemoteObject> GetWifiRemote(int id) override;

    /**
     * @Description dump hotspot information
     *
     * @param fd - file descriptor
     * @param args - dump arguments
     * @return ErrCode - operation result
     */
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;

private:
    bool Init();
    friend void SigHandler(int sig);
    friend bool IsProcessNeedToRestart();
    static sptr<WifiHotspotMgrServiceImpl> g_instance;
    std::map<int, sptr<IRemoteObject>> mWifiService;
    static std::mutex g_instanceLock;
    bool mPublishFlag;
    ServiceRunningState mState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif