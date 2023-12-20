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

#ifndef OHOS_WIFI_DEVICE_MGR_SERVICE_IMPL_H
#define OHOS_WIFI_DEVICE_MGR_SERVICE_IMPL_H

#ifndef OHOS_ARCH_LITE
#include "iremote_object.h"
#include "system_ability.h"
#include "wifi_errcode.h"
#include "wifi_device_mgr_stub.h"
#include "wifi_device_stub.h"

namespace OHOS {
namespace Wifi {
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class WifiDeviceMgrServiceImpl : public SystemAbility, public WifiDeviceMgrStub {
    DECLARE_SYSTEM_ABILITY(WifiDeviceMgrServiceImpl);
public:
    WifiDeviceMgrServiceImpl();
    virtual ~WifiDeviceMgrServiceImpl();
    static sptr<WifiDeviceMgrServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
    sptr<IRemoteObject> GetWifiRemote(int instId) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    std::map<int, sptr<IRemoteObject>>& GetDeviceServiceMgr();

private:
    bool Init();
    static sptr<WifiDeviceMgrServiceImpl> g_instance;
    std::map<int, sptr<IRemoteObject>> mWifiService;
    static std::mutex g_instanceLock;
    bool mPublishFlag;
    ServiceRunningState mState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif