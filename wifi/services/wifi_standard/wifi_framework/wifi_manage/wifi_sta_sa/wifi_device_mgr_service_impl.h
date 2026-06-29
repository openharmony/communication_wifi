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

enum WifiSvcCmd {
    CMD_UNKNOWN,
    CMD_HELP,
    CMD_ENABLE,
    CMD_DISABLE,
    CMD_SCAN,
    CMD_CONNECT,
    CMD_LIST_SCAN_RESULT
};

class WifiDeviceMgrServiceImpl : public SystemAbility, public WifiDeviceMgrStub {
    DECLARE_SYSTEM_ABILITY(WifiDeviceMgrServiceImpl);
public:
    WifiDeviceMgrServiceImpl();
    virtual ~WifiDeviceMgrServiceImpl();
    static sptr<WifiDeviceMgrServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
    int32_t OnExtension(const std::string& extension, MessageParcel& data, MessageParcel& reply) override;
    sptr<IRemoteObject> GetWifiRemote(int instId) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    std::map<int, sptr<IRemoteObject>>& GetDeviceServiceMgr();
    int32_t OnSvcCmd(int32_t fd, const std::vector<std::u16string>& args) override;

private:
    int32_t HandleHelpCmd(int32_t fd, std::string& info);
    int32_t HandleEnableCmd(int32_t fd, std::string& info);
    int32_t HandleDisableCmd(int32_t fd, std::string& info);
    int32_t HandleScanCmd(int32_t fd, std::string& info);
    WifiDeviceConfig SvcMakeConfig(const std::vector<std::u16string>& args);
    int32_t HandleConnectCmd(int32_t fd, std::string& info,
        const std::vector<std::u16string>& args);
    int32_t HandleScanListCmd(int32_t fd, std::string& info);

private:
    bool Init();
    static sptr<WifiDeviceMgrServiceImpl> g_instance;
    std::map<int, sptr<IRemoteObject>> mWifiService;
    static std::mutex g_instanceLock;
    static std::mutex g_initMutex;
    bool mPublishFlag;
    ServiceRunningState mState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif