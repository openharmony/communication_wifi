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

#include "wifi_device_mgr_service_impl.h"
#include "wifi_device_service_impl.h"
#include "wifi_logger.h"
#include "wifi_dumper.h"
#include "wifi_manager.h"
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiDeviceMgrServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex WifiDeviceMgrServiceImpl::g_instanceLock;
sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    WifiDeviceMgrServiceImpl::GetInstance().GetRefPtr());

sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            sptr<WifiDeviceMgrServiceImpl> service = new (std::nothrow) WifiDeviceMgrServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}

WifiDeviceMgrServiceImpl::WifiDeviceMgrServiceImpl()
    : SystemAbility(WIFI_DEVICE_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiDeviceMgrServiceImpl::~WifiDeviceMgrServiceImpl()
{}

void WifiDeviceMgrServiceImpl::OnStart()
{
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start sta service!");
    if (WifiManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiManager init failed!");
        return;
    }
    auto &pWifiStaManager = WifiManager::GetInstance().GetWifiStaManager();
    if (pWifiStaManager) {
        pWifiStaManager->StartUnloadStaSaTimer();
    }
    WifiDeviceServiceImpl::StartWatchdog();
}

void WifiDeviceMgrServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop sta service!");
}

bool WifiDeviceMgrServiceImpl::Init()
{
    if (!mPublishFlag) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; i++) {
            sptr<WifiDeviceServiceImpl> wifi = new WifiDeviceServiceImpl(i);
            if (wifi == nullptr) {
                WIFI_LOGE("create sta service id %{public}d failed!", i);
                return false;
            }
            mWifiService[i] = wifi->AsObject();
        }

        bool ret = Publish(WifiDeviceMgrServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish sta service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

sptr<IRemoteObject> WifiDeviceMgrServiceImpl::GetWifiRemote(int instId)
{
    auto iter = mWifiService.find(instId);
    if (iter != mWifiService.end()) {
        return mWifiService[instId];
    }
    return nullptr;
}

std::map<int, sptr<IRemoteObject>>& WifiDeviceMgrServiceImpl::GetDeviceServiceMgr()
{
    return mWifiService;
}

#ifndef OHOS_ARCH_LITE
int32_t WifiDeviceMgrServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter sta dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.DeviceDump(WifiDeviceServiceImpl::SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi device save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}
#endif
}  // namespace Wifi
}  // namespace OHOS