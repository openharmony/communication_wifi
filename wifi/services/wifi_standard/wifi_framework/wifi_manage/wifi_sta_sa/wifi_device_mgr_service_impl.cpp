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
const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
std::mutex WifiDeviceMgrServiceImpl::g_instanceLock;
std::mutex WifiDeviceMgrServiceImpl::g_initMutex;
sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    WifiDeviceMgrServiceImpl::GetInstance().GetRefPtr());

sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            sptr<WifiDeviceMgrServiceImpl> service = sptr<WifiDeviceMgrServiceImpl>::MakeSptr();
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
    WIFI_LOGI("Start sta service!");
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    if (WifiManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiManager init failed!");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
    auto &pWifiStaManager = WifiManager::GetInstance().GetWifiStaManager();
    if (pWifiStaManager) {
        pWifiStaManager->StartUnloadStaSaTimer();
    }
}

void WifiDeviceMgrServiceImpl::OnStop()
{
    std::lock_guard<std::mutex> lock(g_initMutex);
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop sta service!");
}

bool WifiDeviceMgrServiceImpl::Init()
{
    std::lock_guard<std::mutex> lock(g_initMutex);
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
    std::lock_guard<std::mutex> lock(g_initMutex);
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

int32_t WifiDeviceMgrServiceImpl::OnExtension(const std::string& extension, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGI("extension is %{public}s.", extension.c_str());
    if (extension == EXTENSION_BACKUP) {
        return WifiDeviceServiceImpl::OnBackup(data, reply);
    } else if (extension == EXTENSION_RESTORE) {
        return WifiDeviceServiceImpl::OnRestore(data, reply);
    }
    return 0;
}

int32_t WifiDeviceMgrServiceImpl::OnSvcCmd(int32_t fd, const std::vector<std::u16string>& args)
{
    int32_t instIdWlan0 = 0;
    int32_t svcResult = -1;
    std::string info = "svc wifi help:\n"
                " svc wifi enable: enable wifi device\n"
                " svc wifi disable: disable wifi device\n";

    std::lock_guard<std::mutex> lock(g_initMutex);
    sptr<WifiDeviceServiceImpl> impl = nullptr;
    if (mWifiService.find(instIdWlan0) != mWifiService.end() && mWifiService[instIdWlan0] != nullptr) {
        impl = iface_cast<WifiDeviceServiceImpl>(mWifiService[instIdWlan0]);
    }
    if (!impl || args.size() != 1) {
        info = !impl ? "wifi service in invalid state\n" : "wrong parameter size\n" + info;
        if (!SaveStringToFd(fd, info)) {
            WIFI_LOGE("WiFi device save string to fd failed.");
        }
        return svcResult;
    }

    std::string cmd = Str16ToStr8(args[0]);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    WIFI_LOGI("svc command is %{public}s.", cmd.c_str());
    if (cmd == "help") {
        svcResult = 0;
    } else if (cmd == "enable") {
        if (impl->EnableWifi() == WIFI_OPT_SUCCESS) {
            info = "wifi enable success\n";
            svcResult = 0;
        } else {
            info = "wifi enable fail\n";
        }
    } else if (cmd == "disable") {
        if (impl->DisableWifi() == WIFI_OPT_SUCCESS) {
            info = "wifi disable success\n";
            svcResult = 0;
        } else {
            info = "wifi disable fail\n";
        }
    }

    if (!SaveStringToFd(fd, info)) {
        WIFI_LOGE("WiFi device save string to fd failed.");
    }
    return svcResult;
}
#endif
}  // namespace Wifi
}  // namespace OHOS