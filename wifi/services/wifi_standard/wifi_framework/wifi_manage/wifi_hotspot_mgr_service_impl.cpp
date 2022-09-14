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

#include <csignal>
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_dumper.h"
#include "wifi_manager.h"
#include "wifi_hotspot_mgr_service_impl.h"
#include "wifi_hotspot_service_impl.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotMgrServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex WifiHotspotMgrServiceImpl::g_instanceLock;
sptr<WifiHotspotMgrServiceImpl> WifiHotspotMgrServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    WifiHotspotMgrServiceImpl::GetInstance().GetRefPtr());

sptr<WifiHotspotMgrServiceImpl> WifiHotspotMgrServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            auto service = new (std::nothrow) WifiHotspotMgrServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}

WifiHotspotMgrServiceImpl::WifiHotspotMgrServiceImpl()
    : SystemAbility(WIFI_HOTSPOT_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiHotspotMgrServiceImpl::~WifiHotspotMgrServiceImpl()
{}

bool IsProcessNeedToRestart()
{
    sptr<WifiHotspotMgrServiceImpl> instancePtr = WifiHotspotMgrServiceImpl::GetInstance();
    if (instancePtr == nullptr) {
        return false;
    }
    for (auto it = instancePtr->mWifiService.begin(); it != instancePtr->mWifiService.end(); it++) {
        int id = it->first;
        if (WifiConfigCenter::GetInstance().GetApMidState(id) == WifiOprMidState::RUNNING) {
            return true;
        }
    }
    return false;
}

void SigHandler(int sig)
{
    WIFI_LOGI("[Ap] Recv SIG: %{public}d\n", sig);
    switch (sig) {
        case SIGUSR2:
            if (IsProcessNeedToRestart()) {
                IApServiceCallbacks cb = WifiManager::GetInstance().GetApCallback();
                sptr<WifiHotspotMgrServiceImpl> instancePtr = WifiHotspotMgrServiceImpl::GetInstance();
                if (cb.OnApStateChangedEvent != nullptr && instancePtr != nullptr) {
                    for (auto it = instancePtr->mWifiService.begin(); it != instancePtr->mWifiService.end(); it++) {
                        int id = it->first;
                        cb.OnApStateChangedEvent(ApState::AP_STATE_IDLE, id);
                    }
                }
                WIFI_LOGE("[AP] --------------Abort process to restart!!!--------------\n");
                abort();
            }
            break;

        default:
            break;
    }
}

void WifiHotspotMgrServiceImpl::OnStart()
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
    (void)signal(SIGUSR2, SigHandler);
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start ap service!");
    WifiManager::GetInstance().AddSupportedFeatures(WifiFeatures::WIFI_FEATURE_MOBILE_HOTSPOT);
}

void WifiHotspotMgrServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop ap service!");
}

bool WifiHotspotMgrServiceImpl::Init()
{
    if (!mPublishFlag) {
        for (int i = 0; i < AP_INSTANCE_MAX_NUM; i++) {
            sptr<WifiHotspotServiceImpl> wifi = new WifiHotspotServiceImpl(i);
            if (wifi == nullptr) {
                WIFI_LOGE("create ap hotspot service id %{public}d failed!", i);
                return false;
            }
            mWifiService[i] = wifi->AsObject();
        }

        bool ret = Publish(WifiHotspotMgrServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish hotspot service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

sptr<IRemoteObject> WifiHotspotMgrServiceImpl::GetWifiRemote(int id)
{
    auto iter = mWifiService.find(id);
    if (iter != mWifiService.end()) {
        return mWifiService[id];
    }
    return nullptr;
}

int32_t WifiHotspotMgrServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter hotspot dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.HotspotDump(WifiHotspotServiceImpl::SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi hotspot save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}
}  // namespace Wifi
}  // namespace OHOS
