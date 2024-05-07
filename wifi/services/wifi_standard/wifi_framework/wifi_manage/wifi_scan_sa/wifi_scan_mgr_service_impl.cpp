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

#include "wifi_scan_mgr_service_impl.h"
#include "wifi_scan_service_impl.h"
#include "wifi_logger.h"
#include "wifi_dumper.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiScanMgrServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex WifiScanMgrServiceImpl::g_instanceLock;
sptr<WifiScanMgrServiceImpl> WifiScanMgrServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    WifiScanMgrServiceImpl::GetInstance().GetRefPtr());

sptr<WifiScanMgrServiceImpl> WifiScanMgrServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            sptr<WifiScanMgrServiceImpl> service = new (std::nothrow) WifiScanMgrServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}

WifiScanMgrServiceImpl::WifiScanMgrServiceImpl()
    : SystemAbility(WIFI_SCAN_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiScanMgrServiceImpl::~WifiScanMgrServiceImpl()
{}

void WifiScanMgrServiceImpl::OnStart()
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
    WIFI_LOGI("Start scan service!");
    if (WifiManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiManager init failed!");
        return;
    }
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
    auto &pWifiScanManager = WifiManager::GetInstance().GetWifiScanManager();
    if (scanState == WifiOprMidState::CLOSED && pWifiScanManager) {
        pWifiScanManager->StartUnloadScanSaTimer();
    }
    return;
}

void WifiScanMgrServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop scan service!");
}

bool WifiScanMgrServiceImpl::Init()
{
    if (!mPublishFlag) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; i++) {
            sptr<WifiScanServiceImpl> wifi = new WifiScanServiceImpl(i);
            if (wifi == nullptr) {
                WIFI_LOGE("create scan service id %{public}d failed!", i);
                return false;
            }
            mWifiService[i] = wifi->AsObject();
        }

        bool ret = Publish(WifiScanMgrServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish sta service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

sptr<IRemoteObject> WifiScanMgrServiceImpl::GetWifiRemote(int instId)
{
    auto iter = mWifiService.find(instId);
    if (iter != mWifiService.end()) {
        return mWifiService[instId];
    }
    return nullptr;
}

std::map<int, sptr<IRemoteObject>>& WifiScanMgrServiceImpl::GetScanServiceMgr()
{
    return mWifiService;
}

#ifndef OHOS_ARCH_LITE
int32_t WifiScanMgrServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter scan dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.ScanDump(WifiScanServiceImpl::SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi scan save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}
#endif
}  // namespace Wifi
}  // namespace OHOS