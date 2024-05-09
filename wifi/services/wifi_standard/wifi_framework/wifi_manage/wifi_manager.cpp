/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "wifi_manager.h"
#include <dirent.h>
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "wifi_country_code_manager.h"
#endif
#include "wifi_service_manager.h"
#include "wifi_common_def.h"
#include "wifi_common_util.h"
#include "wifi_common_service_manager.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiManager");

WifiManager &WifiManager::GetInstance()
{
    static WifiManager gWifiManager;
    return gWifiManager;
}

WifiManager::WifiManager() : mInitStatus(INIT_UNKNOWN), mSupportedFeatures(0)
{}

WifiManager::~WifiManager()
{
    Exit();
}

int WifiManager::Init()
{
    std::unique_lock<std::mutex> lock(initStatusMutex);
    if (mInitStatus == INIT_OK) {
        WIFI_LOGI("WifiManager already init!");
        return 0;
    }
    mInitStatus = WifiCommonServiceManager::GetInstance().Init();
    if (mInitStatus != INIT_OK) {
        WIFI_LOGE("WifiCommonServiceManager Init failed!");
        return -1;
    }

    if (WifiServiceManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiServiceManager Init failed!");
        mInitStatus = SERVICE_MANAGER_INIT_FAILED;
        return -1;
    }

    mCloseServiceThread = std::make_unique<WifiEventHandler>("CloseServiceThread");
#ifndef OHOS_ARCH_LITE
    wifiEventSubscriberManager = std::make_unique<WifiEventSubscriberManager>();
#endif
    wifiStaManager = std::make_unique<WifiStaManager>();
    wifiScanManager = std::make_unique<WifiScanManager>();
    wifiTogglerManager = std::make_unique<WifiTogglerManager>();
#ifdef FEATURE_AP_SUPPORT
    wifiHotspotManager = std::make_unique<WifiHotspotManager>();
#endif
#ifdef FEATURE_P2P_SUPPORT
    wifiP2pManager = std::make_unique<WifiP2pManager>();
#endif

    if (WifiServiceManager::GetInstance().CheckPreLoadService() < 0) {
        WIFI_LOGE("WifiServiceManager check preload feature service failed!");
        WifiManager::GetInstance().Exit();
        return -1;
    }
    mInitStatus = INIT_OK;

    if (WifiConfigCenter::GetInstance().GetStaLastRunState()) { /* Automatic startup upon startup */
        WIFI_LOGI("AutoStartServiceThread");
        WifiSettings::GetInstance().SetWifiToggledState(true);
        mStartServiceThread = std::make_unique<WifiEventHandler>("StartServiceThread");
        mStartServiceThread->PostAsyncTask([this]() {
            AutoStartServiceThread();
        });
    } else {
        /**
         * The sta service automatically starts upon startup. After the sta
         * service is started, the scanning is directly started.
         */
        if (WifiSettings::GetInstance().GetScanOnlySwitchState()) {
            WIFI_LOGI("Auto start scan only!");
            wifiTogglerManager->ScanOnlyToggled(1);
        }
#ifndef DTFUZZ_TEST
        AutoStartEnhanceService();
#endif
        wifiScanManager->CheckAndStartScanService();
    }
    InitPidfile();
    return 0;
}

void WifiManager::Exit()
{
    WIFI_LOGI("[WifiManager] Exit.");
    WifiServiceManager::GetInstance().UninstallAllService();
    PushServiceCloseMsg(WifiCloseServiceCode::SERVICE_THREAD_EXIT);
    if (mCloseServiceThread) {
        mCloseServiceThread.reset();
    }
    if (mStartServiceThread) {
        mStartServiceThread.reset();
    }
    if (wifiStaManager) {
        wifiStaManager.reset();
    }
    if (wifiScanManager) {
        wifiScanManager.reset();
    }
    if (wifiTogglerManager) {
        wifiTogglerManager.reset();
    }
#ifdef FEATURE_AP_SUPPORT
    if (wifiHotspotManager) {
        wifiHotspotManager.reset();
    }
#endif
#ifdef FEATURE_P2P_SUPPORT
    if (wifiP2pManager) {
        wifiP2pManager.reset();
    }
#endif
#ifndef OHOS_ARCH_LITE
    if (wifiEventSubscriberManager) {
        wifiEventSubscriberManager.reset();
    }
#endif
    return;
}

int WifiManager::GetSupportedFeatures(long &features) const
{
    long supportedFeatures = mSupportedFeatures;
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_INFRA);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_INFRA_5G);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_PASSPOINT);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_AP_STA);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_WPA3_SAE);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_WPA3_SUITE_B);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_OWE);
    features = supportedFeatures;
    return 0;
}

void WifiManager::AddSupportedFeatures(WifiFeatures feature)
{
    mSupportedFeatures |= static_cast<long>(feature);
}

void WifiManager::PushServiceCloseMsg(WifiCloseServiceCode code, int instId)
{
    switch (code) {
        case WifiCloseServiceCode::STA_SERVICE_CLOSE:
            mCloseServiceThread->PostAsyncTask([this, instId]() {
                wifiStaManager->CloseStaService(instId);
            });
            break;
        case WifiCloseServiceCode::SCAN_SERVICE_CLOSE:
            mCloseServiceThread->PostAsyncTask([this, instId]() {
                wifiScanManager->CloseScanService(instId);
            });
            break;
#ifdef FEATURE_AP_SUPPORT
        case WifiCloseServiceCode::AP_SERVICE_CLOSE:
            mCloseServiceThread->PostAsyncTask([this, instId]() {
                wifiHotspotManager->CloseApService(instId);
            });
            break;
#endif
#ifdef FEATURE_P2P_SUPPORT
        case WifiCloseServiceCode::P2P_SERVICE_CLOSE:
            mCloseServiceThread->PostAsyncTask([this]() {
                wifiP2pManager->CloseP2pService();
            });
            break;
#endif
        case WifiCloseServiceCode::SERVICE_THREAD_EXIT:
            WIFI_LOGI("DealCloseServiceMsg exit!");
            return;
        default:
            WIFI_LOGW("Unknown message code, %{public}d", static_cast<int>(code));
            break;
    }
    return;
}

void WifiManager::AutoStartEnhanceService(void)
{
    WIFI_LOGI("AutoStartEnhanceService start");
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_ENHANCE) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        errCode = pEnhanceService->Init();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("init Enhance service failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    return;
}

std::unique_ptr<WifiStaManager>& WifiManager::GetWifiStaManager()
{
    return wifiStaManager;
}

std::unique_ptr<WifiScanManager>& WifiManager::GetWifiScanManager()
{
    return wifiScanManager;
}

std::unique_ptr<WifiTogglerManager>& WifiManager::GetWifiTogglerManager()
{
    return wifiTogglerManager;
}

#ifdef FEATURE_AP_SUPPORT
std::unique_ptr<WifiHotspotManager>& WifiManager::GetWifiHotspotManager()
{
    return wifiHotspotManager;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
std::unique_ptr<WifiP2pManager>& WifiManager::GetWifiP2pManager()
{
    return wifiP2pManager;
}
#endif

#ifndef OHOS_ARCH_LITE
std::unique_ptr<WifiEventSubscriberManager>& WifiManager::GetWifiEventSubscriberManager()
{
    return wifiEventSubscriberManager;
}
#endif

#ifdef FEATURE_HPF_SUPPORT
void WifiManager::InstallPacketFilterProgram(int screenState, int instId)
{
    WIFI_LOGD("%{public}s enter screenState: %{public}d, instId: %{public}d", __FUNCTION__, screenState, instId);
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGW("%{public}s pEnhanceService is nullptr", __FUNCTION__);
        return;
    }
    // fill mac address arr
    unsigned char macAddr[WIFI_MAC_LEN] = {0};
    std::string macStr;
    WifiSettings::GetInstance().GetRealMacAddress(macStr, instId);
    WIFI_LOGD("%{public}s convert mac from str to arr success, macStr: %{public}s",
        __FUNCTION__, OHOS::Wifi::MacAnonymize(macStr).c_str());
    if (OHOS::Wifi::MacStrToArray(macStr, macAddr) != EOK) {
        WIFI_LOGW("%{public}s get mac addr fail, set default mac addr", __FUNCTION__);
        if (memset_s(macAddr, WIFI_MAC_LEN, 0x00, WIFI_MAC_LEN) != EOK) {
            WIFI_LOGE("%{public}s set default mac addr fail", __FUNCTION__);
        }
    }
    // get number ip and net mask
    IpInfo ipInfo;
    WifiSettings::GetInstance().GetIpInfo(ipInfo, instId);
    if (ipInfo.ipAddress == 0 || ipInfo.netmask == 0) {
        WIFI_LOGW("%{public}s cannot get device ip address", __FUNCTION__);
    }
    std::string ipAddrStr = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ipMaskStr = IpTools::ConvertIpv4Mask(ipInfo.netmask);
    int netMaskLen = IpTools::GetMaskLength(ipMaskStr);
    WIFI_LOGD("%{public}s get ip info ipaddrStr: %{public}s, ipMaskStr: %{public}s, netMaskLen: %{public}d",
        __FUNCTION__,
        OHOS::Wifi::MacAnonymize(ipAddrStr).c_str(), OHOS::Wifi::MacAnonymize(ipMaskStr).c_str(), netMaskLen);
    if (pEnhanceService->InstallFilterProgram(
        ipInfo.ipAddress, netMaskLen, macAddr, WIFI_MAC_LEN, screenState) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("%{public}s InstallFilterProgram fail", __FUNCTION__);
        return;
    }
    WIFI_LOGE("%{public}s InstallFilterProgram success", __FUNCTION__);
}
#endif

void WifiManager::CheckAndStartSta()
{
    DIR *dir = nullptr;
    struct dirent *dent = nullptr;
    int currentWaitTime = 0;
    const int sleepTime = 1;
    const int maxWaitTimes = 30;
    while (currentWaitTime < maxWaitTimes) {
        dir = opendir("/sys/class/net");
        if (dir == nullptr) {
            wifiTogglerManager->WifiToggled(1, 0);
            return;
        }
        while ((dent = readdir(dir)) != nullptr) {
            if (dent->d_name[0] == '.') {
                continue;
            }
            if (strncmp(dent->d_name, "wlan", strlen("wlan")) == 0) {
                closedir(dir);
                wifiTogglerManager->WifiToggled(1, 0);
                return;
            }
        }
        closedir(dir);
        sleep(sleepTime);
        currentWaitTime++;
    }
    wifiTogglerManager->WifiToggled(1, 0);
}

void WifiManager::AutoStartServiceThread()
{
    WIFI_LOGI("Auto start service...");
    CheckAndStartSta();
}

void WifiManager::InitPidfile()
{
    char pidFile[DIR_MAX_LENGTH] = {0, };
    int n = snprintf_s(pidFile, DIR_MAX_LENGTH, DIR_MAX_LENGTH - 1, "%s/%s.pid", CONFIG_ROOR_DIR, WIFI_MANAGGER_PID_NAME);
    if (n < 0) {
        LOGE("InitPidfile: construct pidFile name failed.");
        return;
    }
    unlink(pidFile);

    pid_t pid = getpid();
    char buf[PID_MAX_LENGTH] = {0};
    if (snprintf_s(buf, PID_MAX_LENGTH, PID_MAX_LENGTH - 1, "%d", pid) < 0) {
        LOGE("InitPidfile: pidFile:%{public}s failed, snprintf_s error:%{public}d!", pidFile, errno);
        return;
    }

    int fd;
    if ((fd = open(pidFile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
        LOGE("InitPidfile: open pidFile:%{public}s error:%{public}d!", pidFile, errno);
        return;
    }

    ssize_t bytes;
    if ((bytes = write(fd, buf, strlen(buf))) <= 0) {
        LOGE("InitPidfile failed, write pidFile:%{public}s error:%{public}d, bytes:%{public}zd!",
            pidFile, errno, bytes);
        close(fd);
        return;
    }
    LOGI("InitPidfile: buf:%{public}s write pidFile:%{public}s, bytes:%{public}zd!", buf, pidFile, bytes);
    close(fd);

    if (chdir(CONFIG_ROOR_DIR) != 0) {
        LOGE("InitPidfile failed, chdir pidDir:%{public}s error:%{public}d!", CONFIG_ROOR_DIR, errno);
        return;
    }

    umask(DEFAULT_UMASK_VALUE);
    chmod(pidFile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    return;
}
}  // namespace Wifi
}  // namespace OHOS
