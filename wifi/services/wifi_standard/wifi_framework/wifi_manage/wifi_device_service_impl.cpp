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

#include "wifi_device_service_impl.h"
#include <algorithm>
#include <csignal>
#include <unistd.h>
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif
#include "wifi_permission_utils.h"
#include "wifi_internal_msg.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#endif
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_protect_manager.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_dumper.h"
#include "wifi_common_util.h"
#include "wifi_protect_manager.h"

DEFINE_WIFILOG_LABEL("WifiDeviceServiceImpl");
namespace OHOS {
namespace Wifi {
std::mutex WifiDeviceServiceImpl::g_instanceLock;
bool WifiDeviceServiceImpl::isServiceStart = false;
#ifdef OHOS_ARCH_LITE
std::shared_ptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::g_instance;
std::shared_ptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::GetInstance()
#else
const uint32_t TIMEOUT_APP_EVENT = 3000;
const uint32_t TIMEOUT_SCREEN_EVENT = 3000;
const uint32_t TIMEOUT_THERMAL_EVENT = 3000;
using TimeOutCallback = std::function<void()>;
sptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(WifiDeviceServiceImpl::GetInstance().GetRefPtr());

sptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::GetInstance()
#endif
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
#ifdef OHOS_ARCH_LITE
            auto service = std::make_shared<WifiDeviceServiceImpl>();
#else
            auto service = new (std::nothrow) WifiDeviceServiceImpl;
#endif
            g_instance = service;
        }
    }
    return g_instance;
}

WifiDeviceServiceImpl::WifiDeviceServiceImpl()
#ifdef OHOS_ARCH_LITE
    : mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)

#else
    : SystemAbility(WIFI_DEVICE_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
#endif
{
    isServiceStart = false;
}

WifiDeviceServiceImpl::~WifiDeviceServiceImpl()
{}

bool WifiDeviceServiceImpl::IsProcessNeedToRestart()
{
    return WifiDeviceServiceImpl::isServiceStart;
}

void WifiDeviceServiceImpl::SigHandler(int sig)
{
    WIFI_LOGI("[Sta] Recv SIG: %{public}d\n", sig);
    switch (sig) {
        case SIGUSR1:
            if (IsProcessNeedToRestart()) {
                StaServiceCallback cb = WifiManager::GetInstance().GetStaCallback();
                if (cb.OnStaCloseRes != nullptr) {
                    cb.OnStaCloseRes(OperateResState::CLOSE_WIFI_SUCCEED);
                }
                WIFI_LOGE("[Sta] --------------Abort process to restart!!!--------------\n");
                abort();
            }
            break;

        default:
            break;
    }
}

void WifiDeviceServiceImpl::OnStart()
{
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    (void)signal(SIGUSR1, SigHandler);
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    isServiceStart = true;
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start sta service!");
    WifiManager::GetInstance();
#ifndef OHOS_ARCH_LITE
    if (eventSubscriber_ == nullptr) {
        lpTimer_ = std::make_unique<Utils::Timer>("WifiDeviceServiceImpl");
        TimeOutCallback timeoutCallback = std::bind(&WifiDeviceServiceImpl::RegisterAppRemoved, this);
        if (lpTimer_ != nullptr) {
            lpTimer_->Setup();
            lpTimer_->Register(timeoutCallback, TIMEOUT_APP_EVENT, true);
        } else {
            WIFI_LOGE("lpTimer_ is nullptr!");
        }
    }

    if (screenEventSubscriber_ == nullptr) {
        lpScreenTimer_ = std::make_unique<Utils::Timer>("WifiDeviceServiceImpl");
        TimeOutCallback timeoutCallback = std::bind(&WifiDeviceServiceImpl::RegisterScreenEvent, this);
        if (lpScreenTimer_ != nullptr) {
            lpScreenTimer_->Setup();
            lpScreenTimer_->Register(timeoutCallback, TIMEOUT_SCREEN_EVENT, true);
        } else {
            WIFI_LOGE("lpScreenTimer_ is nullptr");
        }
    }

    if (thermalLevelSubscriber_ == nullptr) {
        lpThermalTimer_ = std::make_unique<Utils::Timer>("WifiDeviceServiceImpl");
        TimeOutCallback timeoutCallback = std::bind(&WifiDeviceServiceImpl::RegisterThermalLevel, this);
        lpThermalTimer_->Setup();
        lpThermalTimer_->Register(timeoutCallback, TIMEOUT_THERMAL_EVENT, true);
    }
#endif
}

void WifiDeviceServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
#ifndef OHOS_ARCH_LITE
    if (eventSubscriber_ != nullptr) {
        UnRegisterAppRemoved();
    }
    if (lpTimer_ != nullptr) {
        lpTimer_->Shutdown(false);
        lpTimer_ = nullptr;
    }
    if (screenEventSubscriber_ != nullptr) {
        UnRegisterScreenEvent();
    }
    if (lpScreenTimer_ != nullptr) {
        lpScreenTimer_->Shutdown(false);
        lpScreenTimer_ = nullptr;
    }
    if (thermalLevelSubscriber_ != nullptr) {
        UnRegisterThermalLevel();
    }
    if (lpThermalTimer_ != nullptr) {
        lpThermalTimer_->Shutdown(false);
        lpThermalTimer_ = nullptr;
    }
#endif
    WIFI_LOGI("Stop sta service!");
}

bool WifiDeviceServiceImpl::Init()
{
    if (!mPublishFlag) {
#ifdef OHOS_ARCH_LITE
        bool ret = true;
#else
        bool ret = Publish(WifiDeviceServiceImpl::GetInstance());
#endif
        if (!ret) {
            WIFI_LOGE("Failed to publish sta service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

ErrCode WifiDeviceServiceImpl::EnableWifi()
{
    ErrCode errCode = CheckCanEnableWifi();
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("current wifi state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::CLOSING) { /* when current wifi is closing, return */
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }

#ifdef FEATURE_AP_SUPPORT
    curState = WifiConfigCenter::GetInstance().GetApMidState(0);
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGW("current ap state is %{public}d, please close SoftAp first!",
            static_cast<int>(curState));
        return WIFI_OPT_NOT_SUPPORTED;
    }
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::OPENING)) {
        WIFI_LOGI("set wifi mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }

    errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA) < 0) {
            break;
        }
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }

        errCode = pService->RegisterStaServiceCallback(WifiManager::GetInstance().GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register sta service callback failed!");
            break;
        }

        errCode = pService->EnableWifi();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable sta failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (false);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        return errCode;
    }
#ifdef FEATURE_P2P_SUPPORT
    sptr<WifiP2pServiceImpl> p2pService = WifiP2pServiceImpl::GetInstance();
    if (p2pService != nullptr && p2pService->EnableP2p() != WIFI_OPT_SUCCESS) {
        // only record to log
        WIFI_LOGE("Enable P2p failed!");
    }
#endif

    WifiSettings::GetInstance().SyncWifiConfig();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::DisableWifi()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableWifi:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current wifi state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::OPENING) { /* when current wifi is opening, return */
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

#ifdef FEATURE_P2P_SUPPORT
    sptr<WifiP2pServiceImpl> p2pService = WifiP2pServiceImpl::GetInstance();
    if (p2pService != nullptr && p2pService->DisableP2p() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Disable P2p failed!");
        return WIFI_OPT_FAILED;
    }
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("set wifi mid state opening failed! may be other activity has been operated");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ret = pService->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
    } else {
        WifiConfigCenter::GetInstance().SetStaLastRunState(false);
    }
    return ret;
}

ErrCode WifiDeviceServiceImpl::InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName)
{
    if (WifiProtectManager::GetInstance().InitWifiProtect(protectType, protectName)) {
        return WIFI_OPT_SUCCESS;
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceServiceImpl::GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName)
{
    if (WifiProtectManager::GetInstance().GetWifiProtect(protectMode, protectName)) {
        return WIFI_OPT_SUCCESS;
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceServiceImpl::PutWifiProtectRef(const std::string &protectName)
{
    if (WifiProtectManager::GetInstance().PutWifiProtect(protectName)) {
        return WIFI_OPT_SUCCESS;
    }
    return WIFI_OPT_FAILED;
}

bool WifiDeviceServiceImpl::CheckConfigEap(const WifiDeviceConfig &config)
{
    if (config.keyMgmt != KEY_MGMT_EAP) {
        WIFI_LOGE("CheckConfigEap: keyMgmt is not EAP!");
        return false;
    }
    if (config.wifiEapConfig.eap == EAP_METHOD_TLS) {
        if (config.wifiEapConfig.identity.empty() ||
            (config.wifiEapConfig.certEntry.size() == 0 &&
            (config.wifiEapConfig.clientCert.empty() ||
            config.wifiEapConfig.privateKey.empty()))) {
            WIFI_LOGE("CheckConfigEap: with invalid TLS params!");
            return false;
        }
        return true;
    } else if (config.wifiEapConfig.eap == EAP_METHOD_PEAP) {
        if (config.wifiEapConfig.identity.empty() || config.wifiEapConfig.password.empty()) {
            WIFI_LOGE("CheckConfigEap: with invalid PEAP params!");
            return false;
        }
        return true;
    } else {
        WIFI_LOGE("EAP:%{public}s unsupported!", config.wifiEapConfig.eap.c_str());
    }
    return false;
}

bool WifiDeviceServiceImpl::CheckConfigPwd(const WifiDeviceConfig &config)
{
    if ((config.ssid.length() <= 0) || (config.keyMgmt.length()) <= 0) {
        WIFI_LOGE("CheckConfigPwd: invalid ssid or keyMgmt!");
        return false;
    }

    WIFI_LOGI("CheckConfigPwd: keyMgmt = %{public}s!", config.keyMgmt.c_str());
    if (config.keyMgmt == KEY_MGMT_EAP) {
        return CheckConfigEap(config);
    }

    if ((config.keyMgmt != KEY_MGMT_NONE && config.keyMgmt != KEY_MGMT_WEP) &&
        config.preSharedKey.empty()) {
        WIFI_LOGE("CheckConfigPwd: preSharedKey is empty!");
        return false;
    }

    int len = config.preSharedKey.length();
    bool isAllHex = std::all_of(config.preSharedKey.begin(), config.preSharedKey.end(), isxdigit);
    WIFI_LOGI("CheckConfigPwd, ssid: %{public}s, psk len: %{public}d", SsidAnonymize(config.ssid).c_str(), len);
    if (config.keyMgmt == KEY_MGMT_WEP) {
        for (int i = 0; i != WEPKEYS_SIZE; ++i) {
            if (!config.wepKeys[i].empty()) { // wep
                int wepLen = config.wepKeys[i].size();
                if (wepLen == WEP_KEY_LEN1 || wepLen == WEP_KEY_LEN2 || wepLen == WEP_KEY_LEN3) {
                    return true;
                }
                constexpr int MULTIPLE_HEXT_TO_ASCII = 2;
                if (wepLen == (WEP_KEY_LEN1 * MULTIPLE_HEXT_TO_ASCII) ||
                    wepLen == (WEP_KEY_LEN2 * MULTIPLE_HEXT_TO_ASCII) ||
                    wepLen == (WEP_KEY_LEN3 * MULTIPLE_HEXT_TO_ASCII)) {
                    return isAllHex;
                }
                WIFI_LOGE("CheckConfigPwd: invalid wepLen: %{public}d!", wepLen);
                return false;
            }
        }
        return true;
    }
    if (config.keyMgmt == KEY_MGMT_NONE) {
        return config.preSharedKey.empty();
    }
    int minLen = config.keyMgmt == KEY_MGMT_SAE ? MIN_SAE_LEN : MIN_PSK_LEN;
    int maxLen = isAllHex ? MAX_HEX_LEN : MAX_PRESHAREDKEY_LEN;
    if (len < minLen || len > maxLen) {
        WIFI_LOGE("CheckConfigPwd: preSharedKey length error: %{public}d", len);
        return false;
    }
    return true;
}

ErrCode WifiDeviceServiceImpl::CheckCallingUid(int &uid)
{
#ifndef OHOS_ARCH_LITE
    uid = GetCallingUid();
    if (!IsForegroundApp(uid)) {
        return WIFI_OPT_INVALID_PARAM;
    }
    return WIFI_OPT_SUCCESS;
#else
    return WIFI_OPT_NOT_SUPPORTED;
#endif
}

ErrCode WifiDeviceServiceImpl::CheckRemoveCandidateConfig(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CheckRemoveCandidateConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        WIFI_LOGE("CheckRemoveCandidateConfig:IsStaServiceRunning not running!");
        return WIFI_OPT_STA_NOT_OPENED;
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::RemoveCandidateConfig(const WifiDeviceConfig &config)
{
    ErrCode ret = CheckRemoveCandidateConfig();
    if (ret != WIFI_OPT_SUCCESS) {
        return ret;
    }
    /* check the caller's uid */
    int uid = 0;
    if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("CheckCallingUid failed!");
        return WIFI_OPT_INVALID_PARAM;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    /* get all candidate configs */
    std::vector<WifiDeviceConfig> configs;
    if (WifiConfigCenter::GetInstance().GetCandidateConfigs(uid, configs) != 0) {
        WIFI_LOGE("NOT find the caller's configs!");
        return WIFI_OPT_INVALID_CONFIG;
    }
    /* find the networkId of the removed config */
    int networkId = INVALID_NETWORK_ID;
    size_t size = configs.size();
    for (size_t i = 0; i < size; i++) {
        if (configs[i].ssid == config.ssid) {
            networkId = configs[i].networkId;
            WIFI_LOGI("find the removed config, networkId:%{public}d!", networkId);
            break;
        }
    }
    /* removed the config */
    if (networkId != INVALID_NETWORK_ID) {
        return pService->RemoveCandidateConfig(uid, networkId);
    }
    return WIFI_OPT_INVALID_CONFIG;
}

ErrCode WifiDeviceServiceImpl::RemoveCandidateConfig(int networkId)
{
    ErrCode ret = CheckRemoveCandidateConfig();
    if (ret != WIFI_OPT_SUCCESS) {
        return ret;
    }
    int uid = 0;
    if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("CheckCallingUid failed!");
        return WIFI_OPT_INVALID_PARAM;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    if (networkId == INVALID_NETWORK_ID) {
        return pService->RemoveAllCandidateConfig(uid);
    } else {
        return pService->RemoveCandidateConfig(uid, networkId);
    }
}

ErrCode WifiDeviceServiceImpl::AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!isCandidate) {
        if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("AddDeviceConfig:VerifySetWifiConfigPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }

    if (!CheckConfigPwd(config)) {
        WIFI_LOGE("CheckConfigPwd failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("CheckCallingUid failed!");
            return WIFI_OPT_INVALID_PARAM;
        }
        return pService->AddCandidateConfig(uid, config, result);
    }

    int retNetworkId = pService->AddDeviceConfig(config);
    if (retNetworkId < 0) {
        return WIFI_OPT_FAILED;
    }
    result = retNetworkId;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::UpdateDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("UpdateDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("UpdateDeviceConfig:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    int retNetworkId = pService->UpdateDeviceConfig(config);
    if (retNetworkId <= INVALID_NETWORK_ID) {
        return WIFI_OPT_FAILED;
    }
    result = retNetworkId;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::RemoveDevice(int networkId)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveDevice:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveDevice:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (networkId < 0) {
        return WIFI_OPT_INVALID_PARAM;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RemoveDevice(networkId);
}

ErrCode WifiDeviceServiceImpl::RemoveAllDevice()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveAllDevice:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveAllDevice:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RemoveAllDevice();
}

ErrCode WifiDeviceServiceImpl::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");

        if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (!isCandidate) {
            if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
                WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
                return WIFI_OPT_PERMISSION_DENIED;
            }
        }
    }

    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("CheckCallingUid failed!");
            return WIFI_OPT_INVALID_PARAM;
        }
        WifiConfigCenter::GetInstance().GetCandidateConfigs(uid, result);
    } else {
        WifiConfigCenter::GetInstance().GetDeviceConfig(result);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (networkId < 0) {
        return WIFI_OPT_INVALID_PARAM;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->EnableDeviceConfig(networkId, attemptEnable);
}

ErrCode WifiDeviceServiceImpl::DisableDeviceConfig(int networkId)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (networkId < 0) {
        return WIFI_OPT_INVALID_PARAM;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DisableDeviceConfig(networkId);
}

ErrCode WifiDeviceServiceImpl::ConnectToNetwork(int networkId, bool isCandidate)
{
    if (isCandidate) {
        if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("ConnectToCandidateConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    } else {
        if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("ConnectToNetwork:VerifyWifiConnectionPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }

    if (!IsStaServiceRunning()) {
        WIFI_LOGE("ConnectToNetwork: sta service is not running!");
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (networkId < 0) {
        WIFI_LOGE("ConnectToNetwork: invalid networkId = %{public}d!", networkId);
        return WIFI_OPT_INVALID_PARAM;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("ConnectToNetwork: pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("CheckCallingUid failed!");
            return WIFI_OPT_INVALID_PARAM;
        }
        return pService->ConnectToCandidateConfig(uid, networkId);
    }
    return pService->ConnectToNetwork(networkId);
}

ErrCode WifiDeviceServiceImpl::ConnectToDevice(const WifiDeviceConfig &config)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ConnectToDevice:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ConnectToDevice:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ConnectToDevice:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!CheckConfigPwd(config)) {
        WIFI_LOGE("CheckConfigPwd failed!");
        return WIFI_OPT_INVALID_PARAM;
    }
    if (!IsStaServiceRunning()) {
        WIFI_LOGE("ConnectToDevice: sta service is not running!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("ConnectToNetwork: pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->ConnectToDevice(config);
}

ErrCode WifiDeviceServiceImpl::IsConnected(bool &isConnected)
{
    WifiLinkedInfo linkedInfo;

    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsConnected:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    isConnected = (linkedInfo.connState == ConnState::CONNECTED);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ReConnect()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReConnect:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReConnect:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->ReConnect();
}

ErrCode WifiDeviceServiceImpl::ReAssociate(void)
{
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReAssociate:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->ReAssociate();
}

ErrCode WifiDeviceServiceImpl::Disconnect(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Disconnect:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Disconnect:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->Disconnect();
}

ErrCode WifiDeviceServiceImpl::StartWps(const WpsConfig &config)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWps:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->StartWps(config);
}

ErrCode WifiDeviceServiceImpl::CancelWps(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CancelWps:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->CancelWps();
}

ErrCode WifiDeviceServiceImpl::IsWifiActive(bool &bActive)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsWifiActive:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bActive = IsStaServiceRunning();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetWifiState(int &state)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetWifiState:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    state = WifiConfigCenter::GetInstance().GetWifiState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetLinkedInfo(WifiLinkedInfo &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetLinkedInfo(info);
    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetWifiLocalMacPermission() PERMISSION_DENIED!");
        /* Clear mac addr */
        info.macAddress = "";
    }

    WIFI_LOGI("GetLinkedInfo, networkId=%{public}d, ssid=%{public}s, rssi=%{public}d, frequency=%{public}d",
        info.networkId, SsidAnonymize(info.ssid).c_str(), info.rssi, info.frequency);
    WIFI_LOGI("GetLinkedInfo, connState=%{public}d, supplicantState=%{public}d, detailedState=%{public}d",
        info.connState, info.supplicantState, info.detailedState);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetIpInfo(IpInfo &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetIpInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetIpInfo(info);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::SetCountryCode(const std::string &countryCode)
{
    if (countryCode.length() != WIFI_COUNTRY_CODE_LEN) {
        return WIFI_OPT_INVALID_PARAM;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetCountryCode:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->SetCountryCode(countryCode);
}

ErrCode WifiDeviceServiceImpl::GetCountryCode(std::string &countryCode)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetCountryCode:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetCountryCode(countryCode);
    WIFI_LOGI("GetCountryCode: country code is %{public}s", countryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiDeviceServiceImpl::RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback)
#else
ErrCode WifiDeviceServiceImpl::RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback)
#endif
{
    WIFI_LOGI("RegisterCallBack");
    if (callback == nullptr) {
        WIFI_LOGE("Get call back client failed!");
        return WIFI_OPT_FAILED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBackClient:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiInternalEventDispatcher::GetInstance().SetSingleStaCallback(callback);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSignalLevel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    level = WifiConfigCenter::GetInstance().GetSignalLevel(rssi, band);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetSupportedFeatures(long &features)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedFeatures:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    int ret = WifiManager::GetInstance().GetSupportedFeatures(features);
    if (ret < 0) {
        WIFI_LOGE("Failed to get supported features!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetDeviceMacAddress(std::string &result)
{
    WIFI_LOGI("GetDeviceMacAddress");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiLocalMacPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetMacAddress(result);
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceServiceImpl::SetLowLatencyMode(bool enabled)
{
    WIFI_LOGI("SetLowLatencyMode");
    return WifiProtectManager::GetInstance().SetLowLatencyMode(enabled);
}

ErrCode WifiDeviceServiceImpl::CheckCanEnableWifi(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableWifi:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    /**
     * when airplane mode opened, if the config "can_use_sta_when_airplanemode"
     * opened, then can open sta; other, return forbid.
     */
    if (!WifiConfigCenter::GetInstance().GetCanOpenStaWhenAirplaneMode() &&
        WifiConfigCenter::GetInstance().GetAirplaneModeState() == 1 &&
        !WifiConfigCenter::GetInstance().GetCanUseStaWhenAirplaneMode()) {
        WIFI_LOGI("current airplane mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
    /* when power saving mode opened, can't open sta, return forbid. */
    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGI("current power saving mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }
    /**
     * Check the interval between the last STA shutdown and the current STA
     * startup.
     */
    double interval = WifiConfigCenter::GetInstance().GetWifiStaInterval();
    if (interval <= REOPEN_STA_INTERVAL) {
        int waitMils = REOPEN_STA_INTERVAL - int(interval) + 1;
        WIFI_LOGI("open wifi too frequent, interval since last close is %{public}lf, and wait %{public}d ms",
            interval,
            waitMils);
        usleep(waitMils * MSEC);
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceServiceImpl::IsStaServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGW("current wifi state is %{public}d", static_cast<int>(curState));
        return false;
    }
    return true;
}

bool WifiDeviceServiceImpl::IsScanServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetScanMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGW("scan service does not started!");
        return false;
    }
    return true;
}

void WifiDeviceServiceImpl::SaBasicDump(std::string& result)
{
    WifiDeviceServiceImpl impl;
    bool isActive = impl.IsStaServiceRunning();
    result.append("WiFi active state: ");
    std::string strActive = isActive ? "activated" : "inactive";
    result += strActive + "\n\n";

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    bool isConnected = linkedInfo.connState == ConnState::CONNECTED;
    result.append("WiFi connection status: ");
    std::string strIsConnected = isConnected ? "connected" : "not connected";
    result += strIsConnected + "\n";
    if (isConnected) {
        std::stringstream ss;
        ss << "  Connection.ssid: " << linkedInfo.ssid << "\n";
        ss << "  Connection.bssid: " << MacAnonymize(linkedInfo.bssid) << "\n";
        ss << "  Connection.rssi: " << linkedInfo.rssi << "\n";

        enum {BAND_2GHZ = 1, BAND_5GHZ = 2, BAND_ANY = 3};
        auto funcStrBand = [](int band) {
            std::string retStr;
            switch (band) {
                case BAND_2GHZ:
                    retStr = "2.4GHz";
                    break;
                case BAND_5GHZ:
                    retStr = "5GHz";
                    break;
                case BAND_ANY:
                    retStr = "dual-mode frequency band";
                    break;
                default:
                    retStr = "unknown band";
            }
            return retStr;
        };
        ss << "  Connection.band: " << funcStrBand(linkedInfo.band) << "\n";
        ss << "  Connection.frequency: " << linkedInfo.frequency << "\n";
        ss << "  Connection.linkSpeed: " << linkedInfo.linkSpeed << "\n";
        ss << "  Connection.macAddress: " << MacAnonymize(linkedInfo.macAddress) << "\n";
        ss << "  Connection.isHiddenSSID: " << (linkedInfo.ifHiddenSSID ? "true" : "false") << "\n";

        int level = WifiConfigCenter::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band);
        ss << "  Connection.signalLevel: " << level << "\n";
        result += ss.str();
    }
    result += "\n";

    std::string cc;
    WifiConfigCenter::GetInstance().GetCountryCode(cc);
    result.append("Country Code: ").append(cc);
    result += "\n";
}

bool WifiDeviceServiceImpl::IsRemoteDied(void)
{
    return false;
}

#ifndef OHOS_ARCH_LITE
int32_t WifiDeviceServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter sta dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.DeviceDump(SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi device save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}

void WifiDeviceServiceImpl::RegisterAppRemoved()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    eventSubscriber_ = std::make_shared<AppEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(eventSubscriber_)) {
        WIFI_LOGE("AppEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AppEvent SubscribeCommonEvent() OK");
    }
}

void WifiDeviceServiceImpl::UnRegisterAppRemoved()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(eventSubscriber_)) {
        WIFI_LOGE("AppEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AppEvent UnSubscribeCommonEvent() OK");
    }
    eventSubscriber_ = nullptr;
}

void WifiDeviceServiceImpl::RegisterScreenEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    screenEventSubscriber_ = std::make_shared<ScreenEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent SubscribeCommonEvent() OK");
    }
}

void WifiDeviceServiceImpl::UnRegisterScreenEvent()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent UnSubscribeCommonEvent() OK");
    }
    screenEventSubscriber_ = nullptr;
}

void WifiDeviceServiceImpl::RegisterThermalLevel()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    thermalLevelSubscriber_ = std::make_shared<ThermalLevelSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(thermalLevelSubscriber_)) {
        WIFI_LOGE("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() OK");
    }
}

void WifiDeviceServiceImpl::UnRegisterThermalLevel()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(thermalLevelSubscriber_)) {
        WIFI_LOGE("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() OK");
    }
    thermalLevelSubscriber_ = nullptr;
}

void AppEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("AppEventSubscriber::OnReceiveEvent : %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        auto wantTemp = data.GetWant();
        auto uid = wantTemp.GetIntParam(AppExecFwk::Constants::UID, -1);
        WIFI_LOGI("Package removed of uid %{public}d.", uid);
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
        if (pService == nullptr) {
            WIFI_LOGI("Sta service not opend!");
            std::vector<WifiDeviceConfig> tempConfigs;
            WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
            for (const auto &config : tempConfigs) {
                if (WifiSettings::GetInstance().RemoveDevice(config.networkId) != WIFI_OPT_SUCCESS) {
                    WIFI_LOGE("RemoveAllCandidateConfig-RemoveDevice() failed!");
                }
            }
            WifiSettings::GetInstance().SyncDeviceConfig();
            return;
        }
        if (pService->RemoveAllCandidateConfig(uid) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("RemoveAllCandidateConfig failed");
        }
    }
}

void ScreenEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ScreenEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("sta service is NOT start!");
        return;
    }

    int screenState = WifiSettings::GetInstance().GetScreenState();
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF &&
        screenState == MODE_STATE_OPEN) {
        WifiSettings::GetInstance().SetScreenState(MODE_STATE_CLOSE);
        /* Send suspend to wpa */
        if (pService->SetSuspendMode(true) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetSuspendMode failed");
        }
        return;
    }

    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON &&
        screenState == MODE_STATE_CLOSE) {
        WifiSettings::GetInstance().SetScreenState(MODE_STATE_OPEN);
        /* Send resume to wpa */
        if (pService->SetSuspendMode(false) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetSuspendMode failed");
        }
        return;
    }
    WIFI_LOGW("ScreenEventSubscriber::OnReceiveEvent, screen state: %{public}d.", screenState);
}

void ThermalLevelSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ThermalLevelSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        static const std::string THERMAL_EVENT_ID = "0";
        int level = data.GetWant().GetIntParam(THERMAL_EVENT_ID, 0);
        WifiSettings::GetInstance().SetThermalLevel(level);
        WIFI_LOGI("ThermalLevelSubscriber SetThermalLevel: %{public}d.", level);
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS
