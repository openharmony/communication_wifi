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
#include <chrono>
#include <unistd.h>
#include "wifi_permission_utils.h"
#include "wifi_internal_msg.h"
#include "wifi_auth_center.h"
#include "wifi_channel_helper.h"
#include "wifi_config_center.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sa_manager.h"
#include "mac_address.h"
#include "wifi_p2p_service_impl.h"
#include "wifi_country_code_manager.h"
#include "app_network_speed_limit_service.h"
#endif
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_protect_manager.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_common_util.h"
#include "wifi_protect_manager.h"
#include "wifi_global_func.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_randommac_helper.h"
#include "wifi_sta_hal_interface.h"

DEFINE_WIFILOG_LABEL("WifiDeviceServiceImpl");
namespace OHOS {
namespace Wifi {

constexpr const char *BROKER_PROCESS_PROTECT_FLAG = "register_process_info";
constexpr int WIFI_BROKER_NETWORK_ID = -2;
constexpr int EXTENSION_ERROR_CODE = 13500099;
constexpr int32_t UID_CALLINGUID_TRANSFORM_DIVISOR = 200000;

bool g_hiLinkActive = false;
constexpr int HILINK_CMD_MAX_LEN = 1024;

#ifdef OHOS_ARCH_LITE
std::mutex WifiDeviceServiceImpl::g_instanceLock;
std::shared_ptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::g_instance = nullptr;
std::shared_ptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            std::shared_ptr<WifiDeviceServiceImpl> service = std::make_shared<WifiDeviceServiceImpl>();
            g_instance = service;
        }
    }
    return g_instance;
}

void WifiDeviceServiceImpl::OnStart()
{
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    
    WifiManager::GetInstance();
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start sta service!");
}

void WifiDeviceServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    WIFI_LOGI("Stop sta service!");
}
#endif


WifiDeviceServiceImpl::WifiDeviceServiceImpl()
#ifdef OHOS_ARCH_LITE
    : mState(ServiceRunningState::STATE_NOT_START)
#endif
{
    WIFI_LOGI("enter WifiDeviceServiceImpl");
}

#ifndef OHOS_ARCH_LITE
WifiDeviceServiceImpl::WifiDeviceServiceImpl(int instId) : WifiDeviceStub(instId)
{
    WIFI_LOGI("enter WifiDeviceServiceImpl");
}
#endif

WifiDeviceServiceImpl::~WifiDeviceServiceImpl()
{
    WIFI_LOGI("enter ~WifiDeviceServiceImpl");
}

ErrCode WifiDeviceServiceImpl::EnableWifi()
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("EnableWifi(), pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    ErrCode errCode = CheckCanEnableWifi();
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    if (m_instId == INSTID_WLAN0) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED);
#ifndef OHOS_ARCH_LITE
        WifiSettings::GetInstance().SetWifiToggleCaller(GetCallingPid(), m_instId);
#endif
        WifiManager::GetInstance().GetWifiTogglerManager()->StartWifiToggledTimer();
        WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
    }
    return WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, m_instId);
}

ErrCode WifiDeviceServiceImpl::DisableWifi()
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("DisableWifi(), pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisableWifi: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableWifi:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (m_instId == INSTID_WLAN0 || m_instId == INSTID_WLAN1) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_DISABLED, m_instId);
        WifiConfigCenter::GetInstance().SetWifiAllowSemiActive(false);
#ifndef OHOS_ARCH_LITE
        WifiSettings::GetInstance().SetWifiToggleCaller(GetCallingPid(), m_instId);
#endif
    }

    if (m_instId == INSTID_WLAN0) {
        WifiManager::GetInstance().GetWifiTogglerManager()->StopWifiToggledTimer();
        WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
    }
    return WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, m_instId);
}

ErrCode WifiDeviceServiceImpl::EnableSemiWifi()
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("EnableSemiWifi(), pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("EnableSemiWifi: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableSemiWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableSemiWifi:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
#ifndef OHOS_ARCH_LITE
    if (WifiManager::GetInstance().GetWifiEventSubscriberManager()->IsMdmForbidden()) {
        WIFI_LOGE("EnableSemiWifi: Mdm forbidden PERMISSION_DENIED!");
        return WIFI_OPT_ENTERPRISE_DENIED;
    }
    if (WifiManager::GetInstance().GetWifiTogglerManager()->IsSatelliteStateStart()) {
        WIFI_LOGI("current satellite mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
#endif
    if (m_instId == INSTID_WLAN0 || m_instId == INSTID_WLAN1) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_SEMI_ENABLED);
#ifndef OHOS_ARCH_LITE
        WifiSettings::GetInstance().SetWifiToggleCaller(GetCallingPid(), m_instId);
#endif
    }

    if (m_instId == INSTID_WLAN0) {
        WifiManager::GetInstance().GetWifiTogglerManager()->StopWifiToggledTimer();
        WifiManager::GetInstance().GetWifiTogglerManager()->StartSemiWifiToggledTimer();
    }
    return WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, m_instId);
}

ErrCode WifiDeviceServiceImpl::InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName)
{
    /* refer to WifiProtectManager::GetInstance().InitWifiProtect, DO NOT support now! */
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::IsHeldWifiProtectRef(
    const std::string &protectName, bool &isHoldProtect)
{
#ifdef OHOS_ARCH_LITE
    /* refer to WifiProtectManager::GetInstance().IsHeldWifiProtect, DO NOT support now! */
    return WIFI_OPT_SUCCESS;
#else
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHeldWifiProtectRef:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    isHoldProtect = WifiProtectManager::GetInstance().IsHeldWifiProtect(protectName);
    WIFI_LOGD("App %{public}s hold protect is %{public}d", protectName.c_str(), isHoldProtect);
    return WIFI_OPT_SUCCESS;
#endif
}

ErrCode WifiDeviceServiceImpl::GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName)
{
#ifdef OHOS_ARCH_LITE
    /* refer to WifiProtectManager::GetInstance().GetWifiProtect, DO NOT support now! */
    return WIFI_OPT_SUCCESS;
#else
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetWifiProtectRef:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiProtectManager::GetInstance().GetWifiProtect(protectMode, protectName)) {
        WIFI_LOGE("App %{public}s set protect mode %{public}d failed.",
            protectName.c_str(), static_cast<int>(protectMode));
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
#endif
}

ErrCode WifiDeviceServiceImpl::PutWifiProtectRef(const std::string &protectName)
{
#ifdef OHOS_ARCH_LITE
    /* refer to WifiProtectManager::GetInstance().PutWifiProtect, DO NOT support now! */
    return WIFI_OPT_SUCCESS;
#else
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("PutWifiProtectRef:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiProtectManager::GetInstance().PutWifiProtect(protectName)) {
        WIFI_LOGE("App %{public}s remove protect mode failed.", protectName.c_str());
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
#endif
}

bool WifiDeviceServiceImpl::CheckConfigEap(const WifiDeviceConfig &config)
{
    if (config.keyMgmt != KEY_MGMT_EAP && config.keyMgmt != KEY_MGMT_SUITE_B_192) {
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
    } else if ((config.wifiEapConfig.eap == EAP_METHOD_PEAP) || (config.wifiEapConfig.eap == EAP_METHOD_PWD) ||
        (config.wifiEapConfig.eap == EAP_METHOD_TTLS)) {
        if (config.wifiEapConfig.identity.empty() || config.wifiEapConfig.password.empty()) {
            WIFI_LOGE("CheckConfigEap: invalid parameter, the identity length is:%{public}zu",
                config.wifiEapConfig.identity.length());
            return false;
        }
        return true;
    } else {
        WIFI_LOGW("EAP:%{public}s unsupported!", config.wifiEapConfig.eap.c_str());
    }
    return true;
}

bool WifiDeviceServiceImpl::CheckConfigWapi(const WifiDeviceConfig &config)
{
    if (config.keyMgmt == KEY_MGMT_WAPI_PSK) {
        if (config.wifiWapiConfig.wapiPskType < static_cast<int>(WapiPskType::WAPI_PSK_ASCII) ||
            config.wifiWapiConfig.wapiPskType > static_cast<int>(WapiPskType::WAPI_PSK_HEX)) {
            WIFI_LOGE("CheckConfigWapi: with invalid wapiPskType!");
            return false;
        }
        return true;
    }

    if (config.wifiWapiConfig.wapiAsCertData.empty() || config.wifiWapiConfig.wapiUserCertData.empty()) {
        WIFI_LOGE("CheckConfigWapi: with cert data empty!");
        return false;
    }

    return true;
}

bool WifiDeviceServiceImpl::CheckConfigPwd(const WifiDeviceConfig &config)
{
    if ((config.ssid.length() <= 0) || (config.ssid.length() > DEVICE_NAME_LENGTH) || (config.keyMgmt.length()) <= 0) {
        WIFI_LOGE("CheckConfigPwd: invalid ssid or keyMgmt!");
        return false;
    }

    WIFI_LOGI("CheckConfigPwd: keyMgmt = %{public}s!", config.keyMgmt.c_str());
    if (config.keyMgmt == KEY_MGMT_EAP || config.keyMgmt == KEY_MGMT_SUITE_B_192) {
        return CheckConfigEap(config);
    }

    if (config.keyMgmt == KEY_MGMT_WAPI_CERT || config.keyMgmt == KEY_MGMT_WAPI_PSK) {
        return CheckConfigWapi(config);
    }

    if (config.keyMgmt == KEY_MGMT_NONE) {
        return config.preSharedKey.empty();
    }

    if (config.keyMgmt != KEY_MGMT_WEP && config.preSharedKey.empty()) {
        WIFI_LOGE("CheckConfigPwd: preSharedKey is empty!");
        return false;
    }

    int len = static_cast<int>(config.preSharedKey.length());
    bool isAllHex = std::all_of(config.preSharedKey.begin(), config.preSharedKey.end(), isxdigit);
    WIFI_LOGI("CheckConfigPwd, ssid: %{public}s, psk len: %{public}d", SsidAnonymize(config.ssid).c_str(), len);
    if (config.keyMgmt == KEY_MGMT_WEP) {
        for (int i = 0; i != WEPKEYS_SIZE; ++i) {
            if (!config.wepKeys[i].empty()) { // wep
                uint32_t wepLen = config.wepKeys[i].size();
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
    int minLen = config.keyMgmt == KEY_MGMT_SAE ? MIN_SAE_LEN : MIN_PSK_LEN;
    int maxLen = isAllHex ? MAX_HEX_LEN : MAX_PRESHAREDKEY_LEN;
    if (len < minLen || len > maxLen) {
        WIFI_LOGE("CheckConfigPwd: preSharedKey length error: %{public}d", len);
        return false;
    }
    return true;
}

#ifndef OHOS_ARCH_LITE
bool WifiDeviceServiceImpl::InitWifiBrokerProcessInfo(const WifiDeviceConfig &config)
{
    WIFI_LOGD("InitWifiBrokerProcessInfo,networkId=%{public}d, ProcessName=[%{public}s],"
        "ancoCallProcessName =[%{public}s],bssid = [%{public}s],ssid=[%{public}s]",
        config.networkId, config.callProcessName.c_str(), config.ancoCallProcessName.c_str(),
        MacAnonymize(config.bssid).c_str(), SsidAnonymize(config.ssid).c_str());
    if (config.networkId != WIFI_BROKER_NETWORK_ID || config.ancoCallProcessName != BROKER_PROCESS_PROTECT_FLAG ||
        !config.bssid.empty() || !config.ssid.empty()) {
        return false;
    }
    std::string ancoWifiValue = "";
    bool success = WifiSettings::GetInstance().GetConfigValueByName("anco_broker_name", ancoWifiValue);
    if (success && config.callProcessName == ancoWifiValue) {
        SetWifiBrokerProcess(GetCallingPid(), config.callProcessName);
        return true;
    }
    return false;
}
#endif

ErrCode WifiDeviceServiceImpl::CheckCallingUid(int &uid)
{
#ifndef OHOS_ARCH_LITE
    uid = GetCallingUid();
    if (!WifiAppStateAware::GetInstance().IsForegroundApp(uid)) {
        return WIFI_OPT_INVALID_PARAM;
    }
    return WIFI_OPT_SUCCESS;
#else
    return WIFI_OPT_NOT_SUPPORTED;
#endif
}

bool WifiDeviceServiceImpl::IsWifiBrokerProcess(int uid)
{
#ifndef OHOS_ARCH_LITE
   int pid = GetCallingPid();
   std::string wifiBrokerFrameProcessName = "";
   bool success = WifiSettings::GetInstance().GetConfigValueByName("anco_broker_name", wifiBrokerFrameProcessName);
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(uid, pid);
    if (!success || ancoBrokerFrameProcessName != wifiBrokerFrameProcessName) {
        return false;
    }
    return true;
#else
    return false;
#endif
}

ErrCode WifiDeviceServiceImpl::CheckRemoveCandidateConfig(void)
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
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

void WifiDeviceServiceImpl::SetWifiConnectedMode(void)
{
#ifndef OHOS_ARCH_LITE
    if (IsWifiBrokerProcess(GetCallingUid())) {
        WifiConfigCenter::GetInstance().SetWifiConnectedMode(true, m_instId);
        WIFI_LOGD("WifiDeviceServiceImpl %{public}s, anco, %{public}d", __func__, m_instId);
    } else {
        WifiConfigCenter::GetInstance().SetWifiConnectedMode(false, m_instId);
        WIFI_LOGD("WifiDeviceServiceImpl %{public}s, not anco, %{public}d", __func__, m_instId);
    }
#endif
    return;
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
        if (!IsWifiBrokerProcess(uid)) {
            WIFI_LOGE("CheckCallingUid IsWifiBrokerProcess failed!");
            return WIFI_OPT_INVALID_PARAM;
        }
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    /* get all candidate configs */
    std::vector<WifiDeviceConfig> configs;
    if (WifiSettings::GetInstance().GetAllCandidateConfig(uid, configs) != 0) {
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
        if (!IsWifiBrokerProcess(uid)) {
            WIFI_LOGE("IsWifiBrokerProcess failed!");
            return WIFI_OPT_INVALID_PARAM;
        }
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
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

void WifiDeviceServiceImpl::updateStaDeviceMacAddress(WifiDeviceConfig &config)
{
    WifiMacAddrInfo macAddrInfo;
    macAddrInfo.bssid = config.bssid;
    macAddrInfo.bssidType = config.bssidType;
    std::string macAddr =
        WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
            macAddrInfo);
    if (macAddr.empty()) {
        WIFI_LOGW("%{public}s: record not found, bssid:%{private}s, bssidType:%{public}d",
            __func__, config.bssid.c_str(), config.bssidType);
    } else {
        WIFI_LOGI("%{public}s: the record is exists, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
            __func__, config.bssid.c_str(), config.bssidType, macAddr.c_str());
        /* random MAC address are translated into real MAC address */
        if (!config.bssid.empty() && config.bssidType == RANDOM_DEVICE_ADDRESS) {
            config.bssid = macAddr;
            config.bssidType = REAL_DEVICE_ADDRESS;
            WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                __func__, config.bssid.c_str(), config.bssidType);
        }
    }
}

ErrCode WifiDeviceServiceImpl::AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate)
{
    ErrCode errCode = CheckCanAddDeviceConfig(isCandidate);
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }
#ifndef OHOS_ARCH_LITE
    if (InitWifiBrokerProcessInfo(config)) {
        return WIFI_OPT_SUCCESS;
    }
#endif
    if (!CheckConfigPwd(config)) {
        WIFI_LOGE("CheckConfigPwd failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (isCandidate && config.bssid.length() != 0 && CheckMacIsValid(config.bssid) != 0) {
        WIFI_LOGE("AddDeviceConfig:VerifyBSSID failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    WifiDeviceConfig updateConfig = config;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    updateStaDeviceMacAddress(updateConfig);
#endif
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            if (!IsWifiBrokerProcess(uid)) {
                WIFI_LOGE("CheckCallingUid IsWifiBrokerProcess failed!");
                return WIFI_OPT_INVALID_PARAM;
            }
        }
        if (!IsWifiBrokerProcess(uid)) {
            updateConfig.isEphemeral = true;
        }
        return pService->AddCandidateConfig(uid, updateConfig, result);
    }

    int retNetworkId = pService->AddDeviceConfig(updateConfig);
    if (retNetworkId < 0) {
        return WIFI_OPT_FAILED;
    }
    result = retNetworkId;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::CheckCanAddDeviceConfig(const bool isCandidate)
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
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
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::UpdateDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("UpdateDeviceConfig: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
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

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED &&
        WifiPermissionUtils::VerifyEnterpriseWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveDevice:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (networkId < 0) {
        return WIFI_OPT_INVALID_PARAM;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RemoveDevice(networkId);
}

ErrCode WifiDeviceServiceImpl::RemoveAllDevice()
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("RemoveAllDevice:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RemoveAllDevice();
}

ErrCode WifiDeviceServiceImpl::SetTxPower(int power)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("SetTxPower:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("setTxPower:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiStaHalInterface::GetInstance().SetTxPower(power) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetTxPower() failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
    if (WifiPermissionUtils::VerifySameProcessPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetDpiMarkRule:VerifySameProcessPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    if (WifiStaHalInterface::GetInstance().SetDpiMarkRule(ifaceName, uid, protocol, enable) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetDpiMarkRule failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void WifiDeviceServiceImpl::ReplaceConfigWhenCandidateConnected(std::vector<WifiDeviceConfig> &result)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        return;
    }
    WifiDeviceConfig wifiConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, wifiConfig) != 0) {
        return;
    }
    // -1: Connect by system, use default uid.
    if (wifiConfig.uid == -1 || wifiConfig.isShared) {
        return;
    }
    for (auto iter = result.begin(); iter != result.end(); iter++) {
        if (iter->ssid == wifiConfig.ssid && iter->keyMgmt == wifiConfig.keyMgmt) {
            WIFI_LOGI("ReplaceConfigWhenCandidateConnected networkid: %{public}d!", iter->networkId);
            result.erase(iter);
            break;
        }
    }
    result.push_back(wifiConfig);
}

ErrCode WifiDeviceServiceImpl::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate)
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    } else if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!isCandidate) {
        if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }

    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            if (!IsWifiBrokerProcess(uid)) {
                WIFI_LOGE("IsWifiBrokerProcess failed!");
                return WIFI_OPT_INVALID_PARAM;
            }
        }
        WifiSettings::GetInstance().GetAllCandidateConfig(uid, result);
    } else {
        WifiSettings::GetInstance().GetDeviceConfig(result);
        ReplaceConfigWhenCandidateConnected(result);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetDeviceConfig(const int &networkId, WifiDeviceConfig &config)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetDeviceConfig:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceConfig:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");

        if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfig:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

    #ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfig:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    #endif
    }

    WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("EnableDeviceConfig:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->EnableDeviceConfig(networkId, attemptEnable);
}

ErrCode WifiDeviceServiceImpl::DisableDeviceConfig(int networkId)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisableDeviceConfig:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DisableDeviceConfig(networkId);
}

ErrCode WifiDeviceServiceImpl::ConnectToNetwork(int networkId, bool isCandidate)
{
    if (IsOtherVapConnect()) {
        LOGI("ConnectToNetwork: p2p or hml connected, and hotspot is enable");
        WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, 0);
    }
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (isCandidate) {
        if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("ConnectToCandidateConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    } else {
        if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED &&
            WifiPermissionUtils::VerifyEnterpriseWifiConnectionPermission() == PERMISSION_DENIED) {
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("ConnectToNetwork: pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    SetWifiConnectedMode();
    if (isCandidate) {
        int uid = 0;
        if (CheckCallingUid(uid) != WIFI_OPT_SUCCESS) {
            if (!IsWifiBrokerProcess(uid)) {
                WIFI_LOGE("ConnectToNetwork IsWifiBrokerProcess failed!");
                return WIFI_OPT_INVALID_PARAM;
            }
        }
        WifiSettings::GetInstance().SetDeviceEphemeral(networkId, false);
        WifiSettings::GetInstance().SetDeviceState(networkId, static_cast<int>(WifiDeviceConfigStatus::ENABLED), false);
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
        if (linkedInfo.connState == ConnState::CONNECTING || linkedInfo.connState == ConnState::CONNECTED) {
            bool isSame = linkedInfo.networkId == networkId;
            WIFI_LOGE("ConnectToNetwork isCandidate isConnected isSame:%{public}s!", isSame ? "true" : "false");
            if (isSame) {
                return WIFI_OPT_SUCCESS;
            }
        }
        return pService->ConnectToCandidateConfig(uid, networkId);
    }
    return pService->ConnectToNetwork(networkId);
}

ErrCode WifiDeviceServiceImpl::ConnectToDevice(const WifiDeviceConfig &config)
{
    WIFI_LOGI("%{public}s: device address %{private}s, addressType:%{public}d",
        __func__, config.bssid.c_str(), config.bssidType);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("ConnectToDevice:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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
    WifiDeviceConfig updateConfig = config;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (MacAddress::IsValidMac(config.bssid)) {
        if (config.bssidType > REAL_DEVICE_ADDRESS) {
            WIFI_LOGE("%{public}s: invalid bssidType:%{public}d", __func__, config.bssidType);
            return WIFI_OPT_INVALID_PARAM;
        }
        WifiMacAddrInfo macAddrInfo;
        macAddrInfo.bssid = config.bssid;
        macAddrInfo.bssidType = config.bssidType;
        std::string randomMacAddr =
            WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
                macAddrInfo);
        if (randomMacAddr.empty()) {
            WIFI_LOGW("%{public}s: record not found, bssid:%{private}s, bssidType:%{public}d",
                __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
        } else {
            WIFI_LOGI("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
                __func__, config.bssid.c_str(), config.bssidType, randomMacAddr.c_str());
            /* random MAC address are translated into real MAC address */
            if (config.bssidType == RANDOM_DEVICE_ADDRESS) {
                updateConfig.bssid = randomMacAddr;
                updateConfig.bssidType = REAL_DEVICE_ADDRESS;
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
                    __func__, updateConfig.bssid.c_str(), updateConfig.bssidType, randomMacAddr.c_str());
            }
        }
    }
#endif

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("ConnectToNetwork: pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    SetWifiConnectedMode();
    return pService->ConnectToDevice(updateConfig);
}

ErrCode WifiDeviceServiceImpl::StartRoamToNetwork(const int networkId, const std::string bssid, const bool isCandidate)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("%{public}s enter, pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        __FUNCTION__, GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    if (isCandidate) {
        WIFI_LOGE("%{public}s: don't support roam to candidate network", __FUNCTION__);
        return WIFI_OPT_NOT_SUPPORTED;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("%{public}s:VerifyWifiConnectionPermission PERMISSION_DENIED!", __FUNCTION__);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsStaServiceRunning()) {
        WIFI_LOGE("%{public}s: sta service is not running!", __FUNCTION__);
        return WIFI_OPT_STA_NOT_OPENED;
    }
    if (networkId < 0 || (!bssid.empty() && CheckMacIsValid(bssid) != 0)) {
        WIFI_LOGE("%{public}s: invalid param, networkId: %{public}d, bssid:%{public}s",
            __FUNCTION__, networkId, MacAnonymize(bssid).c_str());
        return WIFI_OPT_INVALID_PARAM;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("%{public}s: pService is nullptr!", __FUNCTION__);
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->StartRoamToNetwork(networkId, bssid);
}

ErrCode WifiDeviceServiceImpl::StartConnectToUserSelectNetwork(int networkId, std::string bssid, bool isCandidate)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("%{public}s enter, pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        __FUNCTION__, GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    if (isCandidate) {
        WIFI_LOGE("%{public}s: do not support connect to user select candidate network", __FUNCTION__);
        return WIFI_OPT_NOT_SUPPORTED;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("%{public}s:VerifyWifiConnectionPermission PERMISSION_DENIED!", __FUNCTION__);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsStaServiceRunning()) {
        WIFI_LOGE("%{public}s: sta service is not running", __FUNCTION__);
        return WIFI_OPT_STA_NOT_OPENED;
    }
    if (networkId < 0 || (!bssid.empty() && CheckMacIsValid(bssid) != 0)) {
        WIFI_LOGE("%{public}s: invalid param, networkId: %{public}d, bssid:%{public}s",
            __FUNCTION__, networkId, MacAnonymize(bssid).c_str());
        return WIFI_OPT_INVALID_PARAM;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("%{public}s: pService is nullptr", __FUNCTION__);
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->StartConnectToUserSelectNetwork(networkId, bssid);
}

ErrCode WifiDeviceServiceImpl::IsConnected(bool &isConnected)
{
    WifiLinkedInfo linkedInfo;

    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsConnected:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    isConnected = (linkedInfo.connState == ConnState::CONNECTED);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ReConnect()
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("ReConnect:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
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

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    SetWifiConnectedMode();
    return pService->ReConnect();
}

ErrCode WifiDeviceServiceImpl::ReAssociate(void)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("ReAssociate:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("ReAssociate:VerifySetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReAssociate:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
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

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED &&
        WifiPermissionUtils::VerifyEnterpriseWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Disconnect:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->Disconnect();
}

ErrCode WifiDeviceServiceImpl::StartWps(const WpsConfig &config)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetScanOnlyAvailable: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWps:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->StartWps(config);
}

ErrCode WifiDeviceServiceImpl::CancelWps(void)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetScanOnlyAvailable: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CancelWps:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->CancelWps();
}

ErrCode WifiDeviceServiceImpl::IsWifiActive(bool &bActive)
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
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

    state = WifiConfigCenter::GetInstance().GetWifiState(m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::IsMeteredHotspot(bool &bMeteredHotspot)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsMeteredHotspot:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiLinkedInfo info;
    WifiConfigCenter::GetInstance().GetLinkedInfo(info, m_instId);
    WIFI_LOGI("%{public}s, connState=%{public}d, detailedState=%{public}d",
        __func__, info.connState, info.detailedState);
    if (info.connState != ConnState::CONNECTED) {
        return WIFI_OPT_FAILED;
    }
    bMeteredHotspot = info.isDataRestricted;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetLinkedInfo(WifiLinkedInfo &info)
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiConfigCenter::GetInstance().GetLinkedInfo(info, m_instId);
    if (info.macType == static_cast<int>(WifiPrivacyConfig::DEVICEMAC)) {
        if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetLinkedInfo:VerifyGetWifiLocalMacPermission() PERMISSION_DENIED!");
            /* Clear mac addr */
            info.macAddress = "";
        }
    }

    std::string appId = "";
    std::string packageName = "";
#ifndef OHOS_ARCH_LITE
    GetBundleNameByUid(GetCallingUid(), packageName);
    int32_t userId = static_cast<int32_t>(GetCallingUid() / UID_CALLINGUID_TRANSFORM_DIVISOR);
    appId = GetBundleAppIdByBundleName(userId, packageName);
#endif
    if (ProcessPermissionVerify(appId, packageName) == PERMISSION_DENIED) {
        if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetLinkedInfo:VerifyGetWifiPeersMacPermission() PERMISSION_DENIED!");
#ifdef SUPPORT_RANDOM_MAC_ADDR
        info.bssid = WifiConfigCenter::GetInstance().GetRandomMacAddr(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
            info.bssid);
#else
        /* Clear mac addr */
        info.bssid = "";
#endif
        }
    }

    WIFI_LOGD("GetLinkedInfo, networkId=%{public}d, ssid=%{public}s, rssi=%{public}d, frequency=%{public}d",
              info.networkId, SsidAnonymize(info.ssid).c_str(), info.rssi, info.frequency);
    WIFI_LOGD("GetLinkedInfo, connState=%{public}d, supplicantState=%{public}d, detailedState=%{public}d,\
     wifiStandard=%{public}d RxMaxSpeed=%{public}d TxmaxSpeed=%{public}d rxSpeed=%{public}d txSpeed=%{public}d",
              info.connState, info.supplicantState, info.detailedState, info.wifiStandard,
              info.maxSupportedRxLinkSpeed, info.maxSupportedTxLinkSpeed, info.rxLinkSpeed, info.txLinkSpeed);
    info.isAncoConnected = WifiConfigCenter::GetInstance().GetWifiConnectedMode(m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetDisconnectedReason(DisconnectedReason &reason)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetDisconnectedReason:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDisconnectedReason:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDisconnectedReason:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    WifiLinkedInfo info;
    WifiConfigCenter::GetInstance().GetLinkedInfo(info, m_instId);
    WIFI_LOGI("%{public}s, connState=%{public}d, detailedState=%{public}d",
        __func__, info.connState, info.detailedState);
    if (info.connState == ConnState::CONNECTING || info.connState == ConnState::CONNECTED) {
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().GetDisconnectedReason(reason, m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetIpInfo(IpInfo &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetIpInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetIpInfo(info, m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetIpv6Info(IpV6Info &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetIpv6Info:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetIpv6Info(info, m_instId);
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
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("set country code from external");
    return WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal(countryCode);
#else
    return WIFI_OPT_SUCCESS;
#endif
}

ErrCode WifiDeviceServiceImpl::GetCountryCode(std::string &countryCode)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetCountryCode:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
#ifndef OHOS_ARCH_LITE
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(countryCode);
    WIFI_LOGI("GetCountryCode: country code is %{public}s", countryCode.c_str());
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetWifiDetailState(WifiDetailState &state)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetWifiDetailState: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetWifiDetailState:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetWifiDetailState:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    state = WifiConfigCenter::GetInstance().GetWifiDetailState(m_instId);
    WIFI_LOGI("GetWifiDetailState: state is %{public}d", static_cast<int>(state));
    return WIFI_OPT_SUCCESS;
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiDeviceServiceImpl::RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
#else
ErrCode WifiDeviceServiceImpl::RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
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

    for (const auto &eventName : event) {
        WifiInternalEventDispatcher::GetInstance().SetSingleStaCallback(callback, eventName, m_instId);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSignalLevel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    level = WifiSettings::GetInstance().GetSignalLevel(rssi, band, m_instId);
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
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetDeviceMacAddress:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiLocalMacPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    /* mac will be got from hal when wifi is enabled. if wifi is disabled, we don't return mac. */
    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }
    
    WifiSettings::GetInstance().GetRealMacAddress(result);
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceServiceImpl::SetLowLatencyMode(bool enabled)
{
    WIFI_LOGI("SetLowLatencyMode");
    /* refer to WifiProtectManager::GetInstance().SetLowLatencyMode, DO NOT support now! */
    return true;
}

ErrCode WifiDeviceServiceImpl::CheckCanEnableWifi(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED &&
        WifiPermissionUtils::VerifyEnterpriseWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableWifi:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
#ifndef OHOS_ARCH_LITE
    if (WifiManager::GetInstance().GetWifiEventSubscriberManager()->IsMdmForbidden()) {
        WIFI_LOGE("EnableWifi: Mdm forbidden PERMISSION_DENIED!");
        return WIFI_OPT_ENTERPRISE_DENIED;
    }
#endif

    /**
     * when airplane mode opened, if the config "can_open_sta_when_airplanemode"
     * opened, then can open sta; other, return forbid.
     */
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN &&
        !WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode(m_instId)) {
        WIFI_LOGI("current airplane mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
    /* when power saving mode opened, can't open sta, return forbid. */
    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGI("current power saving mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }
#ifndef OHOS_ARCH_LITE
    if (WifiManager::GetInstance().GetWifiTogglerManager()->IsSatelliteStateStart()) {
        WIFI_LOGI("current satellite mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
#endif
    /**
     * Check the interval between the last STA shutdown and the current STA
     * startup.
     */
    double interval = WifiConfigCenter::GetInstance().GetWifiStaInterval(m_instId);
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
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState(m_instId);
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGW("current wifi state is %{public}d, instId: %{public}d", static_cast<int>(curState), m_instId);
        return false;
    }
    return true;
}

bool WifiDeviceServiceImpl::IsScanServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetScanMidState(m_instId);
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

        enum {BAND_2GHZ = 1, BAND_5GHZ = 2, BAND_6GHZ = 3, BAND_60GHZ = 4, BAND_ANY = 5};
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
                case BAND_6GHZ:
                    retStr = "6GHz";
                    break;
                case BAND_60GHZ:
                    retStr = "60GHz";
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

        int level = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band);
        ss << "  Connection.signalLevel: " << level << "\n";
        result += ss.str();
    }
    result += "\n";

    std::string cc = "CN";
#ifndef OHOS_ARCH_LITE
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(cc);
#endif
    result.append("Country Code: ").append(cc);
    result += "\n";
}

ErrCode WifiDeviceServiceImpl::GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetChangeDeviceConfig:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetChangeDeviceConfig:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetChangeDeviceConfig:VerifyGetScanInfosPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
    }

    bool result = WifiConfigCenter::GetInstance().GetChangeDeviceConfig(value, config);
    if (!result) {
        WIFI_LOGE("WifiDeviceServiceImpl::GetChangeDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceServiceImpl::IsRemoteDied(void)
{
    return false;
}

ErrCode WifiDeviceServiceImpl::IsBandTypeSupported(int bandType, bool &supported)
{
    WIFI_LOGI("Enter get bandtype is supported.");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsBandTypeSupported:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (bandType <= (int)BandType::BAND_NONE || bandType >= (int)BandType::BAND_ANY) {
        WIFI_LOGE("IsBandTypeSupported bandType error %{public}d!", bandType);
        return WIFI_OPT_INVALID_PARAM;
    } else {
        ChannelsTable channels;
        WifiChannelHelper::GetInstance().GetValidChannels(channels);
        supported = channels.find((BandType)bandType) != channels.end();
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::Get5GHzChannelList(std::vector<int> &result)
{
    WIFI_LOGI("Enter get 5g channel list.");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("Get5GHzChannelList: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Get5GHzChannelList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Get5GHzChannelList:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    ChannelsTable channels;
    WifiChannelHelper::GetInstance().GetValidChannels(channels);
    if (channels.find(BandType::BAND_5GHZ) != channels.end()) {
        result = channels[BandType::BAND_5GHZ];
    }
    
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::StartPortalCertification()
{
    WIFI_LOGI("Enter StartPortalCertification.");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("StartPortalCertification: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartPortalCertification:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartPortalCertification:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }

    return pService->StartPortalCertification();
}

ErrCode WifiDeviceServiceImpl::FactoryReset()
{
    WIFI_LOGI("Enter FactoryReset.");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("FactoryReset: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:FactoryReset() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:FactoryReset() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WIFI_LOGI("WifiDeviceServiceImpl FactoryReset sta,p2p,hotspot! m_instId:%{public}d", m_instId);
    if (m_instId == INSTID_WLAN0 || m_instId == INSTID_WLAN1) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_SEMI_ENABLED, m_instId);
#ifndef OHOS_ARCH_LITE
        WifiSettings::GetInstance().SetWifiToggleCaller(GetCallingPid(), m_instId);
#endif
    }
    WifiManager::GetInstance().GetWifiTogglerManager()->StartSemiWifiToggledTimer();
    WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, m_instId);
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(m_instId);
    WIFI_LOGI("WifiDeviceServiceImpl curState:%{public}d", curState);
    if (curState == WifiOprMidState::RUNNING) {
        WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, m_instId);
    }
    // wifi device
    WifiSettings::GetInstance().ClearDeviceConfig();
    WifiSettings::GetInstance().SyncDeviceConfig();
    /* p2p */
    WifiSettings::GetInstance().RemoveWifiP2pGroupInfo();
    WifiSettings::GetInstance().SyncWifiP2pGroupInfoConfig();
    WifiSettings::GetInstance().RemoveWifiP2pSupplicantGroupInfo();
    /* Hotspot */
    WifiSettings::GetInstance().ClearHotspotConfig();
    WifiSettings::GetInstance().SyncHotspotConfig();
    WIFI_LOGI("WifiDeviceServiceImpl FactoryReset ok!");
    return WIFI_OPT_SUCCESS;
}

bool ComparedHinlinkKeymgmt(const std::string scanInfoKeymgmt, const std::string deviceKeymgmt)
{
    if (deviceKeymgmt == "WPA-PSK") {
        return scanInfoKeymgmt.find("PSK") != std::string::npos;
    } else if (deviceKeymgmt == "WPA-EAP") {
        return scanInfoKeymgmt.find("EAP") != std::string::npos;
    } else if (deviceKeymgmt == "SAE") {
        return scanInfoKeymgmt.find("SAE") != std::string::npos;
    } else if (deviceKeymgmt == "NONE") {
        return (scanInfoKeymgmt.find("PSK") == std::string::npos) &&
               (scanInfoKeymgmt.find("EAP") == std::string::npos) && (scanInfoKeymgmt.find("SAE") == std::string::npos);
    } else {
        return false;
    }
}

ErrCode WifiDeviceServiceImpl::HilinkGetMacAddress(WifiDeviceConfig &deviceConfig, std::string &currentMac)
{
#ifndef SUPPORT_LOCAL_RANDOM_MAC
    WifiSettings::GetInstance().GetRealMacAddress(currentMac, m_instId);
#else
    if (deviceConfig.wifiPrivacySetting == WifiPrivacyConfig::DEVICEMAC) {
        WifiSettings::GetInstance().GetRealMacAddress(currentMac, m_instId);
    } else {
        WifiStoreRandomMac randomMacInfo;
        std::vector<WifiScanInfo> scanInfoList;
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
        for (auto scanInfo : scanInfoList) {
            if ((deviceConfig.ssid == scanInfo.ssid) &&
                (ComparedHinlinkKeymgmt(scanInfo.capabilities, deviceConfig.keyMgmt))) {
                randomMacInfo.ssid = scanInfo.ssid;
                randomMacInfo.keyMgmt = deviceConfig.keyMgmt;
                randomMacInfo.preSharedKey = deviceConfig.preSharedKey;
                randomMacInfo.peerBssid = scanInfo.bssid;
                break;
            }
        }
        if (randomMacInfo.ssid.empty()) {
            LOGE("EnableHiLinkHandshake scanInfo has no target wifi!");
            return WIFI_OPT_FAILED;
        }

        WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
        if (randomMacInfo.randomMac.empty()) {
            /* Sets the MAC address of WifiSettings. */
            std::string macAddress;
            std::string deviceConfigKey = randomMacInfo.ssid + randomMacInfo.keyMgmt;
            int ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(deviceConfigKey, macAddress);
            if (ret != 0) {
                ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(deviceConfigKey, macAddress);
            }
            if (ret != 0) {
                WIFI_LOGI("HilinkGetMacAddress Failed to generate MAC address, Using locally generated MAC.");
                WifiRandomMacHelper::GenerateRandomMacAddress(macAddress);
            }
            randomMacInfo.randomMac = macAddress;
            LOGI("%{public}s: generate a random mac, randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
                __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
                MacAnonymize(randomMacInfo.peerBssid).c_str());
            WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
        } else {
            LOGI("%{public}s: randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
                __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
                MacAnonymize(randomMacInfo.peerBssid).c_str());
        }
        currentMac = randomMacInfo.randomMac;
    }
    WIFI_LOGI("EnableHiLinkHandshake mac address get success, mac = %{public}s", MacAnonymize(currentMac).c_str());
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig)
{
    WIFI_LOGI("EnableHiLinkHandshake enter");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("EnableHiLinkHandshake: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHiLinkHandshake:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHiLinkHandshake:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    char cmd[HILINK_CMD_MAX_LEN] = {0};
    if (!uiFlag) {
        if (sprintf_s(cmd, sizeof(cmd), "ENABLE=%d BSSID=%s", uiFlag, bssid.c_str()) < 0) {
            WIFI_LOGE("uiFlag false copy enable and bssid error!");
            return WIFI_OPT_FAILED;
        }
        g_hiLinkActive = uiFlag;
        pService->EnableHiLinkHandshake(deviceConfig, cmd);
        return WIFI_OPT_SUCCESS;
    }
    if (!g_hiLinkActive) {
        if (sprintf_s(cmd, sizeof(cmd), "ENABLE=%d BSSID=%s", uiFlag, bssid.c_str()) < 0) {
            WIFI_LOGE("g_hiLinkActive copy enable and bssid error!");
            return WIFI_OPT_FAILED;
        }
        pService->EnableHiLinkHandshake(deviceConfig, cmd);
    }

    std::string currentMac;
    if (HilinkGetMacAddress(deviceConfig, currentMac) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    g_hiLinkActive = uiFlag;

    (void)memset_s(cmd, sizeof(cmd), 0x0, sizeof(cmd));
    if (sprintf_s(cmd, sizeof(cmd), "HILINK_MAC=%s", currentMac.c_str()) < 0) {
        WIFI_LOGE("g_hiLinkActive copy mac error!");
        return WIFI_OPT_FAILED;
    }
    pService->DeliverStaIfaceData(cmd);

    WIFI_LOGI("WifiDeviceServiceImpl EnableHiLinkHandshake ok!");
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode WifiDeviceServiceImpl::LimitSpeed(const int controlId, const int limitMode)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("%{public}s enter, pid:%{public}d, uid:%{public}d, BundleName:%{public}s.",
        __FUNCTION__, GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
#endif
    WIFI_LOGI("Enter LimitSpeed.");
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("%{public}s NOT NATIVE PROCESS, PERMISSION_DENIED!", __FUNCTION__);
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("%{public}s PERMISSION_DENIED!", __FUNCTION__);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    AppNetworkSpeedLimitService::GetInstance().LimitSpeed(controlId, limitMode);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam)
{
    WIFI_LOGI("%{public}s enter, pid:%{public}d, uid:%{public}d",
        __FUNCTION__, GetCallingPid(), GetCallingUid());
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("%{public}s PERMISSION_DENIED!", __FUNCTION__);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s pEnhanceService is nullptr!", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    if (pEnhanceService->SetLowTxPower(wifiLowPowerParam)) {
        WIFI_LOGE("%{public}s set low tx power fail!", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::SetAppFrozen(std::set<int> pidList, bool isFrozen)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("SetAppFrozen:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:SetAppFrozen() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:SetAppFrozen() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiInternalEventDispatcher::GetInstance().SetAppFrozen(pidList, isFrozen);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ResetAllFrozenApp()
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("ResetAllFrozenApp:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:ResetAllFrozenApp() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("WifiDeviceServiceImpl:ResetAllFrozenApp() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiInternalEventDispatcher::GetInstance().ResetAllFrozenApp();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::DisableAutoJoin(const std::string &conditionName)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisableAutoJoin:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DisableAutoJoin(conditionName);
}

ErrCode WifiDeviceServiceImpl::EnableAutoJoin(const std::string &conditionName)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("EnableAutoJoin:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->EnableAutoJoin(conditionName);
}

ErrCode WifiDeviceServiceImpl::RegisterAutoJoinCondition(const std::string &conditionName,
                                                         const std::function<bool()> &autoJoinCondition)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("RegisterAutoJoinCondition:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterAutoJoinCondition:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RegisterAutoJoinCondition(conditionName, autoJoinCondition);
}

ErrCode WifiDeviceServiceImpl::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("DeregisterAutoJoinCondition:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeregisterAutoJoinCondition:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DeregisterAutoJoinCondition(conditionName);
}

ErrCode WifiDeviceServiceImpl::RegisterFilterBuilder(const FilterTag &filterTag,
                                                     const std::string &builderName,
                                                     const FilterBuilder &filterBuilder)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("RegisterFilterBuilder:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RegisterFilterBuilder(filterTag, builderName, filterBuilder);
}

ErrCode WifiDeviceServiceImpl::DeregisterFilterBuilder(const FilterTag &filterTag,
                                                       const std::string &builderName)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("DeregisterFilterBuilder:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeregisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DeregisterFilterBuilder(filterTag, builderName);
}

ErrCode WifiDeviceServiceImpl::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                                     const CommonBuilder &commonBuilder)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("RegisterFilterBuilder:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->RegisterCommonBuilder(tagType, tagName, commonBuilder);
}

ErrCode WifiDeviceServiceImpl::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("DeregisterFilterBuilder:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeregisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return WIFI_OPT_STA_NOT_OPENED;
    }
    return pService->DeregisterCommonBuilder(tagType, tagName);
}

ErrCode WifiDeviceServiceImpl::SetSatelliteState(const int state)
{
    WIFI_LOGI("Enter SetSatelliteState");

    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("SetSatelliteState:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetSatelliteState:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetSatelliteState:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    return WifiManager::GetInstance().GetWifiTogglerManager()->SatelliteToggled(state);
}

ErrCode WifiDeviceServiceImpl::OnBackup(MessageParcel& data, MessageParcel& reply)
{
    UniqueFd fd(-1);
    std::string replyCode = WifiSettings::GetInstance().SetBackupReplyCode(0);
    std::string backupInfo = data.ReadString();
    int ret = WifiSettings::GetInstance().OnBackup(fd, backupInfo);
    std::fill(backupInfo.begin(), backupInfo.end(), 0);
    if (ret < 0) {
        WIFI_LOGE("OnBackup fail: backup data fail!");
        replyCode = WifiSettings::GetInstance().SetBackupReplyCode(EXTENSION_ERROR_CODE);
    }
    if (reply.WriteFileDescriptor(fd) == false || reply.WriteString(replyCode) == false) {
        close(fd.Release());
        WifiSettings::GetInstance().RemoveBackupFile();
        WIFI_LOGE("OnBackup fail: reply write fail!");
        return WIFI_OPT_FAILED;
    }
    close(fd.Release());
    WifiSettings::GetInstance().RemoveBackupFile();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::OnRestore(MessageParcel& data, MessageParcel& reply)
{
    UniqueFd fd(data.ReadFileDescriptor());
    std::string replyCode = WifiSettings::GetInstance().SetBackupReplyCode(0);
    std::string restoreInfo = data.ReadString();
    int ret = WifiSettings::GetInstance().OnRestore(fd, restoreInfo);
    std::fill(restoreInfo.begin(), restoreInfo.end(), 0);
    if (ret < 0) {
        WIFI_LOGE("OnRestore fail: restore data fail!");
        replyCode = WifiSettings::GetInstance().SetBackupReplyCode(EXTENSION_ERROR_CODE);
    }
    if (reply.WriteString(replyCode) == false) {
        close(fd.Release());
        WifiSettings::GetInstance().RemoveBackupFile();
        WIFI_LOGE("OnRestore fail: reply write fail!");
        return WIFI_OPT_FAILED;
    }
    close(fd.Release());
    WifiSettings::GetInstance().RemoveBackupFile();
    return WIFI_OPT_SUCCESS;
}
#endif

int WifiDeviceServiceImpl::ProcessPermissionVerify(const std::string &appId, const std::string &packageName)
{
    if (appId.empty() || packageName.empty()) {
        WIFI_LOGI("ProcessPermissionVerify(), PERMISSION_DENIED");
        return PERMISSION_DENIED;
    }
    std::map<std::string, std::vector<std::string>> filterMap;
    if (WifiSettings::GetInstance().GetPackageFilterMap(filterMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetPackageInfoMap failed");
        return PERMISSION_DENIED;
    }
    std::vector<std::string> whilteListProcessInfo = filterMap["GetLinkProcessPermissionVerify"];
    auto iter = whilteListProcessInfo.begin();
    while (iter != whilteListProcessInfo.end()) {
        if (*iter == packageName + "|" + appId) {
            return PERMISSION_GRANTED;
        }
        iter++;
    }
    return PERMISSION_DENIED;
}
}  // namespace Wifi
}  // namespace OHOS