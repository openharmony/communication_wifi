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

#include "sta_service.h"
#include "sta_define.h"
#include "sta_service_callback.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher.h"
#include "wifi_country_code_manager.h"
#include "wifi_notification_util.h"
#include "wifi_history_record_manager.h"
#endif
#include "wifi_logger.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_cert_utils.h"
#include "wifi_cmd_client.h"
#include "wifi_common_util.h"
#include "network_selection_manager.h"
#include "wifi_config_center.h"
#include "external_wifi_filter_builder_manager.h"
#include "external_wifi_common_builder_manager.h"
#include "block_connect_service.h"
#include "parameters.h"
#include "wifi_telephony_utils.h"
#include "wifi_service_manager.h"
DEFINE_WIFILOG_LABEL("StaService");

namespace OHOS {
namespace Wifi {

constexpr const int REMOVE_ALL_DEVICECONFIG = 0x7FFFFFFF;
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT

#endif

#define EAP_AUTH_IMSI_MCC_POS 0
#define EAP_AUTH_MAX_MCC_LEN  3
#define EAP_AUTH_IMSI_MNC_POS 3
#define EAP_AUTH_MIN_MNC_LEN  2
#define EAP_AUTH_MAX_MNC_LEN  3
#define EAP_AUTH_MIN_PLMN_LEN  5
#define EAP_AUTH_MAX_PLMN_LEN  6
#define EAP_AUTH_MAX_IMSI_LENGTH 15
#define INVALID_SUPPLIER_ID 0

#define EAP_AKA_PERMANENT_PREFIX "0"
#define EAP_SIM_PERMANENT_PREFIX "1"
#define EAP_AKA_PRIME_PERMANENT_PREFIX "6"

#define EAP_AUTH_WLAN_MNC "@wlan.mnc"
#define EAP_AUTH_WLAN_MCC ".mcc"
#define EAP_AUTH_PERMANENT_SUFFIX ".3gppnetwork.org"
#define ENABLE_BACK_AUDIO "persist.booster.enable_back_audio"

const int WIFI_DETECT_MODE_LOW = 1;
const int WIFI_DETECT_MODE_HIGH = 2;
 
const std::string VOWIFI_DETECT_SET_PREFIX = "VOWIFI_DETECT SET ";

StaService::StaService(int instId)
    : pStaStateMachine(nullptr),
      pStaMonitor(nullptr),
      pStaAutoConnectService(nullptr),
      m_instId(instId)
{}

StaService::~StaService()
{
    WIFI_LOGI("Enter ~StaService");
    if (pStaMonitor != nullptr) {
        pStaMonitor->UnInitStaMonitor();
        delete pStaMonitor;
        pStaMonitor = nullptr;
    }

    if (pStaAutoConnectService != nullptr) {
        delete pStaAutoConnectService;
        pStaAutoConnectService = nullptr;
    }

    if (pStaStateMachine != nullptr) {
        delete pStaStateMachine;
        pStaStateMachine = nullptr;
    }
}

ErrCode StaService::InitStaService(const std::vector<StaServiceCallback> &callbacks)
{
    WIFI_LOGI("Enter InitStaService m_instId:%{public}d\n", m_instId);
    pStaStateMachine = new (std::nothrow) StaStateMachine(m_instId);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("Alloc pStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaStateMachine->InitStaStateMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    RegisterStaServiceCallback(callbacks);

    pStaMonitor = new (std::nothrow) StaMonitor(m_instId);
    if (pStaMonitor == nullptr) {
        WIFI_LOGE("Alloc pStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaMonitor->InitStaMonitor() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    pStaMonitor->SetStateMachine(pStaStateMachine);

    if (m_instId == INSTID_WLAN0) {
        pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine, m_instId);
        if (pStaAutoConnectService == nullptr) {
            WIFI_LOGE("Alloc pStaAutoConnectService failed.\n");
            return WIFI_OPT_FAILED;
        }
        if (pStaAutoConnectService->InitAutoConnectService() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitAutoConnectService failed.\n");
            return WIFI_OPT_FAILED;
        }
        pStaAutoConnectService->SetAutoConnectStateCallback(callbacks);
#ifndef OHOS_ARCH_LITE
        GetStaControlInfo();
#endif
    }
    WIFI_LOGI("Init staservice successfully.\n");
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
void StaService::GetStaControlInfo()
{
    WIFI_LOGI("Enter GetStaControlInfo.");
    std::map<std::string, std::vector<PackageInfo>> packageInfoMap;
    if (WifiSettings::GetInstance().GetPackageInfoMap(packageInfoMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetPackageInfoMap failed");
    }
    sta_candidate_trust_list = packageInfoMap["CandidateFilterPackages"];
    return;
}

bool StaService::IsAppInCandidateFilterList(int uid) const
{
    std::string packageName;
    GetBundleNameByUid(uid, packageName);
    for (auto iter = sta_candidate_trust_list.begin(); iter != sta_candidate_trust_list.end(); iter++) {
        if (iter->name == packageName) {
            WIFI_LOGI("App is in Candidate filter list.");
            return true;
        }
    }
    return false;
}
#endif

ErrCode StaService::EnableStaService()
{
    WIFI_LOGI("Enter EnableStaService m_instId:%{public}d\n", m_instId);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        // notification of registration country code change
        std::string moduleName = "StaService_" + std::to_string(m_instId);
        m_staObserver = std::make_shared<WifiCountryCodeChangeObserver>(moduleName, *pStaStateMachine);
        if (m_staObserver == nullptr) {
            WIFI_LOGI("m_staObserver is null\n");
            return WIFI_OPT_FAILED;
        }
        WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_staObserver);
#endif
        WifiSettings::GetInstance().ReloadDeviceConfig();
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_ENABLE_STA);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableStaService() const
{
    WIFI_LOGI("Enter DisableStaService.\n");
#ifndef OHOS_ARCH_LITE
    if (m_instId == INSTID_WLAN0) {
        // deregistration country code change notification
        WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(m_staObserver);
    }
#endif
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISABLE_STA);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId) const
{
    LOGI("Enter AddCandidateConfig.\n");

    netWorkId = INVALID_NETWORK_ID;
    constexpr int UID_UNTRUSTED_CONFIG_LEN = 16;
    std::vector<WifiDeviceConfig> tempConfigs;
    WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
    if (tempConfigs.size() >= UID_UNTRUSTED_CONFIG_LEN) {
        LOGE("AddCandidateConfig failed, exceed max num: %{public}d\n", UID_UNTRUSTED_CONFIG_LEN);
        return WIFI_OPT_FAILED;
    }

    if (config.keyMgmt == KEY_MGMT_WEP) {
#ifndef OHOS_ARCH_LITE
        auto wifiBrokerFrameProcessName = WifiSettings::GetInstance().GetPackageName("anco_broker_name");
        std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
        if (wifiBrokerFrameProcessName.empty() || ancoBrokerFrameProcessName != wifiBrokerFrameProcessName) {
            LOGE("AddCandidateConfig unsupport wep key!");
            return WIFI_OPT_NOT_SUPPORTED;
        }
#else
        LOGE("AddCandidateConfig unsupport wep key!");
        return WIFI_OPT_NOT_SUPPORTED;
#endif
    }
    WifiDeviceConfig tempDeviceConfig = config;
    tempDeviceConfig.uid = uid;
#ifndef OHOS_ARCH_LITE
    if (IsAppInCandidateFilterList(uid)) {
        tempDeviceConfig.isShared = true;
        tempDeviceConfig.isEphemeral = false;
    } else {
        tempDeviceConfig.isShared = false;
    }
#endif
    netWorkId = AddDeviceConfig(tempDeviceConfig);
    return (netWorkId == INVALID_NETWORK_ID) ? WIFI_OPT_FAILED : WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveCandidateConfig(const int uid, const int networkId) const
{
    LOGD("Enter RemoveCandidateConfig.\n");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetCandidateConfig(uid, networkId, config) == INVALID_NETWORK_ID) {
        LOGE("RemoveCandidateConfig-GetCandidateConfig no foud failed!");
        return WIFI_OPT_FAILED;
    }

    /* Remove network configuration. */
    return RemoveDevice(config.networkId);
}

ErrCode StaService::RemoveAllCandidateConfig(const int uid) const
{
    LOGD("Enter RemoveAllCandidateConfig.\n");
    std::vector<WifiDeviceConfig> tempConfigs;
    WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
    for (const auto &config : tempConfigs) {
        if (RemoveDevice(config.networkId) != WIFI_OPT_SUCCESS) {
            LOGE("RemoveAllCandidateConfig-RemoveDevice() failed!");
        }
    }
    return WIFI_OPT_SUCCESS;
}

void StaService::NotifyCandidateApprovalStatus(CandidateApprovalStatus status) const
{
#ifndef OHOS_ARCH_LITE
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CANDIDATE_CONNECT_CHANGE;
    cbMsg.msgData = static_cast<int>(status);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#endif
}

ErrCode StaService::ConnectToCandidateConfig(const int uid, const int networkId) const
{
    LOGI("Enter ConnectToCandidateConfig.\n");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetCandidateConfig(uid, networkId, config) == INVALID_NETWORK_ID) {
        LOGE("ConnectToCandidateConfig:GetCandidateConfig is null!");
        return WIFI_OPT_FAILED;
    }
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    if (pStaStateMachine->WhetherRestrictedByMdm(config.ssid, config.bssid, false)) {
        LOGD("ConnectToCandiateConfig RestrictedByMdm");
        pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL);
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(config.networkId,
            DisabledReason::DISABLED_MDM_RESTRICTED);
        return WIFI_OPT_FAILED;
    }
#endif
#ifndef OHOS_ARCH_LITE
    if (!WifiConfigCenter::GetInstance().IsAllowPopUp() || !IsBundleInstalled("com.ohos.locationdialog")) {
        LOGE("ConnectToCandidateConfig: not support to show dialog!");
        return WIFI_OPT_NOT_SUPPORTED;
    }
    if (config.lastConnectTime <= 0) {
        WifiConfigCenter::GetInstance().SetSelectedCandidateNetworkId(networkId);
        WifiNotificationUtil::GetInstance().ShowDialog(WifiDialogType::CANDIDATE_CONNECT, config.ssid);
        return WIFI_OPT_SUCCESS;
    }
#endif
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SetPortalBrowserFlag(false);
    NotifyCandidateApprovalStatus(CandidateApprovalStatus::USER_ACCEPT);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_USER);
    return WIFI_OPT_SUCCESS;
}


std::string StaService::GetMcc(const std::string &imsi) const
{
    return imsi.substr(EAP_AUTH_IMSI_MCC_POS, EAP_AUTH_MAX_MCC_LEN);
}

std::string StaService::GetMnc(const std::string &imsi, const int mncLen) const
{
    return imsi.substr(EAP_AUTH_IMSI_MNC_POS, mncLen);
}

void StaService::UpdateEapConfig(const WifiDeviceConfig &config, WifiEapConfig &wifiEapConfig) const
{
    std::string eapMethod = config.wifiEapConfig.eap;

    LOGI("Enter StaService::UpdateEapConfig, eapMethod:%{public}s", eapMethod.c_str());
    std::string prefix;
    if (eapMethod == EAP_METHOD_SIM) {
        prefix = EAP_SIM_PERMANENT_PREFIX;
    } else if (eapMethod == EAP_METHOD_AKA) {
        prefix = EAP_AKA_PERMANENT_PREFIX;
    } else if (eapMethod == EAP_METHOD_AKA_PRIME) {
        prefix = EAP_AKA_PRIME_PERMANENT_PREFIX;
    } else {
        return;
    }
    int32_t slotId = WifiTelephonyUtils::GetSlotId(config.wifiEapConfig.eapSubId);
    if (slotId == -1) {
        return;
    }

    std::string imsi = WifiTelephonyUtils::GetImsi(slotId);
    if (imsi.empty() || imsi.length() > EAP_AUTH_MAX_IMSI_LENGTH) {
        LOGE("invalid imsi, length: %{public}zu", imsi.length());
        return;
    }

    std::string mnc;
    std::string plmn = WifiTelephonyUtils::GetPlmn(slotId);
    LOGI("imsi: %{private}s, plmn: %{public}s", imsi.c_str(), plmn.c_str());
    if (plmn.length() == EAP_AUTH_MIN_PLMN_LEN) {
        mnc = "0" + GetMnc(imsi, EAP_AUTH_MIN_MNC_LEN);
    } else if (plmn.length() == EAP_AUTH_MAX_PLMN_LEN) {
        mnc = GetMnc(imsi, EAP_AUTH_MAX_MNC_LEN);
    } else {
        LOGE("invalid plmn, length: %{public}zu", plmn.length());
        return;
    }

    // identity: prefix + imsi + "@wlan.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
    std::string identity = prefix + imsi + EAP_AUTH_WLAN_MNC + mnc +
        EAP_AUTH_WLAN_MCC + GetMcc(imsi) + EAP_AUTH_PERMANENT_SUFFIX;
    LOGI("StaService::UpdateEapConfig, identity: %{public}s", identity.c_str());
    wifiEapConfig.identity = identity;
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
ErrCode StaService::SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList) const
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    if (WifiSettings::GetInstance().FindWifiBlockListConfig(linkedInfo.ssid, linkedInfo.bssid, 0)) {
        CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
        pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_NETWORK_REMOVED, linkedInfo.networkId);
        WifiSettings::GetInstance().RemoveConnectChoiceFromAllNetwork(linkedInfo.networkId);
    }
    return WIFI_OPT_SUCCESS;
}
#endif

int StaService::AddDeviceConfig(const WifiDeviceConfig &config) const
{
    LOGI("Enter AddDeviceConfig, ssid:%{public}s, bssid=%{public}s, keyMgmt: %{public}s\n",
        SsidAnonymize(config.ssid).c_str(), MacAnonymize(config.bssid).c_str(), config.keyMgmt.c_str());
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    int netWorkId = INVALID_NETWORK_ID;
    bool isUpdate = false;
    std::string bssid;
    std::string userSelectbssid = config.bssid;
    WifiDeviceConfig tempDeviceConfig;
    tempDeviceConfig.instanceId = config.instanceId;
    if (FindDeviceConfig(config, tempDeviceConfig) == 0) {
        netWorkId = tempDeviceConfig.networkId;
        if (m_instId == INSTID_WLAN0) {
            CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
            bssid = config.bssid.empty() ? tempDeviceConfig.bssid : config.bssid;
            pStaAutoConnectService->EnableOrDisableBssid(bssid, true, 0);
        }
        isUpdate = true;
        LOGI("AddDeviceConfig update device networkId:%{public}d", netWorkId);
    } else {
        netWorkId = WifiSettings::GetInstance().GetNextNetworkId();
        LOGI("AddDeviceConfig alloc new id[%{public}d] succeed!", netWorkId);
    }
    tempDeviceConfig = config;
    tempDeviceConfig.numAssociation = 0;
    tempDeviceConfig.instanceId = m_instId;
    tempDeviceConfig.networkId = netWorkId;
    tempDeviceConfig.userSelectBssid = userSelectbssid;
    if (!bssid.empty()) {
        tempDeviceConfig.bssid = bssid;
    }
    if (config.wifiEapConfig.eap == EAP_METHOD_TLS && config.wifiEapConfig.certEntry.size() > 0 &&
        config.wifiEapConfig.clientCert.empty() && config.wifiEapConfig.privateKey.empty()) {
        std::string uri;
        std::string formatSsid = config.ssid;
        for (int i = 0; i < (int)formatSsid.size(); i++) {
            // other char is invalid in certificate manager
            if (!isalnum(formatSsid[i]) && formatSsid[i] != '_') {
                formatSsid[i] = '_';
            }
        }
        std::string alias = formatSsid + "_TLS_" + std::to_string(config.uid < 0 ? 0 : config.uid);
        int ret = WifiCertUtils::InstallCert(config.wifiEapConfig.certEntry,
            std::string(config.wifiEapConfig.certPassword), alias, uri);
        if (ret == 0) {
            tempDeviceConfig.wifiEapConfig.clientCert = uri;
            tempDeviceConfig.wifiEapConfig.privateKey = uri;
            LOGI("success to install cert: %{public}s", tempDeviceConfig.wifiEapConfig.clientCert.c_str());
        } else {
            LOGE("failed to install cert: %{public}d, alias: %{public}s", ret, alias.c_str());
        }
    }

    UpdateEapConfig(config, tempDeviceConfig.wifiEapConfig);
    WifiSettings::GetInstance().SetKeyMgmtBitset(tempDeviceConfig);

    /* Add the new network to WifiSettings. */
    if (!WifiSettings::GetInstance().EncryptionDeviceConfig(tempDeviceConfig)) {
        LOGI("AddDeviceConfig EncryptionDeviceConfig failed");
    }
    tempDeviceConfig.lastUpdateTime = time(0);
    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    /* update net link proxy info */
    pStaStateMachine->ReUpdateNetLinkInfo(tempDeviceConfig);
    ConfigChange changeType = isUpdate ? ConfigChange::CONFIG_UPDATE : ConfigChange::CONFIG_ADD;
    NotifyDeviceConfigChange(changeType, tempDeviceConfig, false);
    return netWorkId;
}

int StaService::UpdateDeviceConfig(const WifiDeviceConfig &config) const
{
    return AddDeviceConfig(config);
}

ErrCode StaService::RemoveDevice(int networkId) const
{
    LOGI("Enter RemoveDevice, networkId = %{public}d m_instId:%{public}d\n", networkId, m_instId);

    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_NETWORK_REMOVED, networkId);

    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) == 0) {
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    } else {
        LOGE("RemoveDevice, networkId = %{public}d do not exist.\n", networkId);
        return WIFI_OPT_FAILED;
    }
    /* Remove network configuration directly without notification to InterfaceService. */
    WifiSettings::GetInstance().RemoveDevice(networkId);
    WifiSettings::GetInstance().RemoveConnectChoiceFromAllNetwork(networkId);
    WifiSettings::GetInstance().SyncDeviceConfig();
    NotifyDeviceConfigChange(ConfigChange::CONFIG_REMOVE, config, false);
#ifndef OHOS_ARCH_LITE
    WifiHistoryRecordManager::GetInstance().DeleteApInfo(config.ssid, config.keyMgmt);
    auto wifiBrokerFrameProcessName = WifiSettings::GetInstance().GetPackageName("anco_broker_name");
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (!wifiBrokerFrameProcessName.empty() && ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
        config.callProcessName = wifiBrokerFrameProcessName;
    } else {
        config.callProcessName = "";
    }
    WifiConfigCenter::GetInstance().SetChangeDeviceConfig(ConfigChange::CONFIG_REMOVE, config);
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveAllDevice() const
{
    LOGI("Enter RemoveAllDevice.\n");
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().ClearDeviceConfig(ifaceName) == WIFI_HAL_OPT_OK) {
        LOGD("Remove all device config successfully!");
    } else {
        LOGE("WifiStaHalInterface:RemoveAllDevice failed!");
        return WIFI_OPT_FAILED;
    }

    WifiSettings::GetInstance().ClearDeviceConfig();
    if (WifiSettings::GetInstance().SyncDeviceConfig() != 0) {
        LOGE("RemoveAllDevice-SyncDeviceConfig() failed!");
        return WIFI_OPT_FAILED;
    }
    WifiDeviceConfig config;
    NotifyDeviceConfigChange(ConfigChange::CONFIG_REMOVE, config, true);
#ifndef OHOS_ARCH_LITE
    WifiHistoryRecordManager::GetInstance().DeleteAllApInfo();
    config.networkId = REMOVE_ALL_DEVICECONFIG;
    auto wifiBrokerFrameProcessName = WifiSettings::GetInstance().GetPackageName("anco_broker_name");
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (!wifiBrokerFrameProcessName.empty() && ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
        config.callProcessName = wifiBrokerFrameProcessName;
    } else {
        config.callProcessName = "";
    }
    WifiConfigCenter::GetInstance().SetChangeDeviceConfig(ConfigChange::CONFIG_REMOVE, config);
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectToDevice(const WifiDeviceConfig &config) const
{
    LOGI(
        "Enter ConnectToDevice, ssid = %{public}s instId:%{public}d. \n", SsidAnonymize(config.ssid).c_str(), m_instId);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    if (pStaStateMachine->WhetherRestrictedByMdm(config.ssid, config.bssid, false)) {
        LOGD("ConnectToDevice RestrictedByMdm");
        pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL);
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(config.networkId,
            DisabledReason::DISABLED_MDM_RESTRICTED);
        return WIFI_OPT_FAILED;
    }
#endif
    int netWorkId = AddDeviceConfig(config);
    if (netWorkId == INVALID_NETWORK_ID) {
        LOGD("ConnectToDevice, AddDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("ConnectToDevice, netWorkId: %{public}d", netWorkId);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, netWorkId, NETWORK_SELECTED_BY_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectToNetwork(int networkId, int type) const
{
    LOGI("Enter ConnectToNetwork, networkId is %{public}d.", networkId);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        LOGE("WifiDeviceConfig is null!");
        return WIFI_OPT_FAILED;
    }
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    if (pStaStateMachine->WhetherRestrictedByMdm(config.ssid, config.bssid, false)) {
        LOGD("ConnectToNetwork RestrictedByMdm");
        pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL);
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(config.networkId,
            DisabledReason::DISABLED_MDM_RESTRICTED);
        return WIFI_OPT_FAILED;
    }
#endif
    LOGI("ConnectToNetwork, ssid = %{public}s.", SsidAnonymize(config.ssid).c_str());
    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SetPortalBrowserFlag(false);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, type);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartConnectToBssid(const int32_t networkId, const std::string bssid, int32_t type) const
{
    LOGI("Enter StartConnectToBssid, networkId: %{public}d, bssid: %{public}s", networkId, MacAnonymize(bssid).c_str());
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        LOGE("%{public}s WifiDeviceConfig is null!", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    if (networkId == linkedInfo.networkId) {
        LOGI("%{public}s current linkedBssid: %{public}s, roam to targetBssid: %{public}s",
            __FUNCTION__,  MacAnonymize(linkedInfo.bssid).c_str(), MacAnonymize(bssid).c_str());
        if (bssid == linkedInfo.bssid) {
            LOGI("%{public}s current linkedBssid equal to target bssid", __FUNCTION__);
            return WIFI_OPT_SUCCESS;
        } else if (linkedInfo.isMloConnected) {
            std::vector<WifiLinkedInfo> mloInfo;
            if (WifiConfigCenter::GetInstance().GetMloLinkedInfo(mloInfo, m_instId) < 0) {
                LOGE("%{public}s get mlo connect info failed", __FUNCTION__);
                return WIFI_OPT_FAILED;
            }
            if (std::find_if(mloInfo.begin(), mloInfo.end(),
                [bssid](WifiLinkedInfo &info) { return bssid == info.bssid; }) == mloInfo.end()) {
                    pStaStateMachine->StartConnectToBssid(networkId, bssid);
                return WIFI_OPT_SUCCESS;
            }
            if (linkedInfo.wifiLinkType == WifiLinkType::WIFI7_MLSR) {
                WifiCmdClient::GetInstance().SendCmdToDriver(
                    WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), CMD_MLD_LINK_SWITCH, bssid);
                return WIFI_OPT_SUCCESS;
            } else if (linkedInfo.wifiLinkType == WifiLinkType::WIFI7_EMLSR) {
                LOGI("%{public}s emlsr not support linkSwitch", __FUNCTION__);
                return WIFI_OPT_SUCCESS;
            }
        }
        pStaStateMachine->StartConnectToBssid(networkId, bssid);
    } else {
        LOGI("%{public}s switch to target network", __FUNCTION__);
        auto message = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK);
        message->SetParam1(networkId);
        message->SetParam2(type);
        message->AddStringMessageBody(bssid);
        pStaStateMachine->SendMessage(message);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartConnectToUserSelectNetwork(int networkId, std::string bssid) const
{
    LOGI("Enter StartConnectToUserSelectNetwork, networkId: %{public}d, bssid: %{public}s",
        networkId, MacAnonymize(bssid).c_str());
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        LOGE("%{public}s WifiDeviceConfig is null!", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    auto message = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK);
    message->SetParam1(networkId);
    message->SetParam2(NETWORK_SELECTED_BY_USER);
    message->AddStringMessageBody(bssid);
    pStaStateMachine->SendMessage(message);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReAssociate() const
{
    WIFI_LOGI("Enter ReAssociate.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::EnableDeviceConfig(int networkId, bool attemptEnable) const
{
    WIFI_LOGI("Enter EnableDeviceConfig, networkid is %{public}d", networkId);

    /* Update wifi status. */
    if (!BlockConnectService::GetInstance().EnableNetworkSelectStatus(networkId)) {
        WIFI_LOGE("Enable device config failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableDeviceConfig(int networkId) const
{
    WIFI_LOGI("Enter DisableDeviceConfig, networkid is %{public}d", networkId);

    if (!BlockConnectService::GetInstance().UpdateNetworkSelectStatus(networkId,
        DisabledReason::DISABLED_BY_WIFI_MANAGER)) {
        WIFI_LOGE("Disable device config failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AllowAutoConnect(int32_t networkId, bool isAllowed) const
{
    WIFI_LOGI("Enter AllowAutoConnect, networkid is %{public}d, isAllowed is %{public}d", networkId, isAllowed);
    WifiDeviceConfig targetNetwork;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, targetNetwork)) {
        WIFI_LOGE("AllowAutoConnect, failed tot get device config");
        return WIFI_OPT_FAILED;
    }

    if (targetNetwork.isAllowAutoConnect == isAllowed) {
        return WIFI_OPT_FAILED;
    }

    targetNetwork.isAllowAutoConnect = isAllowed;
    WifiSettings::GetInstance().AddDeviceConfig(targetNetwork);
    WifiSettings::GetInstance().SyncDeviceConfig();
    if (!isAllowed) {
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
        if (linkedInfo.networkId != networkId && pStaStateMachine->GetTargetNetworkId() != networkId) {
            WIFI_LOGI("AllowAutoConnect, networkid is not correct, linked networkid:%{public}d", linkedInfo.networkId);
            return WIFI_OPT_SUCCESS;
        }
        Disconnect();
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::Disconnect() const
{
    WIFI_LOGI("Enter Disconnect.\n");
    if (m_instId == INSTID_WLAN0) {
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
        if (pStaAutoConnectService->EnableOrDisableBssid(linkedInfo.bssid, false, AP_CANNOT_HANDLE_NEW_STA)) {
            WIFI_LOGI("The blocklist is updated.\n");
        }
    }
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISCONNECT);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWps(const WpsConfig &config) const
{
    WIFI_LOGI("Enter StartWps.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    InternalMessagePtr msg = pStaStateMachine->CreateMessage();
    msg->SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
    msg->SetParam1(static_cast<int>(config.setup));
    msg->AddStringMessageBody(config.pin);
    msg->AddStringMessageBody(config.bssid);
    pStaStateMachine->SendMessage(msg);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::CancelWps() const
{
    WIFI_LOGI("Enter CanceltWps.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CANCELWPS);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AutoConnectService(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGD("Enter AutoConnectService.\n");
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
#ifndef OHOS_ARCH_LITE
    if (IsOtherVapConnect()) {
        LOGI("AutoConnectService: p2p or hml connected, and hotspot is enable");
        return WIFI_OPT_FAILED;
    }
    auto wifiBrokerFrameProcessName = WifiSettings::GetInstance().GetPackageName("anco_broker_name");
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (!wifiBrokerFrameProcessName.empty() && ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
        WifiConfigCenter::GetInstance().SetWifiConnectedMode(true, m_instId);
        WIFI_LOGD("StaService %{public}s, anco, %{public}d", __func__, m_instId);
    } else {
        WifiConfigCenter::GetInstance().SetWifiConnectedMode(false, m_instId);
        WIFI_LOGD("StaService %{public}s,not anco, %{public}d", __func__, m_instId);
    }
#endif
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
    return WIFI_OPT_SUCCESS;
}

void StaService::RegisterStaServiceCallback(const std::vector<StaServiceCallback> &callbacks) const
{
    LOGI("Enter RegisterStaServiceCallback.");
    if (pStaStateMachine == nullptr) {
        LOGE("pStaStateMachine is null.\n");
        return;
    }
    for (StaServiceCallback cb : callbacks) {
        pStaStateMachine->RegisterStaServiceCallback(cb);
    }
}

void StaService::UnRegisterStaServiceCallback(const StaServiceCallback &callbacks) const
{
    LOGI("Enter UnRegisterStaServiceCallback.");
    if (pStaStateMachine == nullptr) {
        LOGE("pStaStateMachine is null.\n");
        return;
    }
    pStaStateMachine->UnRegisterStaServiceCallback(callbacks);
}

ErrCode StaService::ReConnect() const
{
    WIFI_LOGI("Enter ReConnect.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_RECONNECT_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetSuspendMode(bool mode) const
{
    LOGI("Enter SetSuspendMode, mode=[%{public}d]!", mode);
    if (m_instId == INSTID_WLAN0) {
        if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(mode) != WIFI_HAL_OPT_OK) {
            LOGE("WpaSetSuspendMode() failed!");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetPowerMode(bool mode) const
{
    LOGI("Enter SetPowerMode, mode=[%{public}d]!", mode);
    if (WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(mode, m_instId) != WIFI_HAL_OPT_OK) {
        LOGE("SetPowerMode() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaService::NotifyDeviceConfigChange(ConfigChange value, WifiDeviceConfig config, bool isRemoveAll) const
{
    WIFI_LOGI("Notify device config change: %{public}d\n", static_cast<int>(value));
#if defined(FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT) && defined(FEATURE_WIFI_PRO_SUPPORT)
    IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(m_instId);
    if (pWifiProService != nullptr) {
        pWifiProService->OnWifiDeviceConfigChange(static_cast<int32_t>(value), config, isRemoveAll);
    }
#endif
#ifndef OHOS_ARCH_LITE
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE;
    cbMsg.msgData = static_cast<int>(value);
    cbMsg.id = m_instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#endif
}

int StaService::FindDeviceConfig(const WifiDeviceConfig &config, WifiDeviceConfig &outConfig) const
{
    int ret = -1;
    if (config.uid > WIFI_INVALID_UID) {
        ret = WifiSettings::GetInstance().GetCandidateConfig(config.uid, config.ssid, config.keyMgmt, outConfig);
    } else {
        ret = WifiSettings::GetInstance().GetDeviceConfig(config.ssid, config.keyMgmt, outConfig, m_instId);
    }
    LOGI("FindDeviceConfig uid:%{public}d, ssid:%{public}s, ret:%{public}d.", config.uid,
        SsidAnonymize(outConfig.ssid).c_str(), ret);
    return (ret < 0) ? WIFI_OPT_FAILED : WIFI_OPT_SUCCESS;
}

ErrCode StaService::OnSystemAbilityChanged(int systemAbilityid, bool add)
{
    WIFI_LOGI("Enter OnSystemAbilityChanged.");
#ifndef OHOS_ARCH_LITE
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    if (systemAbilityid == COMM_NET_CONN_MANAGER_SYS_ABILITY_ID) {
        uint32_t supplierId = WifiNetAgent::GetInstance().GetSupplierId();
        if ((add && !m_connMangerStatus) || (supplierId == INVALID_SUPPLIER_ID)) {
            WifiNetAgent::GetInstance().ResetSupplierId();
            pStaStateMachine->OnNetManagerRestart();
        }
        m_connMangerStatus = add;
    }
#endif
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaService::WifiCountryCodeChangeObserver::OnWifiCountryCodeChanged(const std::string &wifiCountryCode)
{
    if (strcasecmp(m_lastWifiCountryCode.c_str(), wifiCountryCode.c_str()) == 0) {
        WIFI_LOGI("wifi country code is same, sta not update, code=%{public}s", wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGI("deal wifi country code changed, code=%{public}s", wifiCountryCode.c_str());
    InternalMessagePtr msg = m_stateMachineObj.CreateMessage();
    CHECK_NULL_AND_RETURN(msg, WIFI_OPT_FAILED);
    msg->SetMessageName(static_cast<int>(WIFI_SVR_CMD_UPDATE_COUNTRY_CODE));
    msg->AddStringMessageBody(wifiCountryCode);
    m_stateMachineObj.SendMessage(msg);
    m_lastWifiCountryCode = wifiCountryCode;
    return WIFI_OPT_SUCCESS;
}

std::string StaService::WifiCountryCodeChangeObserver::GetListenerModuleName()
{
    return m_listenerModuleName;
}
#endif
 
void StaService::HandleScreenStatusChanged(int screenState)
{
    WIFI_LOGD("Enter HandleScreenStatusChanged screenState:%{public}d, instId:%{public}d", screenState, m_instId);
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return;
    }
    pStaStateMachine->SendMessage(WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT, screenState);
    if (m_instId == INSTID_WLAN0) {
        if (screenState == MODE_STATE_OPEN) {
            pStaStateMachine->StartDetectTimer(DETECT_TYPE_DEFAULT);
        } else {
            pStaStateMachine->StopTimer(static_cast<int>(CMD_START_NETCHECK));
        }
    }
#endif
    return;
}

ErrCode StaService::DisableAutoJoin(const std::string &conditionName)
{
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->DisableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::EnableAutoJoin(const std::string &conditionName)
{
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->EnableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RegisterAutoJoinCondition(const std::string &conditionName,
    const std::function<bool()> &autoJoinCondition)
{
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->RegisterAutoJoinCondition(conditionName, autoJoinCondition);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->DeregisterAutoJoinCondition(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RegisterFilterBuilder(const OHOS::Wifi::FilterTag &filterTag,
                                          const std::string &filterName,
                                          const OHOS::Wifi::FilterBuilder &filterBuilder)
{
    ExternalWifiFilterBuildManager::GetInstance().RegisterFilterBuilder(filterTag, filterName, filterBuilder);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DeregisterFilterBuilder(const OHOS::Wifi::FilterTag &filterTag, const std::string &filterName)
{
    ExternalWifiFilterBuildManager::GetInstance().DeregisterFilterBuilder(filterTag, filterName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                          const CommonBuilder &commonBuilder)
{
    ExternalWifiCommonBuildManager::GetInstance().RegisterCommonBuilder(tagType, tagName, commonBuilder);
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaService::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    ExternalWifiCommonBuildManager::GetInstance().DeregisterCommonBuilder(tagType, tagName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartPortalCertification()
{
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("StartPortalCertification send message!");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_PORTAL_BROWSE_NOTIFY_EVENT);
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaService::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null");
        return WIFI_OPT_FAILED;
    }

    InternalMessagePtr msg = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_FOREGROUND_APP_CHANGED_EVENT);
    msg->SetMessageObj(appStateData);
    msg->msgLogLevel_ = MsgLogLevel::LOG_D;
    pStaStateMachine->SendMessage(msg);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetEnhanceService(IEnhanceService* enhanceService)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SetEnhanceService(enhanceService);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetSelfCureService(ISelfCureService *selfCureService)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SetSelfCureService(selfCureService);
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode StaService::EnableHiLinkHandshake(bool uiFlag, const WifiDeviceConfig &config, const std::string &cmd)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    InternalMessagePtr msg = pStaStateMachine->CreateMessage();
    msg->SetMessageName(WIFI_SVR_COM_STA_ENABLE_HILINK);
    msg->SetParam1(config.bssidType);
    msg->SetParam2(uiFlag);
    msg->AddStringMessageBody(config.ssid);
    msg->AddStringMessageBody(config.bssid);
    msg->AddStringMessageBody(config.keyMgmt);
    msg->AddStringMessageBody(cmd);
    pStaStateMachine->SendMessage(msg);

    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWifiDetection()
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(CMD_START_NETCHECK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DeliverStaIfaceData(const std::string &currentMac)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_HILINK_DELIVER_MAC, currentMac);

    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DeliverAudioState(int state)
{
    int isEnableBackAudio = 0;
    std::string strValue = system::GetParameter(ENABLE_BACK_AUDIO, "");
    if (!strValue.empty()) {
        isEnableBackAudio = CheckDataLegal(strValue);
    }
    if (isEnableBackAudio) {
        CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
        WIFI_LOGI("DealScreenOffPoll deliver audio state.");
        pStaStateMachine->SendMessage(WIFI_AUDIO_STATE_CHANGED_NOTIFY_EVENT, state);
    }
    return WIFI_OPT_SUCCESS;
}

void StaService::HandleFoldStatusChanged(int foldstatus)
{
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return;
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_FOLD_STATUS_NOTIFY_EVENT, foldstatus);
}

std::string StaService::VoWifiDetect(std::string cmd)
{
    std::unique_lock<std::shared_mutex> lock(voWifiCallbackMutex_);
    std::string result = WifiCmdClient::GetInstance().VoWifiDetectInternal(cmd);
    return result;
}
 
VoWifiSignalInfo StaService::FetchWifiSignalInfoForVoWiFi()
{
    VoWifiSignalInfo voWifiSignalInfo;

    int linkSpeed = -1;
    int frequency = -1;
    int rssi = -1;
    int noise = -1;
 
    WifiSignalPollInfo signalInfo;
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetConnectSignalInfo(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), linkedInfo.bssid, signalInfo);
    WIFI_LOGI("FetchWifiSignalInfoForVoWiFi GetConnectSignalInfo result: %{public}d.", ret);
    
    linkSpeed = signalInfo.txrate;
    frequency = signalInfo.frequency;
    rssi = signalInfo.signal;
 
    int txPacketCounter = signalInfo.txPackets;
    int nativeTxFailed = signalInfo.txFailed;
    int nativeTxSuccessed = txPacketCounter - nativeTxFailed;
 
    // set rssi
    voWifiSignalInfo.rssi = rssi;
 
    // set noise
    noise = 0; // stub
    voWifiSignalInfo.noise = noise;
 
    // set bler
    int bler = static_cast<int>((static_cast<double>(nativeTxFailed) /
        static_cast<double>(std::max(txPacketCounter, 1))) * 100);
    voWifiSignalInfo.bler = bler;
 
    // delta tx packet count
    int deltaTxPacketCounter = nativeTxSuccessed - lastTxPktCnt_;
    lastTxPktCnt_ = nativeTxSuccessed;
    voWifiSignalInfo.deltaTxPacketCounter = deltaTxPacketCounter;
 
    // access type
    int accessType = ConvertToAccessType(linkSpeed, frequency);
    voWifiSignalInfo.accessType = accessType;
 
    // reserve
    voWifiSignalInfo.reverse = 0;
 
    // tx successed packet count
    voWifiSignalInfo.txGood = nativeTxSuccessed;
 
    // tx fialed packet count
    voWifiSignalInfo.txBad = nativeTxFailed;
 
    // max address
    std::string bssid = linkedInfo.bssid;
    std::string macStr = "ffffffffffff";
    std::string::size_type pos = 0;
    while ((pos = bssid.find(':', pos)) != std::string::npos) {
        bssid.replace(pos, 1, "");
        pos++;
    }
    const char* charArray = macStr.data();
    unsigned char* macBytes = reinterpret_cast<unsigned char*>(const_cast<char*>(charArray));
    std::string macAddressStr(reinterpret_cast<char*>(macBytes));
    voWifiSignalInfo.macAddress = macAddressStr;
 
    WIFI_LOGI("rssi:%{public}d, nativeTxFailed:%{public}d, nativeTxSuccessed:%{public}d,"
        "deltaTxPacketCounter:%{public}d, linkSpeed:%{public}d, frequency:%{public}d, mac:%{public}s",
        rssi, nativeTxFailed, nativeTxSuccessed, deltaTxPacketCounter, linkSpeed, frequency,
        MacAnonymize(macAddressStr).c_str());
    return voWifiSignalInfo;
}
 
int StaService::ConvertToAccessType(int linkSpeed, int frequency)
{
    // RESERVE
    return 0;
}
 
void StaService::ProcessSetVoWifiDetectMode(WifiDetectConfInfo info)
{
    bool ret = false;

    if (info.wifiDetectMode == WIFI_DETECT_MODE_LOW) {
        ret = VoWifiDetectSet("LOW_THRESHOLD " + std::to_string(info.threshold));
    } else if (info.wifiDetectMode == WIFI_DETECT_MODE_HIGH) {
        ret = VoWifiDetectSet("HIGH_THRESHOLD " + std::to_string(info.threshold));
    } else {
        ret = VoWifiDetectSet("MODE " + std::to_string(info.wifiDetectMode));
    }
 
    if (ret && VoWifiDetectSet("TRIGGER_COUNT " + std::to_string(info.envalueCount))) {
        ret = VoWifiDetectSet("MODE " + std::to_string(info.wifiDetectMode));
    }
 
    WIFI_LOGI("set VoWifi detect mode: %{public}d, result: %{public}d.", info.wifiDetectMode, ret);
}
 
void StaService::ProcessSetVoWifiDetectPeriod(int period)
{
    bool ret = VoWifiDetectSet("PERIOD " + std::to_string(period));
    WIFI_LOGI("Set VoWifi Detect Period result: %{public}d, period = %{public}d", ret, period);
}

ErrCode StaService::GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    WifiChrUtils::GetInstance().GetSignalPollInfoArray(wifiSignalPollInfos, length);
    return WIFI_OPT_SUCCESS;
}
 
bool StaService::VoWifiDetectSet(std::string cmd)
{
    std::string ret = VoWifiDetect(VOWIFI_DETECT_SET_PREFIX + cmd);
    WIFI_LOGI("VoWifiDetectSet ret : %{public}s", ret.c_str());
    return (!ret.empty() && (ret == "true" || ret == "OK"));
}

void StaService::GetDetectNetState(OperateResState &state)
{
    pStaStateMachine->GetDetectNetState(state);
}
}  // namespace Wifi
}  // namespace OHOS