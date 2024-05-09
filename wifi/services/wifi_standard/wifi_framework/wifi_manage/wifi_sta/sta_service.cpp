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
#include "core_service_client.h"
#include "cellular_data_client.h"
#endif
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_cert_utils.h"
#include "wifi_common_util.h"
#include "network_selection_manager.h"
#include "wifi_config_center.h"
#include "external_wifi_filter_builder_manager.h"

DEFINE_WIFILOG_LABEL("StaService");

namespace OHOS {
namespace Wifi {

constexpr const char *ANCO_SERVICE_BROKER = "anco_service_broker";
constexpr const int REMOVE_ALL_DEVICECONFIG = 0x7FFFFFFF;

#define EAP_AUTH_IMSI_MCC_POS 0
#define EAP_AUTH_MAX_MCC_LEN  3
#define EAP_AUTH_IMSI_MNC_POS 3
#define EAP_AUTH_MIN_MNC_LEN  2
#define EAP_AUTH_MAX_MNC_LEN  3
#define EAP_AUTH_MIN_PLMN_LEN  5
#define EAP_AUTH_MAX_PLMN_LEN  6
#define EAP_AUTH_MAX_IMSI_LENGTH 15

#define EAP_AKA_PERMANENT_PREFIX "0"
#define EAP_SIM_PERMANENT_PREFIX "1"
#define EAP_AKA_PRIME_PERMANENT_PREFIX "6"

#define EAP_AUTH_WLAN_MNC "@wlan.mnc"
#define EAP_AUTH_WLAN_MCC ".mcc"
#define EAP_AUTH_PERMANENT_SUFFIX ".3gppnetwork.org"

StaService::StaService(int instId)
    : pStaStateMachine(nullptr),
      pStaMonitor(nullptr),
      pStaAutoConnectService(nullptr),
#ifndef OHOS_ARCH_LITE
      pStaAppAcceleration(nullptr),
#endif
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

#ifndef OHOS_ARCH_LITE
    if (pStaAppAcceleration != nullptr) {
        delete pStaAppAcceleration;
        pStaAppAcceleration = nullptr;
    }
#endif
}

ErrCode StaService::InitStaService(const std::vector<StaServiceCallback> &callbacks)
{
    WIFI_LOGI("Enter InitStaService.\n");
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

    ChannelsTable chanTbs;
    (void)WifiSettings::GetInstance().GetValidChannels(chanTbs);
    if (chanTbs[BandType::BAND_2GHZ].size() == 0) {
        std::vector<int> freqs2G;
        std::vector<int> freqs5G;
        int band = static_cast<int>(BandType::BAND_2GHZ);
        WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetSupportFrequencies(band, freqs2G);
        if (ret != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("get 2g frequencies failed.");
            WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, freqs2G, m_instId);
        }
        band = static_cast<int>(BandType::BAND_5GHZ);
        ret = WifiStaHalInterface::GetInstance().GetSupportFrequencies(band, freqs5G);
        if (ret != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("get 5g frequencies failed.");
            WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_5GHZ, freqs5G, m_instId);
        }
        std::vector<int32_t> supp2Gfreqs(freqs2G.begin(), freqs2G.end());
        std::vector<int32_t> supp5Gfreqs(freqs5G.begin(), freqs5G.end());
        for (auto iter = supp2Gfreqs.begin(); iter != supp2Gfreqs.end(); iter++) {
            int32_t channel = FrequencyToChannel(*iter);
            if (channel == INVALID_FREQ_OR_CHANNEL) {
                continue;
            }
            chanTbs[BandType::BAND_2GHZ].push_back(channel);
        }
        for (auto iter = supp5Gfreqs.begin(); iter != supp5Gfreqs.end(); iter++) {
            int32_t channel = FrequencyToChannel(*iter);
            if (channel == INVALID_FREQ_OR_CHANNEL) {
                continue;
            }
            chanTbs[BandType::BAND_5GHZ].push_back(channel);
        }
        if (WifiSettings::GetInstance().SetValidChannels(chanTbs)) {
            WIFI_LOGE("%{public}s, fail to SetValidChannels", __func__);
        }
    }

    pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine, m_instId);
    if (pStaAutoConnectService == nullptr) {
        WIFI_LOGE("Alloc pStaAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pStaAutoConnectService->InitAutoConnectService() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    pStaAppAcceleration = new (std::nothrow) StaAppAcceleration(m_instId);
    if (pStaAppAcceleration == nullptr) {
        WIFI_LOGE("Alloc pStaAppAcceleration failed.\n");
    }

    if (pStaAppAcceleration->InitAppAcceleration() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitAppAcceleration failed.\n");
    }
    std::vector<StaServiceCallback> appAccelerationStaCallBacks;
    appAccelerationStaCallBacks.push_back(pStaAppAcceleration->GetStaCallback());
    RegisterStaServiceCallback(appAccelerationStaCallBacks);
#endif
    WIFI_LOGI("Init staservice successfully.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::EnableWifi()
{
    WIFI_LOGI("Enter EnableWifi.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
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
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_ENABLE_WIFI, STA_CONNECT_MODE);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableWifi() const
{
    WIFI_LOGI("Enter DisableWifi.\n");
#ifndef OHOS_ARCH_LITE
    // deregistration country code change notification
    WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(m_staObserver);
#endif
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISABLE_WIFI);
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

    if (config.keyMgmt == KEY_MGMT_NONE || config.keyMgmt == KEY_MGMT_WEP) {
#ifndef OHOS_ARCH_LITE
        const std::string wifiBrokerFrameProcessName = ANCO_SERVICE_BROKER;
        std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
        if (ancoBrokerFrameProcessName != wifiBrokerFrameProcessName) {
            LOGE("AddCandidateConfig unsupport open or wep key!");
            return WIFI_OPT_NOT_SUPPORTED;
        }
#else
        LOGE("AddCandidateConfig unsupport open or wep key!");
        return WIFI_OPT_NOT_SUPPORTED;
#endif
    }
    WifiDeviceConfig tempDeviceConfig = config;
    tempDeviceConfig.uid = uid;
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

ErrCode StaService::ConnectToCandidateConfig(const int uid, const int networkId) const
{
    LOGI("Enter ConnectToCandidateConfig.\n");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetCandidateConfig(uid, networkId, config) == INVALID_NETWORK_ID) {
        LOGE("ConnectToCandidateConfig:GetCandidateConfig is null!");
        return WIFI_OPT_FAILED;
    }

    if (config.keyMgmt == KEY_MGMT_NONE) {
        LOGE("ConnectToCandidateConfig unsupport open or wep key!");
        return WIFI_OPT_NOT_SUPPORTED;
    }

    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SetPortalBrowserFlag(false);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_USER);
    return WIFI_OPT_SUCCESS;
}

std::string StaService::ConvertString(const std::u16string &wideText) const
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(wideText);
}

#ifndef OHOS_ARCH_LITE
int32_t StaService::GetDataSlotId() const
{
    auto slotId = CellularDataClient::GetInstance().GetDefaultCellularDataSlotId();
    int32_t simCount = CoreServiceClient::GetInstance().GetMaxSimCount();
    if ((slotId < 0) || (slotId >= simCount)) {
        LOGE("failed to get default slotId, slotId:%{public}d, simCount:%{public}d", slotId, simCount);
        return -1;
    }
    LOGI("slotId: %{public}d, simCount:%{public}d", slotId, simCount);
    return slotId;
}

std::string StaService::GetImsi(int32_t slotId) const
{
    std::u16string imsi;
    int32_t errCode = CoreServiceClient::GetInstance().GetIMSI(slotId, imsi);
    if (errCode != 0) {
        LOGE("failed to get imsi, errCode: %{public}d", errCode);
        return "";
    }
    return ConvertString(imsi);
}

std::string StaService::GetPlmn(int32_t slotId) const
{
    std::u16string plmn;
    int32_t errCode = CoreServiceClient::GetInstance().GetSimOperatorNumeric(slotId, plmn);
    if (errCode != 0) {
        LOGE("failed to get plmn, errCode: %{public}d", errCode);
        return "";
    }
    return ConvertString(plmn);
}
#endif

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

    int32_t slotId = GetDataSlotId();
    if (slotId == -1) {
        return;
    }

    std::string imsi = GetImsi(slotId);
    if (imsi.empty() || imsi.length() > EAP_AUTH_MAX_IMSI_LENGTH) {
        LOGE("invalid imsi, length: %{public}zu", imsi.length());
        return;
    }

    std::string mnc;
    std::string plmn = GetPlmn(slotId);
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

int StaService::AddDeviceConfig(const WifiDeviceConfig &config) const
{
    LOGI("Enter AddDeviceConfig, bssid=%{public}s\n", MacAnonymize(config.bssid).c_str());
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    int netWorkId = INVALID_NETWORK_ID;
    bool isUpdate = false;
    std::string bssid;
    std::string userSelectbssid = config.bssid;
    int status = config.status;
    WifiDeviceConfig tempDeviceConfig;
    if (FindDeviceConfig(config, tempDeviceConfig) == 0) {
        netWorkId = tempDeviceConfig.networkId;
        status = tempDeviceConfig.status;
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        bssid = config.bssid.empty() ? tempDeviceConfig.bssid : config.bssid;
        pStaAutoConnectService->EnableOrDisableBssid(bssid, true, 0);
        isUpdate = true;
    } else {
        netWorkId = WifiSettings::GetInstance().GetNextNetworkId();
        LOGI("AddDeviceConfig alloc new id[%{public}d] succeed!", netWorkId);
    }
    tempDeviceConfig = config;
    tempDeviceConfig.instanceId = m_instId;
    tempDeviceConfig.networkId = netWorkId;
    tempDeviceConfig.status = status;
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

    /* Add the new network to WifiSettings. */
    if (WifiSettings::GetInstance().EncryptionDeviceConfig(tempDeviceConfig)) {
        LOGE("AddDeviceConfig EncryptionDeviceConfig failed");
    }
    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    /* update net link proxy info */
    pStaStateMachine->ReUpdateNetLinkInfo(tempDeviceConfig);
    ConfigChange changeType = isUpdate ? ConfigChange::CONFIG_UPDATE : ConfigChange::CONFIG_ADD;
    NotifyDeviceConfigChange(changeType);
    return netWorkId;
}

int StaService::UpdateDeviceConfig(const WifiDeviceConfig &config) const
{
    return AddDeviceConfig(config);
}

ErrCode StaService::RemoveDevice(int networkId) const
{
    LOGI("Enter RemoveDevice, networkId = %{public}d.\n", networkId);
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    if (linkedInfo.networkId == networkId) {
        WifiStaHalInterface::GetInstance().ClearDeviceConfig();
    }

    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) == 0) {
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    } else {
        LOGE("RemoveDevice, networkId = %{public}d do not exist.\n", networkId);
        return WIFI_OPT_FAILED;
    }
    /* Remove network configuration directly without notification to InterfaceService. */
    WifiSettings::GetInstance().RemoveDevice(networkId);
    WifiSettings::GetInstance().SyncDeviceConfig();
    NotifyDeviceConfigChange(ConfigChange::CONFIG_REMOVE);
#ifndef OHOS_ARCH_LITE
    const std::string wifiBrokerFrameProcessName = ANCO_SERVICE_BROKER;
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
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
    if (WifiStaHalInterface::GetInstance().ClearDeviceConfig() == WIFI_IDL_OPT_OK) {
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
    NotifyDeviceConfigChange(ConfigChange::CONFIG_REMOVE);
#ifndef OHOS_ARCH_LITE
    WifiDeviceConfig config;
    config.networkId = REMOVE_ALL_DEVICECONFIG;
    const std::string wifiBrokerFrameProcessName = ANCO_SERVICE_BROKER;
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
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
    LOGI("Enter ConnectToDevice, ssid = %{public}s.\n", SsidAnonymize(config.ssid).c_str());
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    int netWorkId = AddDeviceConfig(config);
    if(netWorkId == INVALID_NETWORK_ID) {
        LOGD("ConnectToDevice, AddDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("ConnectToDevice, netWorkId: %{public}d", netWorkId);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, netWorkId, NETWORK_SELECTED_BY_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectToNetwork(int networkId) const
{
    LOGI("Enter ConnectToNetwork, networkId is %{public}d.", networkId);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGE("WifiDeviceConfig is null!");
        return WIFI_OPT_FAILED;
    }
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    LOGI("ConnectToNetwork, ssid = %{public}s.", SsidAnonymize(config.ssid).c_str());
    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SetPortalBrowserFlag(false);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_USER);
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
    if (WifiSettings::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::ENABLED, attemptEnable) <
        0) {
        WIFI_LOGE("Enable device config failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SyncDeviceConfig();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableDeviceConfig(int networkId) const
{
    WIFI_LOGI("Enter DisableDeviceConfig, networkid is %{public}d", networkId);

    if (WifiSettings::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::DISABLED) < 0) {
        WIFI_LOGE("Disable device config failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SyncDeviceConfig();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::Disconnect() const
{
    WIFI_LOGI("Enter Disconnect.\n");
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    if (pStaAutoConnectService->EnableOrDisableBssid(linkedInfo.bssid, false, AP_CANNOT_HANDLE_NEW_STA)) {
        WIFI_LOGI("The blocklist is updated.\n");
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISCONNECT);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWps(const WpsConfig &config) const
{
    WIFI_LOGI("Enter StartWps.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    InternalMessage *msg = pStaStateMachine->CreateMessage();
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
    WIFI_LOGI("Enter AutoConnectService.\n");
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
#ifndef OHOS_ARCH_LITE
    if (IsOtherVapConnect()) {
        LOGI("AutoConnectService: p2p or hml connected, and hotspot is enable");
        return WIFI_OPT_FAILED;
    }
    const std::string wifiBrokerFrameProcessName = ANCO_SERVICE_BROKER;
    std::string ancoBrokerFrameProcessName = GetBrokerProcessNameByPid(GetCallingUid(), GetCallingPid());
    if (ancoBrokerFrameProcessName == wifiBrokerFrameProcessName) {
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
    if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(mode) != WIFI_IDL_OPT_OK) {
        LOGE("WpaSetSuspendMode() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetPowerMode(bool mode) const
{
    LOGI("Enter SetPowerMode, mode=[%{public}d]!", mode);
    if (WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(mode) != WIFI_IDL_OPT_OK) {
        LOGE("SetPowerMode() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaService::NotifyDeviceConfigChange(ConfigChange value) const
{
    WIFI_LOGI("Notify device config change: %{public}d\n", static_cast<int>(value));
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
    if (WifiSettings::GetInstance().GetDeviceConfig(config.ancoCallProcessName, config.ssid, config.keyMgmt,
        outConfig) == 0 && (!config.ancoCallProcessName.empty())) {
        LOGI("The anco same network name already exists in setting! networkId:%{public}d,ssid:%{public}s,"
            "ancoCallProcessName:%{public}s.", outConfig.networkId, SsidAnonymize(outConfig.ssid).c_str(),
            outConfig.ancoCallProcessName.c_str());
    } else if (WifiSettings::GetInstance().GetDeviceConfig(config.ssid, config.keyMgmt,
        outConfig) == 0) {
        LOGI("The same network name already exists in setting! networkId:%{public}d,ssid:%{public}s"
            "ancoCallProcessName:%{public}s,OancoCallProcessName%{public}s", outConfig.networkId,
            SsidAnonymize(outConfig.ssid).c_str(),
            config.ancoCallProcessName.c_str(), outConfig.ancoCallProcessName.c_str());
    } else {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::OnSystemAbilityChanged(int systemAbilityid, bool add)
{
    WIFI_LOGI("Enter OnSystemAbilityChanged.");
#ifndef OHOS_ARCH_LITE
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    if (systemAbilityid == COMM_NET_CONN_MANAGER_SYS_ABILITY_ID && add) {
        pStaStateMachine->OnNetManagerRestart();
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
    InternalMessage *msg = m_stateMachineObj.CreateMessage();
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
    WIFI_LOGI("Enter HandleScreenStatusChanged screenState:%{public}d.", screenState);
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return;
    }
    if (screenState == MODE_STATE_OPEN) {
        pStaStateMachine->StartTimer(static_cast<int>(CMD_START_NETCHECK), 0);
    } else {
        pStaStateMachine->StopTimer(static_cast<int>(CMD_START_NETCHECK));
    }
    if (pStaAppAcceleration != nullptr) {
        pStaAppAcceleration->HandleScreenStatusChanged(screenState);
    }
    pStaStateMachine->SendMessage(WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT, screenState);
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

ErrCode StaService::StartPortalCertification()
{
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return WIFI_OPT_FAILED;
    }
    pStaStateMachine->HandlePortalNetworkPorcess();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RenewDhcp()
{
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("pStaStateMachine is null!");
        return WIFI_OPT_FAILED;
    }
    pStaStateMachine->RenewDhcp();
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaService::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    if (pStaAppAcceleration == nullptr) {
        WIFI_LOGE("pStaAppAcceleration is null");
        return WIFI_OPT_FAILED;
    }
    pStaAppAcceleration->HandleForegroundAppChangedAction(appStateData);
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode StaService::EnableHiLinkHandshake(const WifiDeviceConfig &config, const std::string &bssid)
{
    int netWorkId = INVALID_NETWORK_ID;
    if (bssid.find("ENABLE=1") != INVALID_NETWORK_ID) {
        netWorkId = AddDeviceConfig(config);
        if (netWorkId == INVALID_NETWORK_ID) {
            WIFI_LOGE("EnableHiLinkHandshake, AddDeviceConfig failed!");
            return WIFI_OPT_FAILED;
        }
    }
    WIFI_LOGI("EnableHiLinkHandshake, netWorkId: %{public}d", netWorkId);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_ENABLE_HILINK, netWorkId, 0, bssid);
 
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaService::DeliverStaIfaceData(const std::string &currentMac)
{
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_HILINK_DELIVER_MAC, currentMac);
 
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
