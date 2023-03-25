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
#endif
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_cert_utils.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("StaService");
namespace OHOS {
namespace Wifi {
StaService::StaService()
    : pStaStateMachine(nullptr), pStaMonitor(nullptr), pStaAutoConnectService(nullptr)
{}

StaService::~StaService()
{
    WIFI_LOGI("StaService::~StaService");
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

ErrCode StaService::InitStaService(const StaServiceCallback &callbacks)
{
    WIFI_LOGI("Enter StaService::InitStaService.\n");
    pStaStateMachine = new (std::nothrow) StaStateMachine();
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("Alloc pStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaStateMachine->InitStaStateMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    RegisterStaServiceCallback(callbacks);

    pStaMonitor = new (std::nothrow) StaMonitor();
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
            WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, freqs2G);
        }
        band = static_cast<int>(BandType::BAND_5GHZ);
        ret = WifiStaHalInterface::GetInstance().GetSupportFrequencies(band, freqs5G);
        if (ret != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("get 5g frequencies failed.");
            WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_5GHZ, freqs5G);
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

    pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine);
    if (pStaAutoConnectService == nullptr) {
        WIFI_LOGE("Alloc pStaAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pStaAutoConnectService->InitAutoConnectService() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("Init staservice successfully.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::EnableWifi() const
{
    WIFI_LOGI("Enter StaService::EnableWifi.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_ENABLE_WIFI, STA_CONNECT_MODE);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableWifi() const
{
    WIFI_LOGI("Enter StaService::DisableWifi.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISABLE_WIFI);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId) const
{
    LOGI("Enter StaService::AddCandidateConfig.\n");

    netWorkId = INVALID_NETWORK_ID;
    constexpr int UID_UNTRUSTED_CONFIG_LEN = 16;
    std::vector<WifiDeviceConfig> tempConfigs;
    WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
    if (tempConfigs.size() >= UID_UNTRUSTED_CONFIG_LEN) {
        LOGE("AddCandidateConfig failed, exceed max num: %{public}d\n", UID_UNTRUSTED_CONFIG_LEN);
        return WIFI_OPT_FAILED;
    }

    if (config.keyMgmt == KEY_MGMT_NONE || config.keyMgmt == KEY_MGMT_WEP) {
        LOGE("StaService::AddCandidateConfig unsupport open or wep key!");
        return WIFI_OPT_NOT_SUPPORTED;
    }
    WifiDeviceConfig tempDeviceConfig = config;
    tempDeviceConfig.uid = uid;
    netWorkId = AddDeviceConfig(tempDeviceConfig);
    return (netWorkId == INVALID_NETWORK_ID) ? WIFI_OPT_FAILED : WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveCandidateConfig(const int uid, const int networkId) const
{
    LOGD("Enter StaService::RemoveCandidateConfig.\n");
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
    LOGD("Enter StaService::RemoveAllCandidateConfig.\n");
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
    LOGI("Enter StaService::ConnectToCandidateConfig.\n");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetCandidateConfig(uid, networkId, config) == INVALID_NETWORK_ID) {
        LOGE("StaService::ConnectToCandidateConfig:GetCandidateConfig is null!");
        return WIFI_OPT_FAILED;
    }

    if (config.keyMgmt == KEY_MGMT_NONE) {
        LOGE("StaService::ConnectToCandidateConfig unsupport open or wep key!");
        return WIFI_OPT_NOT_SUPPORTED;
    }

    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);
    return WIFI_OPT_SUCCESS;
}

int StaService::AddDeviceConfig(const WifiDeviceConfig &config) const
{
    LOGI("Enter StaService::AddDeviceConfig.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    int netWorkId = INVALID_NETWORK_ID;
    bool isUpdate = false;
    std::string bssid;
    WifiDeviceConfig tempDeviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(config.ssid, config.keyMgmt, tempDeviceConfig) == 0) {
        netWorkId = tempDeviceConfig.networkId;
        LOGI("The same network name already exists in settings! netWorkId:%{public}d, ssid:%{public}s.",
            netWorkId, SsidAnonymize(config.ssid).c_str());
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        bssid = config.bssid.empty() ? tempDeviceConfig.bssid : config.bssid;
        pStaAutoConnectService->EnableOrDisableBssid(bssid, true, 0);
        isUpdate = true;
    } else {
        if (WifiStaHalInterface::GetInstance().GetNextNetworkId(netWorkId) != WIFI_IDL_OPT_OK) {
            LOGE("StaService::AddDeviceConfig GetNextNetworkId failed!");
            return INVALID_NETWORK_ID;
        }
        LOGI("StaService::AddDeviceConfig alloc new id[%{public}d] succeed!", netWorkId);
    }
    tempDeviceConfig = config;
    tempDeviceConfig.networkId = netWorkId;
    if (!bssid.empty()) {
        tempDeviceConfig.bssid = bssid;
    }
    if (config.wifiEapConfig.eap == EAP_METHOD_TLS && config.wifiEapConfig.certEntry.size() > 0 &&
        config.wifiEapConfig.clientCert.empty() && config.wifiEapConfig.privateKey.empty()) {
        std::string uri;
        std::string formatSsid = config.ssid;
        for (size_t i = 0; i < formatSsid.size(); i++) {
            // other char is invalid in certificate manager
            if (!isalnum(formatSsid[i]) && formatSsid[i] != '_') {
                formatSsid[i] = '_';
            }
        }
        std::string alias = formatSsid + "_TLS_" + std::to_string(config.uid < 0 ? 0 : config.uid);
        int ret = WifiCertUtils::InstallCert(config.wifiEapConfig.certEntry,
            config.wifiEapConfig.certPassword, alias, uri);
        if (ret == 0) {
            tempDeviceConfig.wifiEapConfig.clientCert = uri;
            tempDeviceConfig.wifiEapConfig.privateKey = uri;
            LOGE("install cert: %{public}s", tempDeviceConfig.wifiEapConfig.clientCert.c_str());
        } else {
            LOGE("install cert: %{public}d, alias: %{public}s", ret, alias.c_str());
        }
    }
    /* Setting the network to wpa */
    if(pStaStateMachine->ConvertDeviceCfg(tempDeviceConfig) != WIFI_OPT_SUCCESS) {
        LOGE("StaService::AddDeviceConfig ConvertDeviceCfg failed!");
        return INVALID_NETWORK_ID;
    }

    /* Add the new network to WifiSettings. */
    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
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
    LOGI("Enter StaService::RemoveDevice, networkId = %{public}d.\n", networkId);
    /* Remove network configuration. */
    if (WifiStaHalInterface::GetInstance().RemoveDevice(networkId) != WIFI_IDL_OPT_OK) {
        LOGE("RemoveDeviceConfig() failed!");
        return WIFI_OPT_FAILED;
    }
    if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() != WIFI_IDL_OPT_OK) {
        LOGW("RemoveDevice-SaveDeviceConfig() failed!");
    } else {
        LOGD("RemoveDevice-SaveDeviceConfig() succeed!");
    }
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) == 0) {
        CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
        pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    }
    /* Remove network configuration directly without notification to InterfaceService. */
    WifiSettings::GetInstance().RemoveDevice(networkId);
    WifiSettings::GetInstance().SyncDeviceConfig();
    NotifyDeviceConfigChange(ConfigChange::CONFIG_REMOVE);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveAllDevice() const
{
    LOGI("Enter StaService::RemoveAllDevice.\n");
    if (WifiStaHalInterface::GetInstance().ClearDeviceConfig() == WIFI_IDL_OPT_OK) {
        LOGD("Remove all device config successfully!");
        if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() != WIFI_IDL_OPT_OK) {
            LOGE("WifiStaHalInterface:RemoveAllDevice:SaveDeviceConfig failed!");
        }
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
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectToDevice(const WifiDeviceConfig &config) const
{
    LOGI("Enter StaService::ConnectToDevice, ssid = %{public}s.\n", SsidAnonymize(config.ssid).c_str());
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    int netWorkId = AddDeviceConfig(config);
    if(netWorkId == INVALID_NETWORK_ID) {
        LOGD("StaService::ConnectToDevice, AddDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("StaService::ConnectToDevice, netWorkId: %{public}d", netWorkId);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, netWorkId, NETWORK_SELECTED_BY_THE_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectToNetwork(int networkId) const
{
    LOGI("Enter StaService::ConnectToNetwork, networkId is %{public}d.", networkId);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGE("WifiDeviceConfig is null!");
        return WIFI_OPT_FAILED;
    }
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    LOGI("StaService::ConnectToNetwork, ssid = %{public}s.", SsidAnonymize(config.ssid).c_str());
    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReAssociate() const
{
    WIFI_LOGI("Enter StaService::ReAssociate.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::EnableDeviceConfig(int networkId, bool attemptEnable) const
{
    WIFI_LOGI("Enter StaService::EnableDeviceConfig, networkid is %{public}d", networkId);

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
    WIFI_LOGI("Enter StaService::DisableDeviceConfig, networkid is %{public}d", networkId);

    if (WifiSettings::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::DISABLED) < 0) {
        WIFI_LOGE("Disable device config failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SyncDeviceConfig();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::Disconnect() const
{
    WIFI_LOGI("Enter StaService::Disconnect.\n");
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    if (pStaAutoConnectService->EnableOrDisableBssid(linkedInfo.bssid, false, AP_CANNOT_HANDLE_NEW_STA)) {
        WIFI_LOGI("The blocklist is updated.\n");
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISCONNECT);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWps(const WpsConfig &config) const
{
    WIFI_LOGI("Enter StaService::StartWps.\n");
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
    WIFI_LOGI("Enter StaService::CanceltWps.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CANCELWPS);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetCountryCode(const std::string &countryCode) const
{
    LOGI("Enter StaService::SetCountryCode, countryCode=[%{public}s]!", countryCode.c_str());
    if (WifiSupplicantHalInterface::GetInstance().WpaSetCountryCode(countryCode) != WIFI_IDL_OPT_OK) {
        LOGE("WpaSetCountryCode() failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("WpaSetCountryCode() succeed!");
    WifiSettings::GetInstance().SetCountryCode(countryCode);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AutoConnectService(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter StaService::AutoConnectService.\n");
    CHECK_NULL_AND_RETURN(pStaAutoConnectService, WIFI_OPT_FAILED);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
    return WIFI_OPT_SUCCESS;
}

void StaService::RegisterStaServiceCallback(const StaServiceCallback &callbacks) const
{
    LOGI("Enter StaService::RegisterStaServiceCallback.");
    if (pStaStateMachine == nullptr) {
        LOGE("pStaStateMachine is null.\n");
        return;
    }
    pStaStateMachine->RegisterStaServiceCallback(callbacks);
}

ErrCode StaService::ReConnect() const
{
    WIFI_LOGI("Enter StaService::ReConnect.\n");
    CHECK_NULL_AND_RETURN(pStaStateMachine, WIFI_OPT_FAILED);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_RECONNECT_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetSuspendMode(bool mode) const
{
    LOGI("Enter StaService::SetSuspendMode, mode=[%{public}d]!", mode);
    if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(mode) != WIFI_IDL_OPT_OK) {
        LOGE("WpaSetSuspendMode() failed!");
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
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#endif
}
}  // namespace Wifi
}  // namespace OHOS
