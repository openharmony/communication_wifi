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

#include "wifi_hotspot_stub.h"
#include "wifi_hotspot_callback_proxy.h"
#include "wifi_logger.h"
#include "string_ex.h"
#include "wifi_errcode.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_hotspot_death_recipient.h"
#include "wifi_common_def.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include <algorithm>
#include "wifi_device.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotStub");

namespace OHOS {
namespace Wifi {
const std::string DHCP_IP_V4_DEFAULT = "192.168.43.1";
std::shared_ptr<WifiDevice> wifiDeviceSharedPtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

WifiHotspotStub::WifiHotspotStub():mSingleCallback(false), m_id(0)
{
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiHotspotStub::WifiHotspotStub(int id):mSingleCallback(false), m_id(id)
{
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiHotspotStub::~WifiHotspotStub()
{
    deathRecipient_ = nullptr;
}

void WifiHotspotStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnIsHotspotActive(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GETAPSTATE_WIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetApStateWifi(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetHotspotConfig(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETAPCONFIG_WIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnSetApConfigWifi(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_STATION_LIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetStationList(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnEnableWifiAp(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI_AP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDisableWifiAp(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ADD_BLOCK_LIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnAddBlockList(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DEL_BLOCK_LIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDelBlockList(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_BLOCK_LISTS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetBlockLists(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISCONNECT_STA)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDisassociateSta(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_BANDS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetValidBands(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_CHANNELS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetValidChannels(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnRegisterCallBack(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetSupportedFeatures(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnGetSupportedPowerModel(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_POWER_MODEL)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetPowerModel(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SET_POWER_MODEL)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnSetPowerModel(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnIsHotspotDualBandSupported(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_SUPPORTED)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnIsOpenSoftApAllowed(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETTIMEOUT_AP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnSetApIdleTimeout(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_IFACE_NAME)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetApIfaceName(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_LOCAL_ONLY_HOTSPOT)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnEnableLocalOnlyHotspot(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_LOCAL_ONLY_HOTSPOT)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDisableLocalOnlyHotspot(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_MODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetHotspotMode(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_LOCAL_ONLY_HOTSPOT_CONFIG)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetLocalOnlyHotspotConfig(code, data, reply, option); };
    return;
}

int WifiHotspotStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Hotspot stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    int exception = data.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        WIFI_LOGW("not find function to deal, code %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        (iter->second)(code, data, reply, option);
    }
    return 0;
}

void WifiHotspotStub::OnIsHotspotActive(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool bActive = false;
    ErrCode ret = IsHotspotActive(bActive);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(bActive ? 1 : 0);
    }
    return;
}

void WifiHotspotStub::OnIsHotspotDualBandSupported(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isSupported = false;
    ErrCode ret = IsHotspotDualBandSupported(isSupported);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(isSupported ? 1 : 0);
    }
    return;
}

void WifiHotspotStub::OnIsOpenSoftApAllowed(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isSupported = false;
    ErrCode ret = IsOpenSoftApAllowed(isSupported);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(isSupported ? 1 : 0);
    }
    return;
}

void WifiHotspotStub::OnGetApStateWifi(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = 0;
    ErrCode ret = GetHotspotState(state);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(state);
    }
    return;
}

void WifiHotspotStub::OnGetHotspotConfig(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    HotspotConfig hotspotConfig;

    ErrCode ret = GetHotspotConfig(hotspotConfig);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteCString(hotspotConfig.GetSsid().c_str());
        reply.WriteInt32(static_cast<int>(hotspotConfig.GetSecurityType()));
        reply.WriteInt32(static_cast<int>(hotspotConfig.GetBand()));
        reply.WriteInt32(hotspotConfig.GetChannel());
        reply.WriteCString(hotspotConfig.GetPreSharedKey().c_str());
        reply.WriteInt32(hotspotConfig.GetMaxConn());
        if (hotspotConfig.GetIpAddress().empty()) {
            reply.WriteString(DHCP_IP_V4_DEFAULT);
        } else {
            reply.WriteString(hotspotConfig.GetIpAddress());
        }
        reply.WriteInt32(hotspotConfig.GetLeaseTime());
    }

    return;
}

bool WifiHotspotStub::CheckHotspot160MParam(BandType band, int bandwidth, int channel)
{
    if ((band != BandType::BAND_5GHZ && bandwidth == AP_BANDWIDTH_160) ||
        (bandwidth != AP_BANDWIDTH_160 && bandwidth != AP_BANDWIDTH_DEFAULT) ||
        (band == BandType::BAND_5GHZ && bandwidth == AP_BANDWIDTH_160 &&
        ((channel < AP_CHANNEL_5G_160M_SET_BEGIN) || (channel > AP_CHANNEL_5G_160M_SET_END)))) {
        return false;
    } else {
        return true;
    }
}

bool WifiHotspotStub::CheckHostspot160MCountryCode()
{
    std::string countryCode;
    ErrCode ret = wifiDeviceSharedPtr->GetCountryCode(countryCode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("CheckHostspot160MCountryCode GetcountryCode fail");
        return false;
    }
    transform(countryCode.begin(), countryCode.end(), countryCode.begin(), ::toupper);
    if (countryCode == "CN" || countryCode == "TW" || countryCode == "SG" || countryCode == "KR") {
        WIFI_LOGD("CheckHostspot160MCountryCode countryCode %{public}s", countryCode.c_str());
        return true;
    } else {
        WIFI_LOGE("CheckHostspot160MCountryCode Error countryCode %{public}s", countryCode.c_str());
        return false;
    }
}

void WifiHotspotStub::OnSetApConfigWifi(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    HotspotConfig config;
    const char *ssidRead = data.ReadCString();
    config.SetSecurityType(static_cast<KeyMgmt>(data.ReadInt32()));
    config.SetBand(static_cast<BandType>(data.ReadInt32()));
    int dataRead = data.ReadInt32();
    int channel = dataRead & 0x000000FF;
    int bandwidth = (dataRead & 0x00FF0000) >> 16;

    BandType band = config.GetBand();
    config.SetBandWidth(bandwidth);
    config.SetChannel(channel);
    WIFI_LOGI("run %{public}s channel %{public}d bandwidth %{public}d band %{public}d",
        __func__, config.GetChannel(), config.GetBandWidth(), config.GetBand());
    const char *preSharedKeyRead = data.ReadCString();
    config.SetMaxConn(data.ReadInt32());
    config.SetIpAddress(data.ReadString());
    config.SetLeaseTime(data.ReadInt32());
    if (ssidRead == nullptr || preSharedKeyRead == nullptr || !CheckHotspot160MParam(band, bandwidth, channel)) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else if ((!CheckHostspot160MCountryCode()) && bandwidth == AP_BANDWIDTH_160) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        config.SetSsid(ssidRead);
        config.SetPreSharedKey(preSharedKeyRead);
        ret = SetHotspotConfig(config);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnGetStationList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<StationInfo> result;
    ErrCode ret = GetStationList(result);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int size = static_cast<int>(result.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; i++) {
            reply.WriteCString(result[i].deviceName.c_str());
            reply.WriteCString(result[i].bssid.c_str());
            reply.WriteInt32(result[i].bssidType);
            reply.WriteCString(result[i].ipAddr.c_str());
        }
    }

    return;
}

void WifiHotspotStub::OnDisassociateSta(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    StationInfo info;
    const char *deviceNameRead = data.ReadCString();
    const char *bssidRead = data.ReadCString();
    const int bssidTypeRead = data.ReadInt32();
    const char *ipAddrRead = data.ReadCString();
    if (deviceNameRead == nullptr || bssidRead == nullptr || ipAddrRead == nullptr) {
        WIFI_LOGE("failed to read data, %{public}s", __func__);
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        info.deviceName = deviceNameRead;
        info.bssid = bssidRead;
        info.bssidType = bssidTypeRead;
        info.ipAddr = ipAddrRead;
        ret = DisassociateSta(info);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiHotspotStub::OnGetValidBands(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<BandType> bands;
    ErrCode ret = GetValidBands(bands);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int count = static_cast<int>(bands.size());
        reply.WriteInt32(count);
        for (int i = 0; i < count; i++) {
            reply.WriteInt32((int)bands[i]);
        }
    }
    return;
}

void WifiHotspotStub::OnGetValidChannels(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<int32_t> channels;
    int32_t band = data.ReadInt32();
    ErrCode ret = GetValidChannels(static_cast<BandType>(band), channels);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int count = static_cast<int>(channels.size());
        reply.WriteInt32(count);
        for (int i = 0; i < count; i++) {
            reply.WriteInt32(channels[i]);
        }
    }
    return;
}

void WifiHotspotStub::OnEnableWifiAp(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int32_t serviceType = data.ReadInt32();
    ErrCode ret = EnableHotspot(ServiceType(serviceType));
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnDisableWifiAp(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int32_t serviceType = data.ReadInt32();
    ErrCode ret = DisableHotspot(ServiceType(serviceType));
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnAddBlockList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    StationInfo info;
    const char *deviceNameRead = data.ReadCString();
    const char *bssidRead = data.ReadCString();
    const int bssidTypeRead = data.ReadInt32();
    const char *ipAddrRead = data.ReadCString();
    if (deviceNameRead == nullptr || bssidRead == nullptr || ipAddrRead == nullptr) {
        WIFI_LOGE("failed to read data, %{public}s", __func__);
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        info.deviceName = deviceNameRead;
        info.bssid = bssidRead;
        info.bssidType = bssidTypeRead;
        info.ipAddr = ipAddrRead;
        ret = AddBlockList(info);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnDelBlockList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    StationInfo info;
    const char *deviceNameRead = data.ReadCString();
    const char *bssidRead = data.ReadCString();
    const int bssidTypeRead = data.ReadInt32();
    const char *ipAddrRead = data.ReadCString();
    if (deviceNameRead == nullptr || bssidRead == nullptr || ipAddrRead == nullptr) {
        WIFI_LOGE("failed to read data, %{public}s", __func__);
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        info.deviceName = deviceNameRead;
        info.bssid = bssidRead;
        info.bssidType = bssidTypeRead;
        info.ipAddr = ipAddrRead;
        ret = DelBlockList(info);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnGetBlockLists(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<StationInfo> infos;
    ErrCode ret = GetBlockLists(infos);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int size = static_cast<int>(infos.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; i++) {
            reply.WriteCString(infos[i].deviceName.c_str());
            reply.WriteCString(infos[i].bssid.c_str());
            reply.WriteInt32(infos[i].bssidType);
            reply.WriteCString(infos[i].ipAddr.c_str());
        }
    }

    return;
}

void WifiHotspotStub::OnRegisterCallBack(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    do {
        sptr<IRemoteObject> remote = data.ReadRemoteObject();
        if (remote == nullptr) {
            WIFI_LOGE("Failed to ReadRemoteObject!");
            break;
        }
        sptr<IWifiHotspotCallback> callback_ = iface_cast<IWifiHotspotCallback>(remote);
        if (callback_ == nullptr) {
            callback_ = sptr<WifiHotspotCallbackProxy>::MakeSptr(remote);
            WIFI_LOGI("create new WifiHotspotCallbackProxy!");
        }

        int eventNum = data.ReadInt32();
        std::vector<std::string> event;
        if (eventNum > 0 && eventNum <= MAX_READ_EVENT_SIZE) {
            for (int i = 0; i < eventNum; ++i) {
                event.emplace_back(data.ReadString());
            }
        }

        if (mSingleCallback) {
            ret = RegisterCallBack(callback_, event);
        } else {
            std::unique_lock<std::mutex> lock(deathRecipientMutex);
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = sptr<WifiHotspotDeathRecipient>::MakeSptr();
            }
            // Add death recipient to remote object if this is the first time to register callback.
            if (remote->IsProxyObject() &&
                !WifiInternalEventDispatcher::GetInstance().HasHotspotRemote(remote, m_id)) {
                remote->AddDeathRecipient(deathRecipient_);
            }

            if (callback_ != nullptr) {
                for (const auto &eventName : event) {
                    ret = WifiInternalEventDispatcher::GetInstance().AddHotspotCallback(remote, callback_, eventName,
                        m_id);
                }
            }
        }
    } while (0);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiHotspotStub::OnGetSupportedFeatures(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    long features = 0;
    int ret = GetSupportedFeatures(features);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt64(features);
    }

    return;
}

void WifiHotspotStub::OnGetSupportedPowerModel(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::set<PowerModel> setPowerModelList;
    ErrCode ret = GetSupportedPowerModel(setPowerModelList);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int size = (int)setPowerModelList.size();
        reply.WriteInt32(size);
        for (auto &powerModel : setPowerModelList) {
            reply.WriteInt32(static_cast<int>(powerModel));
        }
    }
    return;
}

void WifiHotspotStub::OnGetPowerModel(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    PowerModel model;
    ErrCode ret = GetPowerModel(model);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    reply.WriteInt32(static_cast<int>(model));
    return;
}

void WifiHotspotStub::OnSetPowerModel(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    PowerModel model = PowerModel(data.ReadInt32());
    ErrCode ret = SetPowerModel(model);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiHotspotStub::OnSetApIdleTimeout(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{private}s code %{private}u, datasize %{private}zu", __func__, code, data.GetRawDataSize());
    int time = data.ReadInt32();
    int ret = SetHotspotIdleTimeout(time);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiHotspotStub::OnGetApIfaceName(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{private}s code %{private}u, datasize %{private}zu", __func__, code, data.GetRawDataSize());
    std::string ifaceName;
    ErrCode ret = GetApIfaceName(ifaceName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteString(ifaceName);
    }
    return;
}

void WifiHotspotStub::OnEnableLocalOnlyHotspot(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int32_t serviceType = data.ReadInt32();
    ErrCode ret = EnableLocalOnlyHotspot(ServiceType(serviceType));
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
 
    return;
}
 
void WifiHotspotStub::OnDisableLocalOnlyHotspot(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int32_t serviceType = data.ReadInt32();
    ErrCode ret = DisableLocalOnlyHotspot(ServiceType(serviceType));
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
 
    return;
}
 
void WifiHotspotStub::OnGetHotspotMode(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    Wifi::HotspotMode mode = Wifi::HotspotMode::NONE;
    ErrCode ret = GetHotspotMode(mode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    reply.WriteInt32(static_cast<int>(mode));
    return;
}
 
void WifiHotspotStub::OnGetLocalOnlyHotspotConfig(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    HotspotConfig localOnlyHotspotConfig;
 
    ErrCode ret = GetLocalOnlyHotspotConfig(localOnlyHotspotConfig);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteCString(localOnlyHotspotConfig.GetSsid().c_str());
        reply.WriteInt32(static_cast<int>(localOnlyHotspotConfig.GetSecurityType()));
        reply.WriteInt32(static_cast<int>(localOnlyHotspotConfig.GetBand()));
        reply.WriteInt32(localOnlyHotspotConfig.GetChannel());
        reply.WriteCString(localOnlyHotspotConfig.GetPreSharedKey().c_str());
        reply.WriteInt32(localOnlyHotspotConfig.GetMaxConn());
        if (localOnlyHotspotConfig.GetIpAddress().empty()) {
            reply.WriteString(DHCP_IP_V4_DEFAULT);
        } else {
            reply.WriteString(localOnlyHotspotConfig.GetIpAddress());
        }
        reply.WriteInt32(localOnlyHotspotConfig.GetLeaseTime());
    }
 
    return;
}
}  // namespace Wifi
}  // namespace OHOS
