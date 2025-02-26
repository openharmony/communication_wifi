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

#include "wifi_device_stub.h"
#include "string_ex.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_device_callback_proxy.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_device_death_recipient.h"
#include "wifi_common_util.h"
#include "wifi_common_def.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_watchdog_utils.h"

DEFINE_WIFILOG_LABEL("WifiDeviceStub");

namespace OHOS {
namespace Wifi {

constexpr int SIGNALARR_LENGTH = 6;

static std::map<int, std::string> g_HicollieStaMap = {
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), "WIFI_SVR_CMD_IS_WIFI_CONNECTED"},
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), "WIFI_SVR_CMD_IS_WIFI_ACTIVE"},
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), "WIFI_SVR_CMD_IS_METERED_HOTSPOT"},
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT),
        "WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT"},
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), "WIFI_SVR_CMD_GET_SIGNAL_LEVEL"},
    {static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE), "WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE"},
};

WifiDeviceStub::WifiDeviceStub() : mSingleCallback(false)
{
    WIFI_LOGI("enter WifiDeviceStub!");
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiDeviceStub::WifiDeviceStub(int instId) : mSingleCallback(false), m_instId(instId)
{
    WIFI_LOGI("enter WifiDeviceStub!");
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiDeviceStub::~WifiDeviceStub()
{
    WIFI_LOGI("enter ~WifiDeviceStub!");
    deathRecipient_ = nullptr;
}

void WifiDeviceStub::InitHandleMapEx()
{
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetSignalLevel(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetSupportedFeatures(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetIpV6Info(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetDeviceMacAdd(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsWifiConnected(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetLowLatencyMode(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnRemoveCandidateConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsBandTypeSupported(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGet5GHzChannelList(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetDisconnectedReason(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetFrozenApp(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnResetAllFrozenApp(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnDisableAutoJoin(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_AUTO_JOIN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnEnableAutoJoin(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnStartPortalCertification(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE)] = [this](
        uint32_t code, MessageParcel &data, MessageParcel &reply) { OnGetChangeDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnFactoryReset(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnLimitSpeed(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnEnableHiLinkHandshake(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnEnableSemiWifi(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetWifiDetailState(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_SATELLITE_STATE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetSatelliteState(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_TX_POWER)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetLowTxPower(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_TX_POWER)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetTxPower(code, data, reply); };
    return;
}

void WifiDeviceStub::InitHandleMapEx2()
{
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_ROAM_TO_NETWORK)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnStartRoamToNetwork(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_CONNECT_TO_USER_SELECT_NETWORK)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply) {
            OnStartConnectToUserSelectNetwork(code, data, reply);
        };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_DPI_MARK_RULE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetDpiMarkRule(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsFeatureSupported(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_NET_CONTROL_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnReceiveNetworkControlInfo(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_NETWORK_LAG_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnUpdateNetworkLagInfo(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_FETCH_SIGNALINFO_VOWIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnFetchWifiSignalInfoForVoWiFi(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SUPPORT_VOWIFI_DETECT)] = [this]
        (uint32_t code, MessageParcel &data, MessageParcel &reply) { OnIsSupportVoWifiDetect(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_MODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetVoWifiDetectMode(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_MODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetVoWifiDetectMode(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_PERIOD)] = [this]
        (uint32_t code, MessageParcel &data, MessageParcel &reply) { OnSetVoWifiDetectPeriod(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_PERIOD)] = [this]
        (uint32_t code, MessageParcel &data, MessageParcel &reply) { OnGetVoWifiDetectPeriod(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNALPOLL_INFO_ARRAY)] = [this]
        (uint32_t code, MessageParcel &data, MessageParcel &reply) { OnGetSignalPollInfoArray(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_MULTI_LINKED_INFO)] = [this]
        (uint32_t code, MessageParcel &data, MessageParcel &reply) { OnGetMultiLinkedInfo(code, data, reply); };
}

void WifiDeviceStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnEnableWifi(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnDisableWifi(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnInitWifiProtect(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetWifiProtectRef(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnPutWifiProtectRef(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsHeldWifiProtectRef(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnAddDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnUpdateDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnRemoveDevice(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply) { OnRemoveAllDevice(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetDeviceConfigs(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnEnableDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnDisableDeviceConfig(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ALLOW_AUTO_CONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnAllowAutoConnect(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnConnectTo(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnConnect2To(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnReConnect(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnReAssociate(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnDisconnect(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnStartWps(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnCancelWps(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsWifiActive(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetWifiState(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnIsMeteredHotspot(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetLinkedInfo(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetIpInfo(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnSetCountryCode(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply) { OnGetCountryCode(code, data, reply); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply) { OnRegisterCallBack(code, data, reply); };
    InitHandleMapEx();
    InitHandleMapEx2();
    return;
}

int WifiDeviceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Sta stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    WIFI_LOGD("%{public}s, code: %{public}u, uid: %{public}d, pid: %{public}d",
        __func__, code, GetCallingUid(), GetCallingPid());
    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        WIFI_LOGI("not find function to deal, code %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        int exception = data.ReadInt32();
        if (exception) {
            return WIFI_OPT_FAILED;
        }
        std::map<int, std::string>::const_iterator itCollieId = g_HicollieStaMap.find(code);
        if (itCollieId != g_HicollieStaMap.end()) {
            int idTimer = 0;
            idTimer = WifiWatchDogUtils::GetInstance()->StartWatchDogForFunc(itCollieId->second);
            WIFI_LOGI("SetTimer id: %{public}d, name: %{public}s.", idTimer, itCollieId->second.c_str());
            (iter->second)(code, data, reply);
            WifiWatchDogUtils::GetInstance()->StopWatchDogForFunc(itCollieId->second, idTimer);
        } else {
            (iter->second)(code, data, reply);
        }
    }
    return 0;
}


void WifiDeviceStub::OnEnableWifi(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = EnableWifi();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisableWifi(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = DisableWifi();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnInitWifiProtect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    WifiProtectType protectType = (WifiProtectType)data.ReadInt32();
    const char *readStr = data.ReadCString();
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string protectName = readStr;
        ret = InitWifiProtect(protectType, protectName);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnGetWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    WifiProtectMode protectMode = (WifiProtectMode)data.ReadInt32();
    const char *readStr = data.ReadCString();
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string protectName = readStr;
        ret = GetWifiProtectRef(protectMode, protectName);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnPutWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    const char *readStr = data.ReadCString();
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string protectName = readStr;
        ret = PutWifiProtectRef(protectName);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnIsHeldWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    const char *readStr = data.ReadCString();
    bool isHoldProtect = false;
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string protectName = readStr;
        ret = IsHeldWifiProtectRef(protectName, isHoldProtect);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(isHoldProtect);
    }
    return;
}

void WifiDeviceStub::OnAddDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isCandidate = data.ReadBool();
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(data, config);

    int result = INVALID_NETWORK_ID;
    ErrCode ret = AddDeviceConfig(config, result, isCandidate);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(result);
    }

    return;
}

void WifiDeviceStub::OnUpdateDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(data, config);
    int result = INVALID_NETWORK_ID;
    ErrCode ret = UpdateDeviceConfig(config, result);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(result);
    }
    return;
}

void WifiDeviceStub::ReadEapConfig(MessageParcel &data, WifiEapConfig &wifiEapConfig)
{
    wifiEapConfig.eap = data.ReadString();
    wifiEapConfig.phase2Method = Phase2Method(data.ReadInt32());
    wifiEapConfig.identity = data.ReadString();
    wifiEapConfig.anonymousIdentity = data.ReadString();
    wifiEapConfig.password = data.ReadString();

    wifiEapConfig.caCertPath = data.ReadString();
    wifiEapConfig.caCertAlias = data.ReadString();
    data.ReadUInt8Vector(&wifiEapConfig.certEntry);

    wifiEapConfig.clientCert = data.ReadString();
    if (strcpy_s(wifiEapConfig.certPassword, sizeof(wifiEapConfig.certPassword),
        data.ReadString().c_str()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy", __func__);
    }
    wifiEapConfig.privateKey = data.ReadString();

    wifiEapConfig.altSubjectMatch = data.ReadString();
    wifiEapConfig.domainSuffixMatch = data.ReadString();
    wifiEapConfig.realm = data.ReadString();
    wifiEapConfig.plmn = data.ReadString();
    wifiEapConfig.eapSubId = data.ReadInt32();
}

void WifiDeviceStub::ReadWifiDeviceConfig(MessageParcel &data, WifiDeviceConfig &config)
{
    config.networkId = data.ReadInt32();
    config.bssid = data.ReadString();
    config.bssidType = data.ReadInt32();
    config.ssid = data.ReadString();
    config.band = data.ReadInt32();
    config.channel = data.ReadInt32();
    config.frequency = data.ReadInt32();
    config.level = data.ReadInt32();
    config.isPasspoint = data.ReadBool();
    config.isEphemeral = data.ReadBool();
    config.preSharedKey = data.ReadString();
    config.keyMgmt = data.ReadString();
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = data.ReadString();
    }
    config.wepTxKeyIndex = data.ReadInt32();
    config.priority = data.ReadInt32();
    config.hiddenSSID = data.ReadBool();
    config.wifiIpConfig.assignMethod = AssignIpMethod(data.ReadInt32());
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = data.ReadInt32();
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.gateway);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer1);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer2);
    config.wifiIpConfig.staticIpAddress.domains = data.ReadString();
    ReadEapConfig(data, config.wifiEapConfig);
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(data.ReadInt32());
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = data.ReadInt32();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = data.ReadString();
    config.wifiPrivacySetting = WifiPrivacyConfig(data.ReadInt32());
    config.callProcessName = data.ReadString();
    config.ancoCallProcessName = data.ReadString();
    config.uid = data.ReadInt32();
    config.wifiWapiConfig.wapiPskType = data.ReadInt32();
    config.wifiWapiConfig.wapiAsCertData = data.ReadString();
    config.wifiWapiConfig.wapiUserCertData = data.ReadString();
    return;
}

void WifiDeviceStub::ReadIpAddress(MessageParcel &data, WifiIpAddress &address)
{
    constexpr int MAX_LIMIT_SIZE = 1024;
    address.family = data.ReadInt32();
    address.addressIpv4 = static_cast<uint32_t>(data.ReadInt32());
    int size = data.ReadInt32();
    if (size > MAX_LIMIT_SIZE) {
        WIFI_LOGE("Read ip address parameter error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(data.ReadInt8());
    }
    return;
}

void WifiDeviceStub::WriteEapConfig(MessageParcel &reply, const WifiEapConfig &wifiEapConfig)
{
    reply.WriteString(wifiEapConfig.eap);
    reply.WriteInt32(static_cast<int>(wifiEapConfig.phase2Method));
    reply.WriteString(wifiEapConfig.identity);
    reply.WriteString(wifiEapConfig.anonymousIdentity);
    reply.WriteString(wifiEapConfig.password);

    reply.WriteString(wifiEapConfig.caCertPath);
    reply.WriteString(wifiEapConfig.caCertAlias);
    reply.WriteUInt8Vector(wifiEapConfig.certEntry);

    reply.WriteString(wifiEapConfig.clientCert);
    reply.WriteString(std::string(wifiEapConfig.certPassword));
    reply.WriteString(wifiEapConfig.privateKey);

    reply.WriteString(wifiEapConfig.altSubjectMatch);
    reply.WriteString(wifiEapConfig.domainSuffixMatch);
    reply.WriteString(wifiEapConfig.realm);
    reply.WriteString(wifiEapConfig.plmn);
    reply.WriteInt32(wifiEapConfig.eapSubId);
}

void WifiDeviceStub::BigDataWriteEapConfig(const WifiEapConfig &wifiEapConfig, std::stringstream &bigDataStream)
{
    bigDataStream << StringToHex(wifiEapConfig.eap) << ";";
    bigDataStream << static_cast<int>(wifiEapConfig.phase2Method) << ";";
    bigDataStream << StringToHex(wifiEapConfig.identity) << ";";
    bigDataStream << StringToHex(wifiEapConfig.anonymousIdentity) << ";";
    bigDataStream << StringToHex(wifiEapConfig.password) << ";";
 
    bigDataStream << StringToHex(wifiEapConfig.caCertPath) << ";";
    bigDataStream << StringToHex(wifiEapConfig.caCertAlias) << ";";
 
    bigDataStream << StringToHex(wifiEapConfig.clientCert) << ";";
    bigDataStream << StringToHex(wifiEapConfig.privateKey) << ";";
 
    bigDataStream << StringToHex(wifiEapConfig.altSubjectMatch) << ";";
    bigDataStream << StringToHex(wifiEapConfig.domainSuffixMatch) << ";";
    bigDataStream << StringToHex(wifiEapConfig.realm) << ";";
    bigDataStream << StringToHex(wifiEapConfig.plmn) << ";";
    bigDataStream << wifiEapConfig.eapSubId << ";";
}

void WifiDeviceStub::WriteWifiDeviceConfig(MessageParcel &reply, const WifiDeviceConfig &config)
{
    reply.WriteInt32(config.networkId);
    reply.WriteString(config.bssid);
    reply.WriteInt32(config.bssidType);
    reply.WriteString(config.ssid);
    reply.WriteInt32(config.band);
    reply.WriteInt32(config.channel);
    reply.WriteInt32(config.frequency);
    reply.WriteInt32(config.level);
    reply.WriteBool(config.isPasspoint);
    reply.WriteBool(config.isEphemeral);
    reply.WriteString(config.preSharedKey);
    reply.WriteString(config.keyMgmt);
    for (int j = 0; j < WEPKEYS_SIZE; j++) {
        reply.WriteString(config.wepKeys[j]);
    }
    reply.WriteInt32(config.wepTxKeyIndex);
    reply.WriteInt32(config.priority);
    reply.WriteBool(config.hiddenSSID);
    reply.WriteInt32((int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
    reply.WriteString(config.wifiIpConfig.staticIpAddress.domains);
    WriteEapConfig(reply, config.wifiEapConfig);
    reply.WriteInt32((int)config.wifiProxyconfig.configureMethod);
    reply.WriteString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress);
    reply.WriteString(config.wifiProxyconfig.manualProxyConfig.serverHostName);
    reply.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    reply.WriteString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
    reply.WriteInt32((int)config.wifiPrivacySetting);
    reply.WriteInt32(config.uid);
    reply.WriteString(config.callProcessName);
    reply.WriteString(config.ancoCallProcessName);
    reply.WriteInt32(config.wifiWapiConfig.wapiPskType);
    reply.WriteInt32((int)config.networkSelectionStatus.status);
    reply.WriteInt32((int)config.networkSelectionStatus.networkSelectionDisableReason);
    reply.WriteBool(config.networkSelectionStatus.seenInLastQualifiedNetworkSelection);
    reply.WriteBool(config.isPortal);
    reply.WriteBool(config.noInternetAccess);
    reply.WriteBool(config.isAllowAutoConnect);
    return;
}

void WifiDeviceStub::WriteIpAddress(MessageParcel &reply, const WifiIpAddress &address)
{
    reply.WriteInt32(address.family);
    reply.WriteInt32(address.addressIpv4);
    int size = static_cast<int>(address.addressIpv6.size());
    reply.WriteInt32(size);
    for (int i = 0; i < size; i++) {
        reply.WriteInt8(address.addressIpv6[i]);
    }

    return;
}

void WifiDeviceStub::BigDataWriteIpAddress(const WifiIpAddress &address, std::stringstream &bigDataStream)
{
    bigDataStream << address.family << ";";
    bigDataStream << address.addressIpv4 << ";";
    int size = static_cast<int>(address.addressIpv6.size());
    bigDataStream << size << ";";
    for (int i = 0; i < size; i++) {
        bigDataStream << address.addressIpv6[i] << ";";
    }
 
    return;
}

void WifiDeviceStub::OnRemoveDevice(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    ErrCode ret = RemoveDevice(networkId);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnRemoveAllDevice(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = RemoveAllDevice();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::SendDeviceConfig(int contentSize, std::vector<WifiDeviceConfig> &result, MessageParcel &reply)
{
    WIFI_LOGI("%{public}s, contentSize: %{public}d", __FUNCTION__, contentSize);
    std::vector<uint32_t> allSize;
    if (contentSize == 0) {
        reply.WriteInt32(WIFI_OPT_SUCCESS);
        reply.WriteUInt32Vector(allSize);
        return;
    }
    std::string name = "deviceconfigs";
    int32_t ashmemSize = 1000; // add buff for max 1000 device config  
    for (int32_t i = 0; i < contentSize; ++i) {
        MessageParcel outParcel;
        WriteWifiDeviceConfig(outParcel, result[i]);
        ashmemSize += static_cast<int>(outParcel.GetDataSize());
    }
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(name.c_str(), ashmemSize);
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        reply.WriteInt32(WIFI_OPT_FAILED);
        if (ashmem != nullptr) {
            ashmem->UnmapAshmem();
            ashmem->CloseAshmem();
        }
        WIFI_LOGE("%{public}s ashmem create fail", __FUNCTION__);
        return;
    }
    int offset = 0;
    for (int32_t i = 0; i < contentSize; ++i) {
        MessageParcel outParcel;
        WriteWifiDeviceConfig(outParcel, result[i]);
        int dataSize = static_cast<int>(outParcel.GetDataSize());
        if (offset + dataSize > ashmemSize) {
            WIFI_LOGW("%{public}s parcelLen over ssid: %{public}s, ashmemSize:%{public}d,"
                "dataSize:%{public}d, offset:%{public}d", __FUNCTION__, SsidAnonymize(result[i].ssid).c_str(),
                ashmemSize, dataSize, offset);
            continue;
        }
        allSize.emplace_back(dataSize);
        ashmem->WriteToAshmem(reinterpret_cast<void*>(outParcel.GetData()), dataSize, offset);
        offset += dataSize;
    }
    reply.WriteInt32(WIFI_OPT_SUCCESS);
    reply.WriteUInt32Vector(allSize);
    reply.WriteAshmem(ashmem);
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
}

constexpr uint32_t MAX_DEVICE_CONFIG_SIZE = 1024;
void WifiDeviceStub::OnGetDeviceConfigs(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isCandidate = data.ReadBool();
    std::vector<WifiDeviceConfig> result;
    ErrCode ret = GetDeviceConfigs(result, isCandidate);
    reply.WriteInt32(0);

    if (ret != WIFI_OPT_SUCCESS) {
        reply.WriteInt32(ret);
        return;
    }
    uint32_t size = result.size();
    if (size > MAX_DEVICE_CONFIG_SIZE) {
        size = MAX_DEVICE_CONFIG_SIZE;
    }
    SendDeviceConfig(size, result, reply);
    return;
}

void WifiDeviceStub::OnEnableDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    bool attemptEnable = data.ReadBool();
    ErrCode ret = EnableDeviceConfig(networkId, attemptEnable);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisableDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    ErrCode ret = DisableDeviceConfig(networkId);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnAllowAutoConnect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int32_t networkId = data.ReadInt32();
    bool isAllowed = data.ReadBool();
    ErrCode ret = AllowAutoConnect(networkId, isAllowed);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnGetChangeDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    Wifi::ConfigChange value;
    Wifi::WifiDeviceConfig config;
    ErrCode ret = GetChangeDeviceConfig(value, config);
    reply.WriteInt32(0);
    reply.WriteInt32((int)value);
    reply.WriteInt32(config.networkId);
    reply.WriteString(config.ssid);
    reply.WriteString(config.bssid);
    reply.WriteString(config.callProcessName);
    reply.WriteString(config.ancoCallProcessName);
    reply.WriteString(config.keyMgmt);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnConnectTo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isCandidate = data.ReadBool();
    int networkId = data.ReadInt32();
    ErrCode ret = ConnectToNetwork(networkId, isCandidate);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnConnect2To(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(data, config);
    ErrCode ret = ConnectToDevice(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnStartRoamToNetwork(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    std::string bssid = data.ReadString();
    bool isCandidate = data.ReadBool();
    ErrCode ret = StartRoamToNetwork(networkId, bssid, isCandidate);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnStartConnectToUserSelectNetwork(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("enter %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    std::string bssid = data.ReadString();
    bool isCandidate = data.ReadBool();
    ErrCode ret = StartConnectToUserSelectNetwork(networkId, bssid, isCandidate);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnIsWifiConnected(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isConnected = false;
    ErrCode ret = IsConnected(isConnected);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(isConnected);
    }
    return;
}

void WifiDeviceStub::OnReConnect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = ReConnect();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnReAssociate(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = ReAssociate();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisconnect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = Disconnect();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnStartWps(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    WpsConfig config;
    config.setup = SetupMethod(data.ReadInt32());
    const char *pinRead = data.ReadCString();
    const char *bssidRead = data.ReadCString();
    if (pinRead == nullptr || bssidRead == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        config.pin = pinRead;
        config.bssid = bssidRead;
        ret = StartWps(config);
    }

    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnCancelWps(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = CancelWps();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnIsWifiActive(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool bActive = false;
    ErrCode ret = IsWifiActive(bActive);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(bActive);
    }
    return;
}

void WifiDeviceStub::OnGetWifiState(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = 0;
    ErrCode ret = GetWifiState(state);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(state);
    }
    return;
}

void WifiDeviceStub::OnIsMeteredHotspot(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool bMeteredHotspot = false;
    ErrCode ret = IsMeteredHotspot(bMeteredHotspot);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(bMeteredHotspot);
    }
    return;
}

void WifiDeviceStub::WriteWifiLinkedInfo(MessageParcel &reply, const WifiLinkedInfo &wifiInfo)
{
    reply.WriteInt32(wifiInfo.networkId);
    reply.WriteString(wifiInfo.ssid);
    reply.WriteString(wifiInfo.bssid);
    reply.WriteInt32(wifiInfo.rssi);
    reply.WriteInt32(wifiInfo.band);
    reply.WriteInt32(wifiInfo.frequency);
    reply.WriteInt32(wifiInfo.linkSpeed);
    reply.WriteString(wifiInfo.macAddress);
    reply.WriteInt32(wifiInfo.macType);
    reply.WriteInt32(wifiInfo.ipAddress);
    reply.WriteInt32(static_cast<int>(wifiInfo.connState));
    reply.WriteBool(wifiInfo.ifHiddenSSID);
    reply.WriteInt32(wifiInfo.rxLinkSpeed);
    reply.WriteInt32(wifiInfo.txLinkSpeed);
    reply.WriteInt32(wifiInfo.chload);
    reply.WriteInt32(wifiInfo.snr);
    reply.WriteInt32(wifiInfo.isDataRestricted);
    reply.WriteString(wifiInfo.portalUrl);
    reply.WriteInt32(static_cast<int>(wifiInfo.supplicantState));
    reply.WriteInt32(static_cast<int>(wifiInfo.detailedState));
    reply.WriteInt32(static_cast<int>(wifiInfo.wifiStandard));
    reply.WriteInt32(static_cast<int>(wifiInfo.maxSupportedRxLinkSpeed));
    reply.WriteInt32(static_cast<int>(wifiInfo.maxSupportedTxLinkSpeed));
    reply.WriteInt32(static_cast<int>(wifiInfo.channelWidth));
    reply.WriteBool(wifiInfo.isAncoConnected);
    reply.WriteInt32(static_cast<int>(wifiInfo.supportedWifiCategory));
    reply.WriteBool(wifiInfo.isHiLinkNetwork);
    reply.WriteInt32(wifiInfo.lastRxPackets);
    reply.WriteInt32(wifiInfo.lastTxPackets);
    reply.WriteInt32(static_cast<int>(wifiInfo.wifiLinkType));
    reply.WriteInt32(wifiInfo.linkId);
}

void WifiDeviceStub::OnGetLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiLinkedInfo wifiInfo;
    ErrCode ret = GetLinkedInfo(wifiInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        WriteWifiLinkedInfo(reply, wifiInfo);
    }
    return;
}

void WifiDeviceStub::OnGetSignalPollInfoArray(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    reply.WriteInt32(0);
    std::vector<WifiSignalPollInfo> wifiSignalPollInfos;
    int length = data.ReadInt32();
    if (length > SIGNALARR_LENGTH) {
        length = SIGNALARR_LENGTH;
    }
    ErrCode ret = GetSignalPollInfoArray(wifiSignalPollInfos, length);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        for (int index  = 0 ; index < length ; index++) {
            reply.WriteInt32(wifiSignalPollInfos[index].signal);
            reply.WriteInt32(wifiSignalPollInfos[index].txrate);
            reply.WriteInt32(wifiSignalPollInfos[index].rxrate);
            reply.WriteInt32(wifiSignalPollInfos[index].noise);
            reply.WriteInt32(wifiSignalPollInfos[index].txPackets);
            reply.WriteInt32(wifiSignalPollInfos[index].rxPackets);
            reply.WriteInt32(wifiSignalPollInfos[index].snr);
            reply.WriteInt32(wifiSignalPollInfos[index].chload);
            reply.WriteInt32(wifiSignalPollInfos[index].ulDelay);
            reply.WriteInt32(wifiSignalPollInfos[index].txBytes);
            reply.WriteInt32(wifiSignalPollInfos[index].rxBytes);
            reply.WriteInt32(wifiSignalPollInfos[index].txFailed);
            reply.WriteInt32(wifiSignalPollInfos[index].chloadSelf);
            reply.WriteInt64(wifiSignalPollInfos[index].timeStamp);
        }
    }
    return;
}
void WifiDeviceStub::OnGetMultiLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<WifiLinkedInfo> multiLinkedInfo;
    ErrCode ret = GetMultiLinkedInfo(multiLinkedInfo);
    reply.WriteInt32(0);
    if (ret != WIFI_OPT_SUCCESS) {
        reply.WriteInt32(ret);
    }
    uint32_t size = static_cast<uint32_t>(multiLinkedInfo.size());
    if (size > WIFI_MAX_MLO_LINK_NUM) {
        size = WIFI_MAX_MLO_LINK_NUM;
    }
    SendMultiLinkedInfo(size, multiLinkedInfo, reply);
}

void WifiDeviceStub::SendMultiLinkedInfo(uint32_t contentSize, std::vector<WifiLinkedInfo> &result,
    MessageParcel &reply)
{
    WIFI_LOGI("%{public}s, contentSize: %{public}d", __FUNCTION__, contentSize);
    std::vector<uint32_t> allSize;
    if (contentSize == 0) {
        reply.WriteInt32(WIFI_OPT_SUCCESS);
        reply.WriteUInt32Vector(allSize);
        return;
    }
    std::string name = "multiLinkedInfo";
    int32_t ashmemSize = WIFI_MAX_MLO_LINK_NUM;
    for (uint32_t i = 0; i < contentSize; i++) {
        MessageParcel outParcel;
        WriteWifiLinkedInfo(outParcel, result[i]);
        ashmemSize += static_cast<int>(outParcel.GetDataSize());
    }
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(name.c_str(), ashmemSize);
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        reply.WriteInt32(WIFI_OPT_FAILED);
        if (ashmem != nullptr) {
            ashmem->UnmapAshmem();
            ashmem->CloseAshmem();
        }
        WIFI_LOGE("%{public}s ashmem create fail", __FUNCTION__);
        return;
    }
    int offset = 0;
    for (uint32_t i = 0; i < contentSize; ++i) {
        MessageParcel outParcel;
        WriteWifiLinkedInfo(outParcel, result[i]);
        int dataSize = static_cast<int>(outParcel.GetDataSize());
        if (offset + dataSize > ashmemSize) {
            WIFI_LOGW("%{public}s parcelLen over ssid: %{public}s, ashmemSize:%{public}d,"
                "dataSize:%{public}d, offset:%{public}d", __FUNCTION__, SsidAnonymize(result[i].ssid).c_str(),
                ashmemSize, dataSize, offset);
            continue;
        }
        allSize.emplace_back(dataSize);
        ashmem->WriteToAshmem(reinterpret_cast<void*>(outParcel.GetData()), dataSize, offset);
        offset += dataSize;
    }
    reply.WriteInt32(WIFI_OPT_SUCCESS);
    reply.WriteUInt32Vector(allSize);
    reply.WriteAshmem(ashmem);
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
}

void WifiDeviceStub::OnGetIpInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    IpInfo info;
    ErrCode ret = GetIpInfo(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(info.ipAddress);
        reply.WriteInt32(info.gateway);
        reply.WriteInt32(info.netmask);
        reply.WriteInt32(info.primaryDns);
        reply.WriteInt32(info.secondDns);
        reply.WriteInt32(info.serverIp);
        reply.WriteInt32(info.leaseDuration);
    }
    return;
}

void WifiDeviceStub::OnGetIpV6Info(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    IpV6Info info;
    ErrCode ret = GetIpv6Info(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteString(info.linkIpV6Address);
        reply.WriteString(info.globalIpV6Address);
        reply.WriteString(info.randGlobalIpV6Address);
        reply.WriteString(info.uniqueLocalAddress1);
        reply.WriteString(info.uniqueLocalAddress2);
        reply.WriteString(info.gateway);
        reply.WriteString(info.netmask);
        reply.WriteString(info.primaryDns);
        reply.WriteString(info.secondDns);
    }
    return;
}

void WifiDeviceStub::OnSetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    std::string countrycode = data.ReadString();
    ret = SetCountryCode(countrycode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}
 
void WifiDeviceStub::OnGetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string countryCode;
    ErrCode ret = GetCountryCode(countryCode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
 
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteString(countryCode);
    }
 
    return;
}

void WifiDeviceStub::OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    do {
        sptr<IRemoteObject> remote = data.ReadRemoteObject();
        if (remote == nullptr) {
            WIFI_LOGW("Failed to ReadRemoteObject!");
            break;
        }
        sptr<IWifiDeviceCallBack> callback_ = iface_cast<IWifiDeviceCallBack>(remote);
        if (callback_ == nullptr) {
            callback_ = new (std::nothrow) WifiDeviceCallBackProxy(remote);
            WIFI_LOGI("create new WifiDeviceCallBackProxy!");
        }

        int pid = data.ReadInt32();
        int tokenId = data.ReadInt32();
        int eventNum = data.ReadInt32();
        std::vector<std::string> event;
        if (eventNum > 0 && eventNum <= MAX_READ_EVENT_SIZE) {
            for (int i = 0; i < eventNum; ++i) {
                event.emplace_back(data.ReadString());
            }
        }
        WIFI_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);

        if (mSingleCallback) {
            ret = RegisterCallBack(callback_, event);
        } else {
            std::unique_lock<std::mutex> lock(deathRecipientMutex);
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new (std::nothrow) WifiDeviceDeathRecipient();
            }
            // Add death recipient to remote object if this is the first time to register callback.
            if (remote->IsProxyObject() &&
                !WifiInternalEventDispatcher::GetInstance().HasStaRemote(remote, m_instId)) {
                remote->AddDeathRecipient(deathRecipient_);
            }
            if (callback_ != nullptr) {
                for (const auto &eventName : event) {
                    ret = WifiInternalEventDispatcher::GetInstance().AddStaCallback(remote, callback_, pid, eventName,
                        tokenId, m_instId);
                }
            }
        }
    } while (0);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnGetSignalLevel(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    int rssi = data.ReadInt32();
    int band = data.ReadInt32();
    int level = 0;
    ErrCode ret = GetSignalLevel(rssi, band, level);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(level);
    }
    return;
}

void WifiDeviceStub::OnGetSupportedFeatures(uint32_t code, MessageParcel &data, MessageParcel &reply)
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

void WifiDeviceStub::OnIsFeatureSupported(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isSupported = false;
    long feature = data.ReadInt64();
    int ret = IsFeatureSupported(feature, isSupported);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(isSupported);
    }

    return;
}

void WifiDeviceStub::OnGetDeviceMacAdd(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string strMacAddr;
    ErrCode ret = GetDeviceMacAddress(strMacAddr);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteCString(strMacAddr.c_str());
    }

    return;
}

void WifiDeviceStub::OnSetLowLatencyMode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    bool enabled = data.ReadBool();
    reply.WriteInt32(0);
    reply.WriteBool(SetLowLatencyMode(enabled));
}

void WifiDeviceStub::OnRemoveCandidateConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    int flag = data.ReadInt32();
    /* Read a flag: 1-remove config by networkId, 2-remove config by WifiDeviceConfig */
    if (flag == 1) {
        int networkId = data.ReadInt32();
        WIFI_LOGI("Remove candidate config by networkId: %{public}d", networkId);
        ret = RemoveCandidateConfig(networkId);
    } else {
        WifiDeviceConfig config;
        ReadWifiDeviceConfig(data, config);
        WIFI_LOGD("Remove candidate config by config: %{public}s", SsidAnonymize(config.ssid).c_str());
        ret = RemoveCandidateConfig(config);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnIsBandTypeSupported(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    int bandType = data.ReadInt32();
    bool result = false;
    ret = IsBandTypeSupported(bandType, result);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    reply.WriteBool(result);
    return;
}

void WifiDeviceStub::OnGet5GHzChannelList(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<int> channelList;
    ErrCode ret = Get5GHzChannelList(channelList);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        unsigned int size = channelList.size();
        reply.WriteInt32(size);
        for (unsigned int i = 0; i < size; ++i) {
            reply.WriteInt32(channelList[i]);
        }
    }
    return;
}

void WifiDeviceStub::OnStartPortalCertification(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = StartPortalCertification();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnGetDisconnectedReason(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    DisconnectedReason reason = DisconnectedReason::DISC_REASON_DEFAULT;
    ErrCode ret = GetDisconnectedReason(reason);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32((int)reason);
    }
    return;
}

void WifiDeviceStub::OnSetFrozenApp(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int size = data.ReadInt32();
    size = size < MAX_PID_LIST_SIZE ? size : MAX_PID_LIST_SIZE;
    std::set<int> pidList;
    for (int i = 0; i < size; i++) {
        pidList.insert(data.ReadInt32());
    }
    bool frozen = data.ReadBool();
    ErrCode ret = SetAppFrozen(pidList, frozen);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnResetAllFrozenApp(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = ResetAllFrozenApp();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnDisableAutoJoin(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = DisableAutoJoin(data.ReadString());
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnEnableAutoJoin(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = EnableAutoJoin(data.ReadString());
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnFactoryReset(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = FactoryReset();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnReceiveNetworkControlInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiNetworkControlInfo networkControlInfo;
    networkControlInfo.uid = data.ReadInt32();
    networkControlInfo.pid = data.ReadInt32();
    networkControlInfo.bundleName = data.ReadString();
    networkControlInfo.state = data.ReadInt32();
    networkControlInfo.sceneId = data.ReadInt32();
    networkControlInfo.rtt = data.ReadInt32();
    ErrCode ret = ReceiveNetworkControlInfo(networkControlInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnLimitSpeed(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int controlId = data.ReadInt32();
    int limitMode = data.ReadInt32();
    ErrCode ret = LimitSpeed(controlId, limitMode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnEnableHiLinkHandshake(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__,  code, data.GetRawDataSize());
    bool uiFlag = data.ReadBool();
    std::string bssid = data.ReadString();
    WifiDeviceConfig deviceConfig;
    ReadWifiDeviceConfig(data, deviceConfig);
    ErrCode ret = EnableHiLinkHandshake(uiFlag, bssid, deviceConfig);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnSetSatelliteState(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    ErrCode ret = SetSatelliteState(state);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnEnableSemiWifi(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = EnableSemiWifi();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnGetWifiDetailState(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDetailState state = WifiDetailState::STATE_UNKNOWN;
    ErrCode ret = GetWifiDetailState(state);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(static_cast<int>(state));
    }

    return;
}

void WifiDeviceStub::OnSetLowTxPower(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiLowPowerParam wifiLowPowerParam;
    wifiLowPowerParam.ifName = data.ReadString();
    wifiLowPowerParam.scene = data.ReadInt32();
    wifiLowPowerParam.rssiThreshold = data.ReadInt32();
    wifiLowPowerParam.peerMacaddr = data.ReadString();
    wifiLowPowerParam.powerParam = data.ReadString();
    wifiLowPowerParam.powerParamLen = data.ReadInt32();
    ErrCode ret = SetLowTxPower(wifiLowPowerParam);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnSetTxPower(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__,  code, data.GetRawDataSize());
    int power = data.ReadInt32();
    ErrCode ret = SetTxPower(power);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnGetDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool networkId = data.ReadInt32();
    WifiDeviceConfig config;
    ErrCode ret = GetDeviceConfig(networkId, config);
    reply.WriteInt32(0);

    if (ret != WIFI_OPT_SUCCESS) {
        reply.WriteInt32(ret);
        return;
    }
    WriteWifiDeviceConfig(reply, config);
    return;
}

void WifiDeviceStub::OnSetDpiMarkRule(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    const char *readStr = data.ReadCString();
    int uid = data.ReadInt32();
    int protocol = data.ReadInt32();
    int enable = data.ReadInt32();
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string ifaceName = readStr;
        ret = SetDpiMarkRule(ifaceName, uid, protocol, enable);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnUpdateNetworkLagInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    NetworkLagType networkLagType = static_cast<NetworkLagType>(data.ReadInt32());
    NetworkLagInfo networkLagInfo;
    networkLagInfo.uid = static_cast<uint32_t>(data.ReadInt32());
    ErrCode ret = UpdateNetworkLagInfo(networkLagType, networkLagInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnFetchWifiSignalInfoForVoWiFi(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    VoWifiSignalInfo signalInfo;
    ErrCode ret = FetchWifiSignalInfoForVoWiFi(signalInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(signalInfo.rssi);
        reply.WriteInt32(signalInfo.noise);
        reply.WriteInt32(signalInfo.bler);
        reply.WriteInt32(signalInfo.deltaTxPacketCounter);
        reply.WriteInt32(signalInfo.accessType);
        reply.WriteInt32(signalInfo.reverse);
        reply.WriteInt64(signalInfo.txGood);
        reply.WriteInt64(signalInfo.txBad);
        reply.WriteString(signalInfo.macAddress);
    }
    return;
}
 
void WifiDeviceStub::OnIsSupportVoWifiDetect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isSupported;
    ErrCode ret = IsSupportVoWifiDetect(isSupported);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(isSupported);
    }
    return;
}
 
void WifiDeviceStub::OnSetVoWifiDetectMode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDetectConfInfo info;
    info.wifiDetectMode = data.ReadInt32();
    info.threshold = data.ReadInt32();
    info.envalueCount = data.ReadInt32();
    ErrCode ret = SetVoWifiDetectMode(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}
 
void WifiDeviceStub::OnGetVoWifiDetectMode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDetectConfInfo info;
    ErrCode ret = GetVoWifiDetectMode(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(info.wifiDetectMode);
        reply.WriteInt32(info.threshold);
        reply.WriteInt32(info.envalueCount);
    }
    return;
}
 
void WifiDeviceStub::OnSetVoWifiDetectPeriod(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int period = data.ReadInt32();
    ErrCode ret = SetVoWifiDetectPeriod(period);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}
 
void WifiDeviceStub::OnGetVoWifiDetectPeriod(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int period;
    ErrCode ret = GetVoWifiDetectPeriod(period);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(period);
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS
