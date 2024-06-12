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

DEFINE_WIFILOG_LABEL("WifiDeviceStub");

namespace OHOS {
namespace Wifi {
WifiDeviceStub::WifiDeviceStub() : mSingleCallback(false)
{
    WIFI_LOGI("enter WifiDeviceStub!");
    InitHandleMap();
}

WifiDeviceStub::WifiDeviceStub(int instId) : mSingleCallback(false), m_instId(instId)
{
    WIFI_LOGI("enter WifiDeviceStub!");
    InitHandleMap();
}

WifiDeviceStub::~WifiDeviceStub()
{
    WIFI_LOGI("enter ~WifiDeviceStub!");
#ifndef OHOS_ARCH_LITE
    RemoveDeviceCbDeathRecipient();
#endif
}

void WifiDeviceStub::InitHandleMapEx()
{
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL)] =
        &WifiDeviceStub::OnGetSignalLevel;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] =
        &WifiDeviceStub::OnGetSupportedFeatures;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO)] =
        &WifiDeviceStub::OnGetIpV6Info;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD)] =
        &WifiDeviceStub::OnGetDeviceMacAdd;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED)] =
        &WifiDeviceStub::OnIsWifiConnected;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE)] =
        &WifiDeviceStub::OnSetLowLatencyMode;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG)] =
        &WifiDeviceStub::OnRemoveCandidateConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED)] =
        &WifiDeviceStub::OnIsBandTypeSupported;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST)] =
        &WifiDeviceStub::OnGet5GHzChannelList;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON)] =
        &WifiDeviceStub::OnGetDisconnectedReason;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP)] =
        &WifiDeviceStub::OnSetFrozenApp;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP)] =
        &WifiDeviceStub::OnResetAllFrozenApp;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN)] =
        &WifiDeviceStub::OnDisableAutoJoin;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_AUTO_JOIN)] =
        &WifiDeviceStub::OnEnableAutoJoin;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF)] =
        &WifiDeviceStub::OnStartPortalCertification;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE)] =
        &WifiDeviceStub::OnGetChangeDeviceConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET)] =
        &WifiDeviceStub::OnFactoryReset;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED)] =
        &WifiDeviceStub::OnLimitSpeed;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT)] =
        &WifiDeviceStub::OnEnableHiLinkHandshake;
    return;
}

void WifiDeviceStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI)] = &WifiDeviceStub::OnEnableWifi;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI)] = &WifiDeviceStub::OnDisableWifi;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT)] =
        &WifiDeviceStub::OnInitWifiProtect;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT)] =
        &WifiDeviceStub::OnGetWifiProtectRef;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT)] =
        &WifiDeviceStub::OnPutWifiProtectRef;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT)] =
        &WifiDeviceStub::OnIsHeldWifiProtectRef;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG)] =
        &WifiDeviceStub::OnAddDeviceConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG)] =
        &WifiDeviceStub::OnUpdateDeviceConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG)] =
        &WifiDeviceStub::OnRemoveDevice;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG)] =
        &WifiDeviceStub::OnRemoveAllDevice;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS)] =
        &WifiDeviceStub::OnGetDeviceConfigs;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE)] =
        &WifiDeviceStub::OnEnableDeviceConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE)] =
        &WifiDeviceStub::OnDisableDeviceConfig;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO)] = &WifiDeviceStub::OnConnectTo;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO)] = &WifiDeviceStub::OnConnect2To;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT)] = &WifiDeviceStub::OnReConnect;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE)] = &WifiDeviceStub::OnReAssociate;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT)] = &WifiDeviceStub::OnDisconnect;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS)] = &WifiDeviceStub::OnStartWps;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS)] = &WifiDeviceStub::OnCancelWps;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE)] =
        &WifiDeviceStub::OnIsWifiActive;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE)] =
        &WifiDeviceStub::OnGetWifiState;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT)] =
        &WifiDeviceStub::OnIsMeteredHotspot;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO)] =
        &WifiDeviceStub::OnGetLinkedInfo;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO)] = &WifiDeviceStub::OnGetIpInfo;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE)] =
         &WifiDeviceStub::OnSetCountryCode;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE)] =
         &WifiDeviceStub::OnGetCountryCode;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT)] =
        &WifiDeviceStub::OnRegisterCallBack;
    InitHandleMapEx();
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
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_NOT_SUPPORTED);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        int exception = data.ReadInt32();
        if (exception) {
            return WIFI_OPT_FAILED;
        }
        (this->*(iter->second))(code, data, reply);
    }

    return 0;
}

#ifndef OHOS_ARCH_LITE
void WifiDeviceStub::RemoveDeviceCbDeathRecipient(void)
{
    WIFI_LOGI("enter RemoveDeviceCbDeathRecipient, remove all death recipient!");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = remoteDeathMap.begin(); iter != remoteDeathMap.end(); ++iter) {
        iter->first->RemoveDeathRecipient(iter->second);
        remoteDeathMap.erase(iter);
    }
    deathRecipient_ = nullptr;
}

void WifiDeviceStub::RemoveDeviceCbDeathRecipient(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGI("RemoveDeviceCbDeathRecipient, remoteObject.promote: %{public}p!",
        static_cast<void*>(remoteObject.promote()));
    std::lock_guard<std::mutex> lock(mutex_);
    RemoteDeathMap::iterator iter = remoteDeathMap.find(remoteObject.promote());
    if (iter == remoteDeathMap.end()) {
        WIFI_LOGI("not find remoteObject to deal!");
    } else {
        WIFI_LOGD("RemoveDeviceCbDeathRecipient, deathRecipient_: %{public}p, iter->second: %{public}p",
            static_cast<void*>(deathRecipient_), static_cast<void*>(iter->second));
        remoteObject->RemoveDeathRecipient(iter->second);
        remoteDeathMap.erase(iter);
        WIFI_LOGI("remove death recipient success! remoteDeathMap.size: %{public}zu.", remoteDeathMap.size());
    }
}

void WifiDeviceStub::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGI("OnRemoteDied, Remote is died! remoteObject: %{public}p", &remoteObject);
    WifiInternalEventDispatcher::GetInstance().RemoveStaCallback(remoteObject.promote());
    RemoveDeviceCbDeathRecipient(remoteObject);
}
#endif

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
    config.status = data.ReadInt32();
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
    return;
}

void WifiDeviceStub::ReadIpAddress(MessageParcel &data, WifiIpAddress &address)
{
    constexpr int MAX_LIMIT_SIZE = 1024;
    address.family = data.ReadInt32();
    address.addressIpv4 = data.ReadInt32();
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

void WifiDeviceStub::WriteWifiDeviceConfig(MessageParcel &reply, const WifiDeviceConfig &config)
{
    reply.WriteInt32(config.networkId);
    reply.WriteInt32(config.status);
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
    return;
}

void WifiDeviceStub::WriteIpAddress(MessageParcel &reply, const WifiIpAddress &address)
{
    reply.WriteInt32(address.family);
    reply.WriteInt32(address.addressIpv4);
    int size = address.addressIpv6.size();
    reply.WriteInt32(size);
    for (int i = 0; i < size; i++) {
        reply.WriteInt8(address.addressIpv6[i]);
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

void WifiDeviceStub::OnGetDeviceConfigs(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isCandidate = data.ReadBool();
    std::vector<WifiDeviceConfig> result;
    ErrCode ret = GetDeviceConfigs(result, isCandidate);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        unsigned int size = result.size();
        reply.WriteInt32(size);
        for (unsigned int i = 0; i < size; ++i) {
            WriteWifiDeviceConfig(reply, result[i]);
        }
    }
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

void WifiDeviceStub::OnGetLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiLinkedInfo wifiInfo;
    ErrCode ret = GetLinkedInfo(wifiInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
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
        reply.WriteInt32((int)wifiInfo.connState);
        reply.WriteBool(wifiInfo.ifHiddenSSID);
        reply.WriteInt32(wifiInfo.rxLinkSpeed);
        reply.WriteInt32(wifiInfo.txLinkSpeed);
        reply.WriteInt32(wifiInfo.chload);
        reply.WriteInt32(wifiInfo.snr);
        reply.WriteInt32(wifiInfo.isDataRestricted);
        reply.WriteString(wifiInfo.portalUrl);
        reply.WriteInt32((int)wifiInfo.supplicantState);
        reply.WriteInt32((int)wifiInfo.detailedState);
        reply.WriteInt32((int)wifiInfo.wifiStandard);
        reply.WriteInt32((int)wifiInfo.maxSupportedRxLinkSpeed);
        reply.WriteInt32((int)wifiInfo.maxSupportedTxLinkSpeed);
        reply.WriteInt32((int)wifiInfo.channelWidth);
        reply.WriteBool(wifiInfo.isAncoConnected);
        reply.WriteInt32((int)wifiInfo.supportedWifiCategory);
        reply.WriteBool(wifiInfo.isHiLinkNetwork);
    }

    return;
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
        WIFI_LOGI("%{public}s, get pid: %{public}d, tokenId: %{private}d, eventNum: %{public}d",
            __func__, pid, tokenId, eventNum);

        if (mSingleCallback) {
            ret = RegisterCallBack(callback_, event);
        } else {
            if (deathRecipient_ == nullptr) {
#ifdef OHOS_ARCH_LITE
                deathRecipient_ = new (std::nothrow) WifiDeviceDeathRecipient();
#else
                deathRecipient_ = new (std::nothrow) WifiDeathRecipient(*this);
#endif
            }
            RemoteDeathMap::iterator iter = remoteDeathMap.find(remote);
            if (iter == remoteDeathMap.end()) {
                std::lock_guard<std::mutex> lock(mutex_);
                remoteDeathMap.insert(std::make_pair(remote, deathRecipient_));
                WIFI_LOGI("OnRegisterCallBack, AddDeathRecipient, remote:%{public}p, remoteDeathMap.size: %{public}zu",
                    static_cast<void*>(remote), remoteDeathMap.size());
                if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
                    WIFI_LOGI("AddDeathRecipient!");
                }
            }

            for (const auto &eventName : event) {
                ret = WifiInternalEventDispatcher::GetInstance().AddStaCallback(remote, callback_, pid, eventName,
                    tokenId, m_instId);
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
}  // namespace Wifi
}  // namespace OHOS
