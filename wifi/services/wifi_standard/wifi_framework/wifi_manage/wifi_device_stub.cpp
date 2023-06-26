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

DEFINE_WIFILOG_LABEL("WifiDeviceStub");

namespace OHOS {
namespace Wifi {
WifiDeviceStub::WifiDeviceStub() : mSingleCallback(false)
{
    InitHandleMap();
}

WifiDeviceStub::~WifiDeviceStub()
{}

void WifiDeviceStub::InitHandleMap()
{
    handleFuncMap[WIFI_SVR_CMD_ENABLE_WIFI] = &WifiDeviceStub::OnEnableWifi;
    handleFuncMap[WIFI_SVR_CMD_DISABLE_WIFI] = &WifiDeviceStub::OnDisableWifi;
    handleFuncMap[WIFI_SVR_CMD_INIT_WIFI_PROTECT] = &WifiDeviceStub::OnInitWifiProtect;
    handleFuncMap[WIFI_SVR_CMD_GET_WIFI_PROTECT] = &WifiDeviceStub::OnGetWifiProtectRef;
    handleFuncMap[WIFI_SVR_CMD_PUT_WIFI_PROTECT] = &WifiDeviceStub::OnPutWifiProtectRef;
    handleFuncMap[WIFI_SVR_CMD_ADD_DEVICE_CONFIG] = &WifiDeviceStub::OnAddDeviceConfig;
    handleFuncMap[WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG] = &WifiDeviceStub::OnUpdateDeviceConfig;
    handleFuncMap[WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveDevice;
    handleFuncMap[WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveAllDevice;
    handleFuncMap[WIFI_SVR_CMD_GET_DEVICE_CONFIGS] = &WifiDeviceStub::OnGetDeviceConfigs;
    handleFuncMap[WIFI_SVR_CMD_ENABLE_DEVICE] = &WifiDeviceStub::OnEnableDeviceConfig;
    handleFuncMap[WIFI_SVR_CMD_DISABLE_DEVICE] = &WifiDeviceStub::OnDisableDeviceConfig;
    handleFuncMap[WIFI_SVR_CMD_CONNECT_TO] = &WifiDeviceStub::OnConnectTo;
    handleFuncMap[WIFI_SVR_CMD_CONNECT2_TO] = &WifiDeviceStub::OnConnect2To;
    handleFuncMap[WIFI_SVR_CMD_RECONNECT] = &WifiDeviceStub::OnReConnect;
    handleFuncMap[WIFI_SVR_CMD_REASSOCIATE] = &WifiDeviceStub::OnReAssociate;
    handleFuncMap[WIFI_SVR_CMD_DISCONNECT] = &WifiDeviceStub::OnDisconnect;
    handleFuncMap[WIFI_SVR_CMD_START_WPS] = &WifiDeviceStub::OnStartWps;
    handleFuncMap[WIFI_SVR_CMD_CANCEL_WPS] = &WifiDeviceStub::OnCancelWps;
    handleFuncMap[WIFI_SVR_CMD_IS_WIFI_ACTIVE] = &WifiDeviceStub::OnIsWifiActive;
    handleFuncMap[WIFI_SVR_CMD_GET_WIFI_STATE] = &WifiDeviceStub::OnGetWifiState;
    handleFuncMap[WIFI_SVR_CMD_GET_LINKED_INFO] = &WifiDeviceStub::OnGetLinkedInfo;
    handleFuncMap[WIFI_SVR_CMD_GET_DHCP_INFO] = &WifiDeviceStub::OnGetIpInfo;
    handleFuncMap[WIFI_SVR_CMD_SET_COUNTRY_CODE] = &WifiDeviceStub::OnSetCountryCode;
    handleFuncMap[WIFI_SVR_CMD_GET_COUNTRY_CODE] = &WifiDeviceStub::OnGetCountryCode;
    handleFuncMap[WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT] = &WifiDeviceStub::OnRegisterCallBack;
    handleFuncMap[WIFI_SVR_CMD_GET_SIGNAL_LEVEL] = &WifiDeviceStub::OnGetSignalLevel;
    handleFuncMap[WIFI_SVR_CMD_GET_SUPPORTED_FEATURES] = &WifiDeviceStub::OnGetSupportedFeatures;
    handleFuncMap[WIFI_SVR_CMD_GET_DERVICE_MAC_ADD] = &WifiDeviceStub::OnGetDeviceMacAdd;
    handleFuncMap[WIFI_SVR_CMD_IS_WIFI_CONNECTED] = &WifiDeviceStub::OnIsWifiConnected;
    handleFuncMap[WIFI_SVR_CMD_SET_LOW_LATENCY_MODE] = &WifiDeviceStub::OnSetLowLatencyMode;
    handleFuncMap[WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG] = &WifiDeviceStub::OnRemoveCandidateConfig;
    return;
}

int WifiDeviceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Sta stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    int exception = data.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }

    WIFI_LOGD("%{public}s, code: %{public}u, uid: %{public}d, pid: %{public}d",
        __func__, code, GetCallingUid(), GetCallingPid());
    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        WIFI_LOGI("not find function to deal, code %{public}u", code);
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_NOT_SUPPORTED);
    } else {
        (this->*(iter->second))(code, data, reply);
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

void WifiDeviceStub::ReadWifiDeviceConfig(MessageParcel &data, WifiDeviceConfig &config)
{
    config.networkId = data.ReadInt32();
    config.status = data.ReadInt32();
    config.bssid = data.ReadString();
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
    config.wifiEapConfig.eap = data.ReadString();
    config.wifiEapConfig.identity = data.ReadString();
    config.wifiEapConfig.password = data.ReadString();
    config.wifiEapConfig.clientCert = data.ReadString();
    config.wifiEapConfig.privateKey = data.ReadString();
    data.ReadUInt8Vector(&config.wifiEapConfig.certEntry);
    config.wifiEapConfig.certPassword = data.ReadString();
    config.wifiEapConfig.phase2Method = Phase2Method(data.ReadInt32());
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(data.ReadInt32());
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = data.ReadInt32();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = data.ReadString();
    config.wifiPrivacySetting = WifiPrivacyConfig(data.ReadInt32());
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

void WifiDeviceStub::WriteWifiDeviceConfig(MessageParcel &reply, const WifiDeviceConfig &config)
{
    reply.WriteInt32(config.networkId);
    reply.WriteInt32(config.status);
    reply.WriteString(config.bssid);
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
    reply.WriteString(config.wifiEapConfig.eap);
    reply.WriteString(config.wifiEapConfig.identity);
    reply.WriteString(config.wifiEapConfig.password);
    reply.WriteString(config.wifiEapConfig.clientCert);
    reply.WriteString(config.wifiEapConfig.privateKey);
    reply.WriteInt32(static_cast<int>(config.wifiEapConfig.phase2Method));
    reply.WriteInt32((int)config.wifiProxyconfig.configureMethod);
    reply.WriteString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress);
    reply.WriteString(config.wifiProxyconfig.manualProxyConfig.serverHostName);
    reply.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    reply.WriteString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
    reply.WriteInt32((int)config.wifiPrivacySetting);
    reply.WriteInt32(config.uid);
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
        WIFI_LOGD("%{public}s, get pid: %{public}d", __func__, pid);
        if (mSingleCallback) {
            ret = RegisterCallBack(callback_);
        } else {
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new (std::nothrow) WifiDeviceDeathRecipient();
            }
            if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
                WIFI_LOGD("AddDeathRecipient!");
            }
            if (callback_ != nullptr) {
                WifiInternalEventDispatcher::GetInstance().AddStaCallback(remote, callback_, pid);
            }
            ret = WIFI_OPT_SUCCESS;
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
}  // namespace Wifi
}  // namespace OHOS
