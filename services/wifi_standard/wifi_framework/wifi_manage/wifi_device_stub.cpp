/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_event_broadcast.h"
#include "wifi_device_death_recipient.h"

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
    handleFuncMap[WIFI_SVR_CMD_ADD_DEVICE_CONFIG] = &WifiDeviceStub::OnAddDeviceConfig;
    handleFuncMap[WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveDeviceConfig;
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
    handleFuncMap[WIFI_SVR_CMD_GET_DHCP_INFO] = &WifiDeviceStub::OnGetDhcpInfo;
    handleFuncMap[WIFI_SVR_CMD_SET_COUNTRY_CODE] = &WifiDeviceStub::OnSetCountryCode;
    handleFuncMap[WIFI_SVR_CMD_GET_COUNTRY_CODE] = &WifiDeviceStub::OnGetCountryCode;
    handleFuncMap[WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT] = &WifiDeviceStub::OnRegisterCallBackClient;
    handleFuncMap[WIFI_SVR_CMD_GET_SIGNAL_LEVEL] = &WifiDeviceStub::OnGetSignalLevel;
    return;
}

int WifiDeviceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int exception = data.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }

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
    int ret = EnableWifi();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisableWifi(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = DisableWifi();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiDeviceStub::OnAddDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(data, config);

    int result = 0;
    int ret = AddDeviceConfig(config, result);

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
    config.bssid = data.ReadCString();
    config.ssid = data.ReadCString();
    config.band = data.ReadInt32();
    config.channel = data.ReadInt32();
    config.frequency = data.ReadInt32();
    config.level = data.ReadInt32();
    config.isPasspoint = data.ReadBool();
    config.isEphemeral = data.ReadBool();
    config.preSharedKey = data.ReadCString();
    config.keyMgmt = data.ReadCString();
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = data.ReadCString();
    }
    config.wepTxKeyIndex = data.ReadInt32();
    config.priority = data.ReadInt32();
    config.hiddenSSID = data.ReadBool();
    config.isEnableWPAICertified = data.ReadBool();
    config.allowedKeyManagement = data.ReadInt32();
    config.allowedProtocols = data.ReadInt32();
    config.allowedAuthAlgorithms = data.ReadInt32();
    config.allowedPairwiseCiphers = data.ReadInt32();
    config.allowedGroupCiphers = data.ReadInt32();
    config.wifiIpConfig.assignMethod = AssignIpMethod(data.ReadInt32());
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = data.ReadInt32();
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.gateway);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer1);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer2);
    config.wifiIpConfig.staticIpAddress.domains = data.ReadCString();
    config.wifiEapConfig.eap = data.ReadCString();
    config.wifiEapConfig.identity = data.ReadCString();
    config.wifiEapConfig.password = data.ReadCString();
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(data.ReadInt32());
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = data.ReadCString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = data.ReadCString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = data.ReadInt32();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = data.ReadCString();
    config.wifiPrivacySetting = WifiPrivacyConfig(data.ReadInt32());
    return;
}

void WifiDeviceStub::ReadIpAddress(MessageParcel &data, WifiIpAddress &address)
{
    address.family = data.ReadInt32();
    address.addressIpv4 = data.ReadInt32();
    int size = data.ReadInt32();
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(data.ReadInt8());
    }

    return;
}

void WifiDeviceStub::WriteWifiDeviceConfig(MessageParcel &reply, const WifiDeviceConfig &config)
{
    reply.WriteInt32(config.networkId);
    reply.WriteInt32(config.status);
    reply.WriteCString(config.bssid.c_str());
    reply.WriteCString(config.ssid.c_str());
    reply.WriteInt32(config.band);
    reply.WriteInt32(config.channel);
    reply.WriteInt32(config.frequency);
    reply.WriteInt32(config.level);
    reply.WriteBool(config.isPasspoint);
    reply.WriteBool(config.isEphemeral);
    reply.WriteCString(config.preSharedKey.c_str());
    reply.WriteCString(config.keyMgmt.c_str());
    for (int j = 0; j < WEPKEYS_SIZE; j++) {
        reply.WriteCString(config.wepKeys[j].c_str());
    }
    reply.WriteInt32(config.wepTxKeyIndex);
    reply.WriteInt32(config.priority);
    reply.WriteBool(config.hiddenSSID);
    reply.WriteBool(config.isEnableWPAICertified);
    reply.WriteInt32(config.allowedKeyManagement);
    reply.WriteInt32(config.allowedProtocols);
    reply.WriteInt32(config.allowedAuthAlgorithms);
    reply.WriteInt32(config.allowedPairwiseCiphers);
    reply.WriteInt32(config.allowedGroupCiphers);
    reply.WriteInt32((int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    reply.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
    reply.WriteCString(config.wifiIpConfig.staticIpAddress.domains.c_str());
    reply.WriteCString(config.wifiEapConfig.eap.c_str());
    reply.WriteCString(config.wifiEapConfig.identity.c_str());
    reply.WriteCString(config.wifiEapConfig.password.c_str());
    reply.WriteInt32((int)config.wifiProxyconfig.configureMethod);
    reply.WriteCString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str());
    reply.WriteCString(config.wifiProxyconfig.manualProxyConfig.serverHostName.c_str());
    reply.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    reply.WriteCString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str());
    reply.WriteInt32((int)config.wifiPrivacySetting);
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

void WifiDeviceStub::OnRemoveDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    int ret = RemoveDeviceConfig(networkId);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnGetDeviceConfigs(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<WifiDeviceConfig> result;
    int ret = GetDeviceConfigs(result);
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
    int ret = EnableDeviceConfig(networkId, attemptEnable);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisableDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    int ret = DisableDeviceConfig(networkId);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnConnectTo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int networkId = data.ReadInt32();
    int ret = ConnectTo(networkId);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnConnect2To(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(data, config);
    int ret = ConnectTo(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnReConnect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = ReConnect();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnReAssociate(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = ReAssociate();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnDisconnect(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = Disconnect();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnStartWps(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WpsConfig config;
    config.setup = SetupMethod(data.ReadInt32());
    config.pin = data.ReadCString();
    config.bssid = data.ReadCString();

    int ret = StartWps(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnCancelWps(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = CancelWps();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnIsWifiActive(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool bActive = false;
    int ret = IsWifiActive(bActive);
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
    int ret = GetWifiState(state);
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
    int ret = GetLinkedInfo(wifiInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(wifiInfo.networkId);
        reply.WriteCString(wifiInfo.ssid.c_str());
        reply.WriteCString(wifiInfo.bssid.c_str());
        reply.WriteInt32(wifiInfo.rssi);
        reply.WriteInt32(wifiInfo.band);
        reply.WriteInt32(wifiInfo.frequency);
        reply.WriteInt32(wifiInfo.linkSpeed);
        reply.WriteCString(wifiInfo.macAddress.c_str());
        reply.WriteInt32(wifiInfo.ipAddress);
        reply.WriteInt32((int)wifiInfo.connState);
        reply.WriteBool(wifiInfo.ifHiddenSSID);
        reply.WriteCString(wifiInfo.rxLinkSpeed.c_str());
        reply.WriteCString(wifiInfo.txLinkSpeed.c_str());
        reply.WriteInt32(wifiInfo.chload);
        reply.WriteInt32(wifiInfo.snr);
        reply.WriteInt32((int)wifiInfo.supplicantState);
        reply.WriteInt32((int)wifiInfo.detailedState);
    }

    return;
}

void WifiDeviceStub::OnGetDhcpInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    DhcpInfo info;
    int ret = GetDhcpInfo(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(info.ipAddress);
        reply.WriteInt32(info.netGate);
        reply.WriteInt32(info.netMask);
        reply.WriteInt32(info.dns1);
        reply.WriteInt32(info.dns2);
        reply.WriteInt32(info.serverAddress);
        reply.WriteInt32(info.leaseDuration);
    }

    return;
}

void WifiDeviceStub::OnSetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string countrycode = data.ReadCString();
    int ret = SetCountryCode(countrycode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiDeviceStub::OnGetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string countryCode;
    int ret = GetCountryCode(countryCode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteCString(countryCode.c_str());
    }

    return;
}

void WifiDeviceStub::OnRegisterCallBackClient(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %zu", __func__, code, data.GetRawDataSize());
    int ret = WIFI_OPT_FAILED;
    do {
        std::string name = data.ReadCString();
        sptr<IRemoteObject> remote = data.ReadRemoteObject();
        if (remote == nullptr) {
            WIFI_LOGD("Failed to ReadRemoteObject!");
            break;
        }
        callback_ = iface_cast<IWifiDeviceCallBack>(remote);
        if (callback_ == nullptr) {
            callback_ = new WifiDeviceCallBackProxy(remote);
            WIFI_LOGD("create new WifiDeviceCallBackProxy!");
        }

        if (mSingleCallback) {
            ret = RegisterCallBackClient(name, callback_);
        } else {
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new WifiDeviceDeathRecipient();
            }
            if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
                WIFI_LOGD("AddDeathRecipient!");
            }
            if (callback_ != nullptr) {
                WifiEventBroadcast::GetInstance().AddStaCallback(remote, callback_);
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
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int rssi = data.ReadInt32();
    int band = data.ReadInt32();
    int level = 0;
    int ret = GetSignalLevel(rssi, band, level);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(level);
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS