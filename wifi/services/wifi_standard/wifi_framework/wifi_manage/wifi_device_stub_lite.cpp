/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "wifi_device_stub_lite.h"
#include "define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "wifi_device_callback_proxy.h"
#include "wifi_errcode.h"
#include "wifi_logger.h"
#include "wifi_msg.h"

DEFINE_WIFILOG_LABEL("WifiDeviceStubLite");

namespace OHOS {
namespace Wifi {
WifiDeviceStub::WifiDeviceStub()
{
    InitHandleMap();
}

WifiDeviceStub::~WifiDeviceStub()
{}

void WifiDeviceStub::ReadIpAddress(IpcIo *req, WifiIpAddress &address)
{
    constexpr int MAX_LIMIT_SIZE = 1024;
    (void)ReadInt32(req, &address.family);
    (void)ReadUint32(req, &address.addressIpv4);
    int size = 0;
    (void)ReadInt32(req, &size);
    if (size > MAX_LIMIT_SIZE) {
        WIFI_LOGE("Read ip address parameter error: %{public}d", size);
        return;
    }
    int8_t tmpInt8;
    for (int i = 0; i < size; i++) {
        (void)ReadInt8(req, &tmpInt8);
        address.addressIpv6.push_back(tmpInt8);
    }
}

void WifiDeviceStub::ReadWifiDeviceConfig(IpcIo *req, WifiDeviceConfig &config)
{
    int tmpInt;
    size_t size;
    (void)ReadInt32(req, &config.networkId);
    (void)ReadInt32(req, &config.status);
    config.bssid = (char *)ReadString(req, &size);
    config.ssid = (char *)ReadString(req, &size);
    (void)ReadInt32(req, &config.band);
    (void)ReadInt32(req, &config.channel);
    (void)ReadInt32(req, &config.frequency);
    (void)ReadInt32(req, &config.level);
    (void)ReadBool(req, &config.isPasspoint);
    (void)ReadBool(req, &config.isEphemeral);
    config.preSharedKey = (char *)ReadString(req, &size);
    config.keyMgmt = (char *)ReadString(req, &size);
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = (char *)ReadString(req, &size);
    }
    (void)ReadInt32(req, &config.wepTxKeyIndex);
    (void)ReadInt32(req, &config.priority);
    (void)ReadBool(req, &config.hiddenSSID);
    (void)ReadInt32(req, &tmpInt);
    config.wifiIpConfig.assignMethod = AssignIpMethod(tmpInt);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    (void)ReadInt32(req, &config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    (void)ReadInt32(req, &config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    (void)ReadInt32(req, &config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.gateway);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer1);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer2);
    config.wifiIpConfig.staticIpAddress.domains = (char *)ReadString(req, &size);
    config.wifiEapConfig.eap = (char *)ReadString(req, &size);
    config.wifiEapConfig.identity = (char *)ReadString(req, &size);
    config.wifiEapConfig.password = (char *)ReadString(req, &size);
    (void)ReadInt32(req, &tmpInt);
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(tmpInt);
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = (char *)ReadString(req, &size);
    config.wifiProxyconfig.manualProxyConfig.serverHostName = (char *)ReadString(req, &size);
    (void)ReadInt32(req, &config.wifiProxyconfig.manualProxyConfig.serverPort);
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = (char *)ReadString(req, &size);
    (void)ReadInt32(req, &tmpInt);
    config.wifiPrivacySetting = WifiPrivacyConfig(tmpInt);
}

void WifiDeviceStub::WriteIpAddress(IpcIo *reply, const WifiIpAddress &address)
{
    (void)WriteInt32(reply, address.family);
    (void)WriteUint32(reply, address.addressIpv4);
    int size = address.addressIpv6.size();
    (void)WriteInt32(reply, size);
    for (int i = 0; i < size; i++) {
        (void)WriteInt8(reply, address.addressIpv6[i]);
    }
}

void WifiDeviceStub::WriteWifiDeviceConfig(IpcIo *reply, const WifiDeviceConfig &config)
{
    (void)WriteInt32(reply, config.networkId);
    (void)WriteInt32(reply, config.status);
    (void)WriteString(reply, config.bssid.c_str());
    (void)WriteString(reply, config.ssid.c_str());
    (void)WriteInt32(reply, config.band);
    (void)WriteInt32(reply, config.channel);
    (void)WriteInt32(reply, config.frequency);
    (void)WriteInt32(reply, config.level);
    (void)WriteBool(reply, config.isPasspoint);
    (void)WriteBool(reply, config.isEphemeral);
    (void)WriteString(reply, config.preSharedKey.c_str());
    (void)WriteString(reply, config.keyMgmt.c_str());
    for (int j = 0; j < WEPKEYS_SIZE; j++) {
        (void)WriteString(reply, config.wepKeys[j].c_str());
    }
    (void)WriteInt32(reply, config.wepTxKeyIndex);
    (void)WriteInt32(reply, config.priority);
    (void)WriteBool(reply, config.hiddenSSID);
    (void)WriteInt32(reply, (int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    (void)WriteInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    (void)WriteInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    (void)WriteInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
    (void)WriteString(reply, config.wifiIpConfig.staticIpAddress.domains.c_str());
    (void)WriteString(reply, config.wifiEapConfig.eap.c_str());
    (void)WriteString(reply, config.wifiEapConfig.identity.c_str());
    (void)WriteString(reply, config.wifiEapConfig.password.c_str());
    (void)WriteInt32(reply, (int)config.wifiProxyconfig.configureMethod);
    (void)WriteString(reply, config.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str());
    (void)WriteString(reply, config.wifiProxyconfig.manualProxyConfig.serverHostName.c_str());
    (void)WriteInt32(reply, config.wifiProxyconfig.manualProxyConfig.serverPort);
    (void)WriteString(reply, config.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str());
    (void)WriteInt32(reply, (int)config.wifiPrivacySetting);
}

void WifiDeviceStub::OnEnableWifi(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = EnableWifi();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnDisableWifi(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DisableWifi();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnInitWifiProtect(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    int type = 0;
    (void)ReadInt32(req, &type);
    WifiProtectType protectType = (WifiProtectType)type;
    std::string protectName = (char *)ReadString(req, &size);
    ErrCode ret = InitWifiProtect(protectType, protectName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnGetWifiProtectRef(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    int mode = 0;
    (void)ReadInt32(req, &mode);
    WifiProtectMode protectMode = (WifiProtectMode)mode;
    std::string protectName = (char *)ReadString(req, &size);
    ErrCode ret = GetWifiProtectRef(protectMode, protectName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnPutWifiProtectRef(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    std::string protectName = (char *)ReadString(req, &size);
    ErrCode ret = PutWifiProtectRef(protectName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnAddDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    bool isCandidate = false;
    WifiDeviceConfig config;
    (void)ReadBool(req, &isCandidate);
    ReadWifiDeviceConfig(req, config);

    int result = INVALID_NETWORK_ID;
    ErrCode ret = AddDeviceConfig(config, result, isCandidate);

    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteInt32(reply, result);
    }
}

void WifiDeviceStub::OnUpdateDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(req, config);
    int result = INVALID_NETWORK_ID;
    ErrCode ret = UpdateDeviceConfig(config, result);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteInt32(reply, result);
    }
}

void WifiDeviceStub::OnRemoveDevice(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = 0;
    (void)ReadInt32(req, &networkId);
    ErrCode ret = RemoveDevice(networkId);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnRemoveAllDevice(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = RemoveAllDevice();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnGetDeviceConfigs(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    bool isCandidate = false;
    std::vector<WifiDeviceConfig> result;
    (void)ReadBool(req, &isCandidate);
    ErrCode ret = GetDeviceConfigs(result, isCandidate);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        unsigned int size = result.size();
        (void)WriteInt32(reply, size);
        for (unsigned int i = 0; i < size; ++i) {
            WriteWifiDeviceConfig(reply, result[i]);
        }
    }
}

void WifiDeviceStub::OnEnableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = 0;
    (void)ReadInt32(req, &networkId);
    bool attemptEnable;
    (void)ReadBool(req, &attemptEnable);
    ErrCode ret = EnableDeviceConfig(networkId, attemptEnable);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnDisableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = 0;
    (void)ReadInt32(req, &networkId);
    ErrCode ret = DisableDeviceConfig(networkId);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnConnectTo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = 0;
    bool isCandidate = false;
    (void)ReadBool(req, &isCandidate);
    (void)ReadInt32(req, &networkId);
    ErrCode ret = ConnectToNetwork(networkId, isCandidate);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnConnect2To(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(req, config);
    ErrCode ret = ConnectToDevice(config);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnIsWifiConnected(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    bool isConnected = false;
    ErrCode ret = IsConnected(isConnected);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteBool(reply, isConnected);
    }
}

void WifiDeviceStub::OnReConnect(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = ReConnect();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnReAssociate(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = ReAssociate();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnDisconnect(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = Disconnect();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnStartWps(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    WpsConfig config;
    int setup;
    (void)ReadInt32(req, &setup);
    config.setup = SetupMethod(setup);
    config.pin = (char *)ReadString(req, &size);
    config.bssid = (char *)ReadString(req, &size);

    ErrCode ret = StartWps(config);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnCancelWps(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = CancelWps();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnIsWifiActive(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    bool bActive = false;
    ErrCode ret = IsWifiActive(bActive);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteBool(reply, bActive);
    }
}

void WifiDeviceStub::OnGetWifiState(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int state = 0;
    ErrCode ret = GetWifiState(state);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteInt32(reply, state);
    }
}

void WifiDeviceStub::OnGetLinkedInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiLinkedInfo wifiInfo;
    ErrCode ret = GetLinkedInfo(wifiInfo);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteInt32(reply, wifiInfo.networkId);
        (void)WriteString(reply, wifiInfo.ssid.c_str());
        (void)WriteString(reply, wifiInfo.bssid.c_str());
        (void)WriteInt32(reply, wifiInfo.rssi);
        (void)WriteInt32(reply, wifiInfo.band);
        (void)WriteInt32(reply, wifiInfo.frequency);
        (void)WriteInt32(reply, wifiInfo.linkSpeed);
        (void)WriteString(reply, wifiInfo.macAddress.c_str());
        (void)WriteUint32(reply, wifiInfo.ipAddress);
        (void)WriteInt32(reply, (int)wifiInfo.connState);
        (void)WriteBool(reply, wifiInfo.ifHiddenSSID);
        (void)WriteInt32(reply, wifiInfo.rxLinkSpeed);
        (void)WriteInt32(reply, wifiInfo.txLinkSpeed);
        (void)WriteInt32(reply, wifiInfo.chload);
        (void)WriteInt32(reply, wifiInfo.snr);
        (void)WriteInt32(reply, wifiInfo.isDataRestricted);
        (void)WriteString(reply, wifiInfo.portalUrl.c_str());
        (void)WriteInt32(reply, (int)wifiInfo.supplicantState);
        (void)WriteInt32(reply, (int)wifiInfo.detailedState);
    }
}

void WifiDeviceStub::OnGetIpInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    IpInfo info;
    ErrCode ret = GetIpInfo(info);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteUint32(reply, info.ipAddress);
        (void)WriteUint32(reply, info.gateway);
        (void)WriteUint32(reply, info.netmask);
        (void)WriteUint32(reply, info.primaryDns);
        (void)WriteUint32(reply, info.secondDns);
        (void)WriteUint32(reply, info.serverIp);
        (void)WriteUint32(reply, info.leaseDuration);
    }
}

void WifiDeviceStub::OnSetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    std::string countrycode = (char *)ReadString(req, &size);
    ErrCode ret = SetCountryCode(countrycode);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnGetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    std::string countryCode;
    ErrCode ret = GetCountryCode(countryCode);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteString(reply, countryCode.c_str());
    }
}

void WifiDeviceStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = WIFI_OPT_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        WIFI_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return;
    }

    std::shared_ptr<IWifiDeviceCallBack> callback_ = std::make_shared<WifiDeviceCallBackProxy>(&sid);
    WIFI_LOGD("create new WifiDeviceCallbackProxy!");
    ret = RegisterCallBack(callback_);

    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
}

void WifiDeviceStub::OnGetSignalLevel(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int rssi = 0;
    int band = 0;
    int level = 0;
    (void)ReadInt32(req, &rssi);
    (void)ReadInt32(req, &band);
    ErrCode ret = GetSignalLevel(rssi, band, level);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteInt32(reply, level);
    }
}

void WifiDeviceStub::OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    long features = 0;
    int ret = GetSupportedFeatures(features);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteUint64(reply, features);
    }
}

void WifiDeviceStub::OnGetDeviceMacAdd(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    std::string strMacAddr;
    ErrCode ret = GetDeviceMacAddress(strMacAddr);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteString(reply, strMacAddr.c_str());
    }
}

void WifiDeviceStub::OnSetLowLatencyMode(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);

    bool enabled;
    (void)ReadBool(req, &enabled);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, WIFI_OPT_SUCCESS);
    (void)WriteBool(reply, SetLowLatencyMode(enabled));
}

void WifiDeviceStub::InitHandleMap()
{
    handleFuncMap_[WIFI_SVR_CMD_ENABLE_WIFI] = &WifiDeviceStub::OnEnableWifi;
    handleFuncMap_[WIFI_SVR_CMD_DISABLE_WIFI] = &WifiDeviceStub::OnDisableWifi;
    handleFuncMap_[WIFI_SVR_CMD_INIT_WIFI_PROTECT] = &WifiDeviceStub::OnInitWifiProtect;
    handleFuncMap_[WIFI_SVR_CMD_GET_WIFI_PROTECT] = &WifiDeviceStub::OnGetWifiProtectRef;
    handleFuncMap_[WIFI_SVR_CMD_PUT_WIFI_PROTECT] = &WifiDeviceStub::OnPutWifiProtectRef;
    handleFuncMap_[WIFI_SVR_CMD_ADD_DEVICE_CONFIG] = &WifiDeviceStub::OnAddDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG] = &WifiDeviceStub::OnUpdateDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveDevice;
    handleFuncMap_[WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveAllDevice;
    handleFuncMap_[WIFI_SVR_CMD_GET_DEVICE_CONFIGS] = &WifiDeviceStub::OnGetDeviceConfigs;
    handleFuncMap_[WIFI_SVR_CMD_ENABLE_DEVICE] = &WifiDeviceStub::OnEnableDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_DISABLE_DEVICE] = &WifiDeviceStub::OnDisableDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_CONNECT_TO] = &WifiDeviceStub::OnConnectTo;
    handleFuncMap_[WIFI_SVR_CMD_CONNECT2_TO] = &WifiDeviceStub::OnConnect2To;
    handleFuncMap_[WIFI_SVR_CMD_RECONNECT] = &WifiDeviceStub::OnReConnect;
    handleFuncMap_[WIFI_SVR_CMD_REASSOCIATE] = &WifiDeviceStub::OnReAssociate;
    handleFuncMap_[WIFI_SVR_CMD_DISCONNECT] = &WifiDeviceStub::OnDisconnect;
    handleFuncMap_[WIFI_SVR_CMD_START_WPS] = &WifiDeviceStub::OnStartWps;
    handleFuncMap_[WIFI_SVR_CMD_CANCEL_WPS] = &WifiDeviceStub::OnCancelWps;
    handleFuncMap_[WIFI_SVR_CMD_IS_WIFI_ACTIVE] = &WifiDeviceStub::OnIsWifiActive;
    handleFuncMap_[WIFI_SVR_CMD_GET_WIFI_STATE] = &WifiDeviceStub::OnGetWifiState;
    handleFuncMap_[WIFI_SVR_CMD_GET_LINKED_INFO] = &WifiDeviceStub::OnGetLinkedInfo;
    handleFuncMap_[WIFI_SVR_CMD_GET_DHCP_INFO] = &WifiDeviceStub::OnGetIpInfo;
    handleFuncMap_[WIFI_SVR_CMD_SET_COUNTRY_CODE] = &WifiDeviceStub::OnSetCountryCode;
    handleFuncMap_[WIFI_SVR_CMD_GET_COUNTRY_CODE] = &WifiDeviceStub::OnGetCountryCode;
    handleFuncMap_[WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT] = &WifiDeviceStub::OnRegisterCallBack;
    handleFuncMap_[WIFI_SVR_CMD_GET_SIGNAL_LEVEL] = &WifiDeviceStub::OnGetSignalLevel;
    handleFuncMap_[WIFI_SVR_CMD_GET_SUPPORTED_FEATURES] = &WifiDeviceStub::OnGetSupportedFeatures;
    handleFuncMap_[WIFI_SVR_CMD_GET_DERVICE_MAC_ADD] = &WifiDeviceStub::OnGetDeviceMacAdd;
    handleFuncMap_[WIFI_SVR_CMD_IS_WIFI_CONNECTED] = &WifiDeviceStub::OnIsWifiConnected;
    handleFuncMap_[WIFI_SVR_CMD_SET_LOW_LATENCY_MODE] = &WifiDeviceStub::OnSetLowLatencyMode;
}

int WifiDeviceStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run: %{public}s code: %{public}u L1", __func__, code);
    if (req == nullptr || reply == nullptr) {
        WIFI_LOGD("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return ERR_FAILED;
    }

    WIFI_LOGD("run ReadInterfaceToken L1 code %{public}u", code);
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(req, &length);
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH || interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            WIFI_LOGE("Sta stub token verification error: %{public}d", code);
            return WIFI_OPT_FAILED;
        }
    }

    int exception = 0;
    (void)ReadInt32(req, &exception);
    if (exception) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, WIFI_OPT_NOT_SUPPORTED);
        return WIFI_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap_.find(code);
    if (iter == handleFuncMap_.end()) {
        WIFI_LOGI("not find function to deal, code %{public}u", code);
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, WIFI_OPT_NOT_SUPPORTED);
    } else {
        (this->*(iter->second))(code, req, reply);
    }

    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
