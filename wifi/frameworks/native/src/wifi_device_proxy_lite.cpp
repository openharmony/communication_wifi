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

#include "wifi_device_proxy.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "serializer.h"
#include "samgr_lite.h"
#include "wifi_ipc_lite_adapter.h"
#include "wifi_device_callback_stub_lite.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceProxyLite");

namespace OHOS {
namespace Wifi {
static SvcIdentity g_sid;
static IpcObjectStub g_objStub;
static WifiDeviceCallBackStub g_deviceCallBackStub;
static void ReadIpAddress(IpcIo *reply, WifiIpAddress &address)
{
    constexpr int MAX_SIZE = 256;
    (void)ReadInt32(reply, &address.family);
    (void)ReadUint32(reply, &address.addressIpv4);
    int size = 0;
    (void)ReadInt32(reply, &size);
    if (size > MAX_SIZE) {
        WIFI_LOGE("Read IP address size error: %{public}d", size);
        return;
    }
    int tmpAddress = 0;
    for (int i = 0; i < size; i++) {
        (void)ReadInt8(reply, (int8_t *)&tmpAddress);
        address.addressIpv6.push_back(tmpAddress);
    }
    return;
}

static void Parse5GChannels(IpcIo *reply, std::vector<int> &result)
{
    int retSize = 0;
    constexpr int MAX_5G_CHANNELS = 36;
    (void)ReadInt32(reply, &retSize);
    if (retSize > MAX_5G_CHANNELS) {
        WIFI_LOGE("Parse5GChannels fail, size error: %{public}d", retSize);
        return;
    }
    for (int i = 0; i < retSize; ++i) {
        int channel = 0;
        (void)ReadInt32(reply, &channel);
        result.emplace_back(channel);
    }
}

static void ReadEapConfig(IpcIo *reply, WifiEapConfig &wifiEapConfig)
{
    size_t readLen;
    wifiEapConfig.eap = (char *)ReadString(reply, &readLen);
    int phase2Method = 0;
    (void)ReadInt32(reply, &phase2Method);
    wifiEapConfig.phase2Method = Phase2Method(phase2Method);
    wifiEapConfig.identity = (char *)ReadString(reply, &readLen);
    wifiEapConfig.anonymousIdentity = (char *)ReadString(reply, &readLen);
    wifiEapConfig.password = (char *)ReadString(reply, &readLen);
    wifiEapConfig.caCertPath = (char *)ReadString(reply, &readLen);
    wifiEapConfig.caCertAlias = (char *)ReadString(reply, &readLen);
    wifiEapConfig.clientCert = (char *)ReadString(reply, &readLen);
    if (strcpy_s(wifiEapConfig.certPassword, sizeof(wifiEapConfig.certPassword),
        (char *)ReadString(reply, &readLen)) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy", __func__);
    }
    wifiEapConfig.privateKey = (char *)ReadString(reply, &readLen);
    wifiEapConfig.altSubjectMatch = (char *)ReadString(reply, &readLen);
    wifiEapConfig.domainSuffixMatch = (char *)ReadString(reply, &readLen);
    wifiEapConfig.realm = (char *)ReadString(reply, &readLen);
    wifiEapConfig.plmn = (char *)ReadString(reply, &readLen);
    (void)ReadInt32(reply, &wifiEapConfig.eapSubId);
}

static void ParseDeviceConfigs(IpcIo *reply, std::vector<WifiDeviceConfig> &result)
{
    size_t readLen;
    constexpr int MAX_DEVICE_CONFIG_SIZE = 1024;
    int retSize = 0;
    (void)ReadInt32(reply, &retSize);
    if (retSize > MAX_DEVICE_CONFIG_SIZE) {
        WIFI_LOGE("Parse device config size error: %{public}d", retSize);
        return;
    }
    for (int i = 0; i < retSize; ++i) {
        WifiDeviceConfig config;
        (void)ReadInt32(reply, &config.networkId);
        (void)ReadInt32(reply, &config.status);
        config.bssid = (char *)ReadString(reply, &readLen);
        config.ssid = (char *)ReadString(reply, &readLen);
        (void)ReadInt32(reply, &config.band);
        (void)ReadInt32(reply, &config.channel);
        (void)ReadInt32(reply, &config.frequency);
        (void)ReadInt32(reply, &config.level);
        (void)ReadBool(reply, &config.isPasspoint);
        (void)ReadBool(reply, &config.isEphemeral);
        config.preSharedKey = (char *)ReadString(reply, &readLen);
        config.keyMgmt = (char *)ReadString(reply, &readLen);
        for (int j = 0; j < WEPKEYS_SIZE; j++) {
            config.wepKeys[j] = (char *)ReadString(reply, &readLen);
        }
        (void)ReadInt32(reply, &config.wepTxKeyIndex);
        (void)ReadInt32(reply, &config.priority);
        (void)ReadBool(reply, &config.hiddenSSID);
        int ipMethod = 0;
        (void)ReadInt32(reply, &ipMethod);
        config.wifiIpConfig.assignMethod = AssignIpMethod(ipMethod);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
        (void)ReadInt32(reply, &config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
        (void)ReadInt32(reply, &config.wifiIpConfig.staticIpAddress.ipAddress.flags);
        (void)ReadInt32(reply, &config.wifiIpConfig.staticIpAddress.ipAddress.scope);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
        config.wifiIpConfig.staticIpAddress.domains = (char *)ReadString(reply, &readLen);
        ReadEapConfig(reply, config.wifiEapConfig);
        int proxyMethod = 0;
        (void)ReadInt32(reply, &proxyMethod);
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(proxyMethod);
        config.wifiProxyconfig.autoProxyConfig.pacWebAddress = (char *)ReadString(reply, &readLen);
        config.wifiProxyconfig.manualProxyConfig.serverHostName = (char *)ReadString(reply, &readLen);
        (void)ReadInt32(reply, &config.wifiProxyconfig.manualProxyConfig.serverPort);
        config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = (char *)ReadString(reply, &readLen);
        int privacyConfig = 0;
        (void)ReadInt32(reply, &privacyConfig);
        config.wifiPrivacySetting = WifiPrivacyConfig(privacyConfig);
        (void)ReadInt32(reply, &config.uid);

        result.emplace_back(config);
    }
}

static void ReadLinkedInfo(IpcIo *reply, WifiLinkedInfo &info)
{
    size_t readLen;
    (void)ReadInt32(reply, &info.networkId);
    info.ssid = (char *)ReadString(reply, &readLen);
    info.bssid = (char *)ReadString(reply, &readLen);
    (void)ReadInt32(reply, &info.rssi);
    (void)ReadInt32(reply, &info.band);
    (void)ReadInt32(reply, &info.frequency);
    (void)ReadInt32(reply, &info.linkSpeed);
    info.macAddress = (char *)ReadString(reply, &readLen);
    (void)ReadUint32(reply, &info.ipAddress);
    int tmpConnState = 0;
    (void)ReadInt32(reply, &tmpConnState);
    if ((tmpConnState >= 0) && (tmpConnState <= (int)ConnState::UNKNOWN)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::UNKNOWN;
    }
    (void)ReadBool(reply, &info.ifHiddenSSID);
    (void)ReadInt32(reply, &info.rxLinkSpeed);
    (void)ReadInt32(reply, &info.txLinkSpeed);
    (void)ReadInt32(reply, &info.chload);
    (void)ReadInt32(reply, &info.snr);
    (void)ReadInt32(reply, &info.isDataRestricted);
    info.portalUrl = (char *)ReadString(reply, &readLen);

    int tmpState = 0;
    (void)ReadInt32(reply, &tmpState);
    if ((tmpState >= 0) && (tmpState <= (int)SupplicantState::INVALID)) {
        info.supplicantState = (SupplicantState)tmpState;
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = 0;
    (void)ReadInt32(reply, &tmpDetailState);
    if ((tmpDetailState >= 0) && (tmpDetailState <= (int)DetailedState::INVALID)) {
        info.detailedState = (DetailedState)tmpDetailState;
    } else {
        info.detailedState = DetailedState::INVALID;
    }
    (void)ReadInt32(reply, &info.wifiStandard);
    (void)ReadInt32(reply, &info.maxSupportedRxLinkSpeed);
    (void)ReadInt32(reply, &info.maxSupportedTxLinkSpeed);

    int tmpChanWidth = (int)WifiChannelWidth::WIDTH_INVALID;
    (void)ReadInt32(reply, &tmpChanWidth);
    if ((tmpChanWidth >= 0) && (tmpChanWidth <= (int)WifiChannelWidth::WIDTH_INVALID)) {
        info.channelWidth = (WifiChannelWidth)tmpChanWidth;
    } else {
        info.channelWidth = WifiChannelWidth::WIDTH_INVALID;
    }
}

static void ReadDhcpInfo(IpcIo *reply, IpInfo &info)
{
    (void)ReadUint32(reply, &info.ipAddress);
    (void)ReadUint32(reply, &info.gateway);
    (void)ReadUint32(reply, &info.netmask);
    (void)ReadUint32(reply, &info.primaryDns);
    (void)ReadUint32(reply, &info.secondDns);
    (void)ReadUint32(reply, &info.serverIp);
    (void)ReadUint32(reply, &info.leaseDuration);
}

static int IpcCallback(void *owner, int code, IpcIo *reply)
{
    if (code != 0 || owner == nullptr || reply == nullptr) {
        WIFI_LOGE("Callback error, code:%{public}d, owner:%{public}d, reply:%{public}d",
            code, owner == nullptr, reply == nullptr);
        return ERR_FAILED;
    }

    struct IpcOwner *data = (struct IpcOwner *)owner;
    (void)ReadInt32(reply, &data->exception);
    (void)ReadInt32(reply, &data->retCode);
    if (data->exception != 0 || data->retCode != WIFI_OPT_SUCCESS || data->variable == nullptr) {
        return ERR_NONE;
    }

    switch (data->funcId) {
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL): {
            (void)ReadInt32(reply, (int32_t *)data->variable);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE): {
            (void)ReadBool(reply, (bool *)data->variable);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE):
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD): {
            size_t readLen = 0;
            *((std::string *)data->variable) = (char *)ReadString(reply, &readLen);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES): {
            int64_t features = 0;
            ReadInt64(reply, &features);
            *((long *)data->variable) = features;
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS): {
            ParseDeviceConfigs(reply, *((std::vector<WifiDeviceConfig> *)data->variable));
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO): {
            ReadLinkedInfo(reply, *((WifiLinkedInfo *)data->variable));
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO): {
            ReadDhcpInfo(reply, *((IpInfo *)data->variable));
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED): {
            (void)ReadBool(reply, (bool *)data->variable);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST): {
            Parse5GChannels(reply, *((std::vector<int> *)data->variable));
            break;
        }
        default:
            break;
    }

    return ERR_NONE;
}

static int AsyncCallback(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    if (data == nullptr) {
        WIFI_LOGE("AsyncCallback error, data is null");
        return ERR_FAILED;
    }
    return g_deviceCallBackStub.OnRemoteRequest(code, data);
}

static void OnRemoteSrvDied(void *arg)
{
    WIFI_LOGE("%{public}s called.", __func__);
    WifiDeviceProxy *client = WifiDeviceProxy::GetInstance();
    if (client != nullptr) {
        client->OnRemoteDied();
    }
    return;
}

WifiDeviceProxy *WifiDeviceProxy::g_instance = nullptr;
WifiDeviceProxy::WifiDeviceProxy() : remoteDied_(false)
{}

WifiDeviceProxy::~WifiDeviceProxy()
{}

WifiDeviceProxy *WifiDeviceProxy::GetInstance(void)
{
    if (g_instance != nullptr) {
        return g_instance;
    }

    WifiDeviceProxy *tempInstance = new(std::nothrow) WifiDeviceProxy();
    g_instance = tempInstance;
    return g_instance;
}

void WifiDeviceProxy::ReleaseInstance(void)
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

ErrCode WifiDeviceProxy::Init()
{
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(WIFI_SERVICE_LITE, WIFI_FEATURE_DEVICE);
    if (iUnknown == nullptr) {
        WIFI_LOGE("GetFeatureApi failed.");
        return WIFI_OPT_FAILED;
    }
    IClientProxy *proxy = nullptr;
    int result = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, reinterpret_cast<void **>(&proxy));
    if (result != 0) {
        WIFI_LOGE("QueryInterface failed.");
        return WIFI_OPT_FAILED;
    }
    remote_ = proxy;

    // Register SA Death Callback
    uint32_t deadId = 0;
    svcIdentity_ = SAMGR_GetRemoteIdentity(WIFI_SERVICE_LITE, WIFI_FEATURE_DEVICE);
    result = AddDeathRecipient(svcIdentity_, OnRemoteSrvDied, nullptr, &deadId);
    if (result != 0) {
        WIFI_LOGE("Register SA Death Callback failed, errorCode[%d]", result);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::EnableWifi()
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::DisableWifi()
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, (int)protectType);
    (void)WriteString(&req, protectName.c_str());
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), error);
        return ErrCode(error);
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, (int)protectMode);
    (void)WriteString(&req, protectName.c_str());
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), error);
        return ErrCode(error);
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::PutWifiProtectRef(const std::string &protectName)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteString(&req, protectName.c_str());
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), error);
        return ErrCode(error);
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::RemoveCandidateConfig(int networkId)
{
    (void)networkId;
    return WIFI_OPT_NOT_SUPPORTED;
}

ErrCode WifiDeviceProxy::RemoveCandidateConfig(const WifiDeviceConfig &config)
{
    (void)config;
    return WIFI_OPT_NOT_SUPPORTED;
}

void WifiDeviceProxy::WriteIpAddress(IpcIo &req, const WifiIpAddress &address)
{
    (void)WriteInt32(&req, address.family);
    (void)WriteUint32(&req, address.addressIpv4);
    int size = address.addressIpv6.size();
    (void)WriteInt32(&req, size);
    for (int i = 0; i < size; i++) {
        (void)WriteInt8(&req, address.addressIpv6[i]);
    }
    return;
}

void WifiDeviceProxy::WriteEapConfig(IpcIo &req, const WifiEapConfig &wifiEapConfig)
{
    (void)WriteString(&req, wifiEapConfig.eap.c_str());
    (void)WriteInt32(&req, static_cast<int>(wifiEapConfig.phase2Method));
    (void)WriteString(&req, wifiEapConfig.identity.c_str());
    (void)WriteString(&req, wifiEapConfig.anonymousIdentity.c_str());
    (void)WriteString(&req, wifiEapConfig.password.c_str());

    (void)WriteString(&req, wifiEapConfig.caCertPath.c_str());
    (void)WriteString(&req, wifiEapConfig.caCertAlias.c_str());

    (void)WriteString(&req, wifiEapConfig.clientCert.c_str());
    (void)WriteString(&req, std::string(wifiEapConfig.certPassword).c_str());
    (void)WriteString(&req, wifiEapConfig.privateKey.c_str());

    (void)WriteString(&req, wifiEapConfig.altSubjectMatch.c_str());
    (void)WriteString(&req, wifiEapConfig.domainSuffixMatch.c_str());
    (void)WriteString(&req, wifiEapConfig.realm.c_str());
    (void)WriteString(&req, wifiEapConfig.plmn.c_str());
    (void)WriteInt32(&req, wifiEapConfig.eapSubId);
}

void WifiDeviceProxy::WriteDeviceConfig(const WifiDeviceConfig &config, IpcIo &req)
{
    (void)WriteInt32(&req, config.networkId);
    (void)WriteInt32(&req, config.status);
    (void)WriteString(&req, config.bssid.c_str());
    (void)WriteString(&req, config.ssid.c_str());
    (void)WriteInt32(&req, config.band);
    (void)WriteInt32(&req, config.channel);
    (void)WriteInt32(&req, config.frequency);
    (void)WriteInt32(&req, config.level);
    (void)WriteBool(&req, config.isPasspoint);
    (void)WriteBool(&req, config.isEphemeral);
    (void)WriteString(&req, config.preSharedKey.c_str());
    (void)WriteString(&req, config.keyMgmt.c_str());
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        (void)WriteString(&req, config.wepKeys[i].c_str());
    }
    (void)WriteInt32(&req, config.wepTxKeyIndex);
    (void)WriteInt32(&req, config.priority);
    (void)WriteBool(&req, config.hiddenSSID);
    (void)WriteInt32(&req, (int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    (void)WriteInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    (void)WriteInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    (void)WriteInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer2);
    (void)WriteString(&req, config.wifiIpConfig.staticIpAddress.domains.c_str());
    WriteEapConfig(req, config.wifiEapConfig);
    (void)WriteInt32(&req, (int)config.wifiProxyconfig.configureMethod);
    (void)WriteString(&req, config.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str());
    (void)WriteString(&req, config.wifiProxyconfig.manualProxyConfig.serverHostName.c_str());
    (void)WriteInt32(&req, config.wifiProxyconfig.manualProxyConfig.serverPort);
    (void)WriteString(&req, config.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str());
    (void)WriteInt32(&req, (int)config.wifiPrivacySetting);
}

ErrCode WifiDeviceProxy::AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_BIG];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_BIG, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteBool(&req, isCandidate);
    WriteDeviceConfig(config, req);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::UpdateDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_BIG];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_BIG, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    WriteDeviceConfig(config, req);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::RemoveDevice(int networkId)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, networkId);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::RemoveAllDevice()
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteBool(&req, isCandidate);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, networkId);
    (void)WriteInt32(&req, attemptEnable);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::DisableDeviceConfig(int networkId)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, networkId);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::ConnectToNetwork(int networkId, bool isCandidate)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteBool(&req, isCandidate);
    (void)WriteInt32(&req, networkId);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::ConnectToDevice(const WifiDeviceConfig &config)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_BIG];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_BIG, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    WriteDeviceConfig(config, req);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::IsConnected(bool &isConnected)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};
    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &isConnected;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::ReConnect()
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::ReAssociate(void)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::Disconnect(void)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::StartWps(const WpsConfig &config)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, static_cast<int>(config.setup));
    (void)WriteString(&req, config.pin.c_str());
    (void)WriteString(&req, config.bssid.c_str());
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::CancelWps(void)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), &req, &owner,
        IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::IsWifiActive(bool &bActive)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &bActive;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::IsMeteredHotspot(bool &bMeteredHotspot)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &bMeteredHotspot;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetWifiState(int &state)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &state;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetLinkedInfo(WifiLinkedInfo &info)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &info;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetIpInfo(IpInfo &info)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &info;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetIpv6Info(IpV6Info &info)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &info;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::SetCountryCode(const std::string &countryCode)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteString(&req, countryCode.c_str());
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetCountryCode(std::string &countryCode)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &countryCode;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGD("RegisterCallBack start!");
    g_objStub.func = AsyncCallback;
    g_objStub.args = nullptr;
    g_objStub.isRemote = false;

    g_sid.handle = IPC_INVALID_HANDLE;
    g_sid.token = SERVICE_TYPE_ANONYMOUS;
    g_sid.cookie = (uintptr_t)&g_objStub;

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    bool writeRemote = WriteRemoteObject(&req, &g_sid);
    if (!writeRemote) {
        WIFI_LOGE("WriteRemoteObject failed.");
        return WIFI_OPT_FAILED;
    }
    int eventNum = event.size();
    (void)WriteInt32(&req, eventNum);
    if (eventNum > 0) {
        for (auto &eventName : event) {
            (void)WriteString(&req, eventName.c_str());
        }
    }
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    g_deviceCallBackStub.RegisterUserCallBack(callback);
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, rssi);
    (void)WriteInt32(&req, band);
    owner.variable = &level;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetSupportedFeatures(long &features)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &features;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetDeviceMacAddress(std::string &result)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD));
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

bool WifiDeviceProxy::SetLowLatencyMode(bool enabled)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    bool result = false;
    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteBool(&req, enabled);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return result;
}

void WifiDeviceProxy::OnRemoteDied(void)
{
    WIFI_LOGW("Remote service is died!");
    remoteDied_ = true;
    g_deviceCallBackStub.SetRemoteDied(true);
}
ErrCode WifiDeviceProxy::IsBandTypeSupported(int bandType, bool &supported)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, bandType);
    owner.variable = &supported;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("IsBandTypeSupported (%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::Get5GHzChannelList(std::vector<int> &result)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    owner.variable = &result;
    owner.funcId = static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST);
    int error = remote_->Invoke(remote_, static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Get5GHzChannelList(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }

    return ErrCode(owner.retCode);
}
}  // namespace Wifi
}  // namespace OHOS
