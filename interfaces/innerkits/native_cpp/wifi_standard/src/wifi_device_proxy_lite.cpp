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
#include "liteipc_adapter.h"
#include "serializer.h"
#include "samgr_lite.h"
#include "wifi_ipc_lite_adapter.h"
#include "wifi_device_callback_stub_lite.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceProxyLite");

namespace OHOS {
namespace Wifi {
static WifiDeviceCallBackStub g_deviceCallBackStub;
static void ReadIpAddress(IpcIo *reply, WifiIpAddress &address)
{
    constexpr int MAX_SIZE = 256;
    address.family = IpcIoPopInt32(reply);
    address.addressIpv4 = IpcIoPopInt32(reply);
    int size = IpcIoPopInt32(reply);
    if (size > MAX_SIZE) {
        WIFI_LOGE("Read IP address size error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(IpcIoPopInt8(reply));
    }
    return;
}

static void ParseDeviceConfigs(IpcIo *reply, std::vector<WifiDeviceConfig> &result)
{
    size_t readLen;
    constexpr int MAX_DEVICE_CONFIG_SIZE = 1024;
    int retSize = IpcIoPopInt32(reply);
    if (retSize > MAX_DEVICE_CONFIG_SIZE) {
        WIFI_LOGE("Parse device config size error: %{public}d", retSize);
        return;
    }
    for (int i = 0; i < retSize; ++i) {
        WifiDeviceConfig config;
        config.networkId = IpcIoPopInt32(reply);
        config.status = IpcIoPopInt32(reply);
        config.bssid = (char *)IpcIoPopString(reply, &readLen);
        config.ssid = (char *)IpcIoPopString(reply, &readLen);
        config.band = IpcIoPopInt32(reply);
        config.channel = IpcIoPopInt32(reply);
        config.frequency = IpcIoPopInt32(reply);
        config.level = IpcIoPopInt32(reply);
        config.isPasspoint = IpcIoPopBool(reply);
        config.isEphemeral = IpcIoPopBool(reply);
        config.preSharedKey = (char *)IpcIoPopString(reply, &readLen);
        config.keyMgmt = (char *)IpcIoPopString(reply, &readLen);
        for (int j = 0; j < WEPKEYS_SIZE; j++) {
            config.wepKeys[j] = (char *)IpcIoPopString(reply, &readLen);
        }
        config.wepTxKeyIndex = IpcIoPopInt32(reply);
        config.priority = IpcIoPopInt32(reply);
        config.hiddenSSID = IpcIoPopBool(reply);
        config.wifiIpConfig.assignMethod = AssignIpMethod(IpcIoPopInt32(reply));
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
        config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = IpcIoPopInt32(reply);
        config.wifiIpConfig.staticIpAddress.ipAddress.flags = IpcIoPopInt32(reply);
        config.wifiIpConfig.staticIpAddress.ipAddress.scope = IpcIoPopInt32(reply);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
        config.wifiIpConfig.staticIpAddress.domains = (char *)IpcIoPopString(reply, &readLen);
        config.wifiEapConfig.eap = (char *)IpcIoPopString(reply, &readLen);
        config.wifiEapConfig.identity = (char *)IpcIoPopString(reply, &readLen);
        config.wifiEapConfig.password = (char *)IpcIoPopString(reply, &readLen);
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(IpcIoPopInt32(reply));
        config.wifiProxyconfig.autoProxyConfig.pacWebAddress = (char *)IpcIoPopString(reply, &readLen);
        config.wifiProxyconfig.manualProxyConfig.serverHostName = (char *)IpcIoPopString(reply, &readLen);
        config.wifiProxyconfig.manualProxyConfig.serverPort = IpcIoPopInt32(reply);
        config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = (char *)IpcIoPopString(reply, &readLen);
        config.wifiPrivacySetting = WifiPrivacyConfig(IpcIoPopInt32(reply));

        result.emplace_back(config);
    }
}

static void ReadLinkedInfo(IpcIo *reply, WifiLinkedInfo &info)
{
    size_t readLen;
    info.networkId = IpcIoPopInt32(reply);
    info.ssid = (char *)IpcIoPopString(reply, &readLen);
    info.bssid = (char *)IpcIoPopString(reply, &readLen);
    info.rssi = IpcIoPopInt32(reply);
    info.band = IpcIoPopInt32(reply);
    info.frequency = IpcIoPopInt32(reply);
    info.linkSpeed = IpcIoPopInt32(reply);
    info.macAddress = (char *)IpcIoPopString(reply, &readLen);
    info.ipAddress = IpcIoPopInt32(reply);
    int tmpConnState = IpcIoPopInt32(reply);
    if ((tmpConnState >= 0) && (tmpConnState <= (int)ConnState::FAILED)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::FAILED;
    }
    info.ifHiddenSSID = IpcIoPopBool(reply);
    info.rxLinkSpeed = (char *)IpcIoPopString(reply, &readLen);
    info.txLinkSpeed = (char *)IpcIoPopString(reply, &readLen);
    info.chload = IpcIoPopInt32(reply);
    info.snr = IpcIoPopInt32(reply);

    int tmpState = IpcIoPopInt32(reply);
    if ((tmpState >= 0) && (tmpState <= (int)SupplicantState::INVALID)) {
        info.supplicantState = (SupplicantState)tmpState;
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = IpcIoPopInt32(reply);
    if ((tmpDetailState >= 0) && (tmpDetailState <= (int)DetailedState::INVALID)) {
        info.detailedState = (DetailedState)tmpDetailState;
    } else {
        info.detailedState = DetailedState::INVALID;
    }
}

static void ReadDhcpInfo(IpcIo *reply, IpInfo &info)
{
    info.ipAddress = IpcIoPopInt32(reply);
    info.gateway = IpcIoPopInt32(reply);
    info.netmask = IpcIoPopInt32(reply);
    info.primaryDns = IpcIoPopInt32(reply);
    info.secondDns = IpcIoPopInt32(reply);
    info.serverIp = IpcIoPopInt32(reply);
    info.leaseDuration = IpcIoPopInt32(reply);
}

static int IpcCallback(void *owner, int code, IpcIo *reply)
{
    if (code != 0 || owner == nullptr || reply == nullptr) {
        WIFI_LOGE("Callback error, code:%{public}d, owner:%{public}d, reply:%{public}d",
            code, owner == nullptr, reply == nullptr);
        return LITEIPC_EINVAL;
    }

    struct IpcOwner *data = (struct IpcOwner *)owner;
    data->exception = IpcIoPopInt32(reply);
    data->retCode = IpcIoPopInt32(reply);
    if (data->exception != 0 || data->retCode != WIFI_OPT_SUCCESS || data->variable == nullptr) {
        return LITEIPC_OK;
    }

    switch (data->funcId) {
        case WIFI_SVR_CMD_ADD_DEVICE_CONFIG:
        case WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG:
        case WIFI_SVR_CMD_GET_WIFI_STATE:
        case WIFI_SVR_CMD_GET_SIGNAL_LEVEL: {
            *((int32_t *)data->variable) = IpcIoPopInt32(reply);
            break;
        }
        case WIFI_SVR_CMD_IS_WIFI_ACTIVE: {
            *((bool *)data->variable) = IpcIoPopBool(reply);
            break;
        }
        case WIFI_SVR_CMD_GET_COUNTRY_CODE:
        case WIFI_SVR_CMD_GET_DERVICE_MAC_ADD: {
            size_t readLen = 0;
            *((std::string *)data->variable) = (char *)IpcIoPopString(reply, &readLen);
            break;
        }
        case WIFI_SVR_CMD_GET_SUPPORTED_FEATURES: {
            *((long *)data->variable) = IpcIoPopInt64(reply);
            break;
        }
        case WIFI_SVR_CMD_GET_DEVICE_CONFIGS: {
            ParseDeviceConfigs(reply, *((std::vector<WifiDeviceConfig> *)data->variable));
            break;
        }
        case WIFI_SVR_CMD_GET_LINKED_INFO: {
            ReadLinkedInfo(reply, *((WifiLinkedInfo *)data->variable));
            break;
        }
        case WIFI_SVR_CMD_GET_DHCP_INFO: {
            ReadDhcpInfo(reply, *((IpInfo *)data->variable));
            break;
        }
        default:
            break;
    }

    return LITEIPC_OK;
}

static int AsyncCallback(const IpcContext *ipcContext, void *ipcMsg, IpcIo *data, void *arg)
{
    if (ipcMsg == nullptr || data == nullptr) {
        WIFI_LOGE("AsyncCallback error, msg:%{public}d, data:%{public}d",
            ipcMsg == nullptr, data == nullptr);
        return LITEIPC_EINVAL;
    }

    uint32_t code;
    int codeRet = GetCode(ipcMsg, &code);
    if (codeRet == LITEIPC_OK) {
        return g_deviceCallBackStub.OnRemoteRequest(code, data);
    }
    return LITEIPC_EINVAL;
}

static int OnRemoteSrvDied(const IpcContext *context, void *ipcMsg, IpcIo *data, void *arg)
{
    WIFI_LOGE("%{public}s called.", __func__);
    WifiDeviceProxy *client = WifiDeviceProxy::GetInstance();
    if (client != nullptr) {
        client->OnRemoteDied();
    }
    return LITEIPC_OK;
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
    result = RegisterDeathCallback(nullptr, svcIdentity_, OnRemoteSrvDied, nullptr, &deadId);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_ENABLE_WIFI;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_ENABLE_WIFI, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ENABLE_WIFI, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_DISABLE_WIFI;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_DISABLE_WIFI, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISABLE_WIFI, error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

void WifiDeviceProxy::WriteIpAddress(IpcIo &req, const WifiIpAddress &address)
{
    IpcIoPushInt32(&req, address.family);
    IpcIoPushInt32(&req, address.addressIpv4);
    int size = address.addressIpv6.size();
    IpcIoPushInt32(&req, size);
    for (int i = 0; i < size; i++) {
        IpcIoPushInt8(&req, address.addressIpv6[i]);
    }
    return;
}

void WifiDeviceProxy::WriteDeviceConfig(const WifiDeviceConfig &config, IpcIo &req)
{
    IpcIoPushInt32(&req, config.networkId);
    IpcIoPushInt32(&req, config.status);
    IpcIoPushString(&req, config.bssid.c_str());
    IpcIoPushString(&req, config.ssid.c_str());
    IpcIoPushInt32(&req, config.band);
    IpcIoPushInt32(&req, config.channel);
    IpcIoPushInt32(&req, config.frequency);
    IpcIoPushInt32(&req, config.level);
    IpcIoPushBool(&req, config.isPasspoint);
    IpcIoPushBool(&req, config.isEphemeral);
    IpcIoPushString(&req, config.preSharedKey.c_str());
    IpcIoPushString(&req, config.keyMgmt.c_str());
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        IpcIoPushString(&req, config.wepKeys[i].c_str());
    }
    IpcIoPushInt32(&req, config.wepTxKeyIndex);
    IpcIoPushInt32(&req, config.priority);
    IpcIoPushBool(&req, config.hiddenSSID);
    IpcIoPushInt32(&req, (int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    IpcIoPushInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    IpcIoPushInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    IpcIoPushInt32(&req, config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer2);
    IpcIoPushString(&req, config.wifiIpConfig.staticIpAddress.domains.c_str());
    IpcIoPushString(&req, config.wifiEapConfig.eap.c_str());
    IpcIoPushString(&req, config.wifiEapConfig.identity.c_str());
    IpcIoPushString(&req, config.wifiEapConfig.password.c_str());
    IpcIoPushInt32(&req, (int)config.wifiProxyconfig.configureMethod);
    IpcIoPushString(&req, config.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str());
    IpcIoPushString(&req, config.wifiProxyconfig.manualProxyConfig.serverHostName.c_str());
    IpcIoPushInt32(&req, config.wifiProxyconfig.manualProxyConfig.serverPort);
    IpcIoPushString(&req, config.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str());
    IpcIoPushInt32(&req, (int)config.wifiPrivacySetting);
}

ErrCode WifiDeviceProxy::AddDeviceConfig(const WifiDeviceConfig &config, int &result)
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
    IpcIoPushInt32(&req, 0);
    WriteDeviceConfig(config, req);
    owner.variable = &result;
    owner.funcId = WIFI_SVR_CMD_ADD_DEVICE_CONFIG;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_ADD_DEVICE_CONFIG, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ADD_DEVICE_CONFIG, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, networkId);
    owner.funcId = WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result)
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &result;
    owner.funcId = WIFI_SVR_CMD_GET_DEVICE_CONFIGS;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_DEVICE_CONFIGS, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_DEVICE_CONFIGS, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, networkId);
    IpcIoPushInt32(&req, attemptEnable);
    owner.funcId = WIFI_SVR_CMD_ENABLE_DEVICE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_ENABLE_DEVICE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ENABLE_DEVICE, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, networkId);
    owner.funcId = WIFI_SVR_CMD_DISABLE_DEVICE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_DISABLE_DEVICE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISABLE_DEVICE, error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::ConnectToNetwork(int networkId)
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, networkId);
    owner.funcId = WIFI_SVR_CMD_CONNECT_TO;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_CONNECT_TO, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CONNECT_TO, error);
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
    IpcIoPushInt32(&req, 0);
    WriteDeviceConfig(config, req);
    owner.funcId = WIFI_SVR_CMD_CONNECT2_TO;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_CONNECT2_TO, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CONNECT2_TO, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_RECONNECT;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_RECONNECT, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_RECONNECT, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_REASSOCIATE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_REASSOCIATE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REASSOCIATE, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_DISCONNECT;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_DISCONNECT, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISCONNECT, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, static_cast<int>(config.setup));
    IpcIoPushString(&req, config.pin.c_str());
    IpcIoPushString(&req, config.bssid.c_str());
    owner.funcId = WIFI_SVR_CMD_START_WPS;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_START_WPS, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_START_WPS, error);
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
    IpcIoPushInt32(&req, 0);
    owner.funcId = WIFI_SVR_CMD_CANCEL_WPS;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_CANCEL_WPS, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CANCEL_WPS, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &bActive;
    owner.funcId = WIFI_SVR_CMD_IS_WIFI_ACTIVE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_IS_WIFI_ACTIVE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_IS_WIFI_ACTIVE, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &state;
    owner.funcId = WIFI_SVR_CMD_GET_WIFI_STATE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_WIFI_STATE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_WIFI_STATE, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &info;
    owner.funcId = WIFI_SVR_CMD_GET_LINKED_INFO;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_LINKED_INFO, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_LINKED_INFO, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &info;
    owner.funcId = WIFI_SVR_CMD_GET_DHCP_INFO;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_DHCP_INFO, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_DHCP_INFO, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushString(&req, countryCode.c_str());
    owner.funcId = WIFI_SVR_CMD_SET_COUNTRY_CODE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_SET_COUNTRY_CODE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_SET_COUNTRY_CODE, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &countryCode;
    owner.funcId = WIFI_SVR_CMD_GET_COUNTRY_CODE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_COUNTRY_CODE, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_COUNTRY_CODE, error);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiDeviceProxy::RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGD("RegisterCallBack start!");
    int ret = RegisterIpcCallback(AsyncCallback, ONCE, IPC_WAIT_FOREVER, &svcIdentity_, nullptr);
    if (ret != 0) {
        WIFI_LOGE("RegisterIpcCallback failed");
        return WIFI_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    IpcIoPushInt32(&req, 0);
    IpcIoPushSvc(&req, &svcIdentity_);

    owner.funcId = WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed, code is %{public}d", WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT, error);
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
    IpcIoPushInt32(&req, 0);
    IpcIoPushInt32(&req, rssi);
    IpcIoPushInt32(&req, band);
    owner.variable = &level;
    owner.funcId = WIFI_SVR_CMD_GET_SIGNAL_LEVEL;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_SIGNAL_LEVEL, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_SIGNAL_LEVEL, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &features;
    owner.funcId = WIFI_SVR_CMD_GET_SUPPORTED_FEATURES;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, error);
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
    IpcIoPushInt32(&req, 0);
    owner.variable = &result;
    owner.funcId = WIFI_SVR_CMD_GET_DERVICE_MAC_ADD;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_DERVICE_MAC_ADD, &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_DERVICE_MAC_ADD);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

void WifiDeviceProxy::OnRemoteDied(void)
{
    WIFI_LOGD("Remote service is died!");
    remoteDied_ = true;
    g_deviceCallBackStub.SetRemoteDied(true);
}
}  // namespace Wifi
}  // namespace OHOS
