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

#include "wifi_scan_proxy.h"
#include "define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "serializer.h"
#include "samgr_lite.h"
#include "wifi_ipc_lite_adapter.h"
#include "wifi_logger.h"
#include "wifi_scan_callback_stub.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanProxyLite");
namespace OHOS {
namespace Wifi {
static SvcIdentity g_sid;
static IpcObjectStub g_objStub;
static WifiScanCallbackStub g_wifiScanCallbackStub;

static ErrCode ParseScanInfos(IpcIo *reply, std::vector<WifiScanInfo> &infos)
{
    constexpr int MAX_SIZE = 4096;
    int tmpsize = 0;
    (void)ReadInt32(reply, &tmpsize);
    if (tmpsize > MAX_SIZE) {
        WIFI_LOGE("Scan info size exceeds maximum allowed size: %{public}d", tmpsize);
        return WIFI_OPT_FAILED;
    }

    unsigned int readLen;
    for (int i = 0; i < tmpsize; ++i) {
        WifiScanInfo info;
        info.bssid = (char *)ReadString(reply, &readLen);
        info.ssid = (char *)ReadString(reply, &readLen);
        info.capabilities = (char *)ReadString(reply, &readLen);
        (void)ReadInt32(reply, &info.frequency);
        (void)ReadInt32(reply, &info.rssi);
        int64_t timestamp = 0;
        (void)ReadInt64(reply, &timestamp);
        info.timestamp = timestamp;
        (void)ReadInt32(reply, &info.band);
        int securityType = 0;
        (void)ReadInt32(reply, &securityType);
        info.securityType = static_cast<WifiSecurity>(securityType);
        int channelWidth = 0;
        (void)ReadInt32(reply, &channelWidth);
        info.channelWidth = static_cast<WifiChannelWidth>(channelWidth);
        (void)ReadInt32(reply, &info.centerFrequency0);
        (void)ReadInt32(reply, &info.centerFrequency1);
        int64_t features = 0;
        (void)ReadInt64(reply, &features);
        info.features = features;

        constexpr int IE_SIZE_MAX = 256;
        int ieSize = 0;
        (void)ReadInt32(reply, &ieSize);
        if (ieSize > IE_SIZE_MAX) {
            WIFI_LOGE("ie size error: %{public}d", ieSize);
            return WIFI_OPT_FAILED;
        }
        for (int m = 0; m < ieSize; ++m) {
            WifiInfoElem tempWifiInfoElem;
            (void)ReadUint32(reply, &tempWifiInfoElem.id);
            int contentSize = 0;
            (void)ReadInt32(reply, &contentSize);
            int8_t tmpInt8 = 0;
            for (int n = 0; n < contentSize; n++) {
                (void)ReadInt8(reply, &tmpInt8);
                char tempChar = static_cast<char>(tmpInt8);
                tempWifiInfoElem.content.emplace_back(tempChar);
            }
            info.infoElems.emplace_back(tempWifiInfoElem);
        }
        infos.emplace_back(info);
    }
    return WIFI_OPT_SUCCESS;
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
        case WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE: {
            (void)ReadBool(reply, (bool *)data->variable);
            break;
        }
        case WIFI_SVR_CMD_GET_SUPPORTED_FEATURES: {
            int64_t features = 0;
            (void)ReadInt64(reply, &features);
            *((long *)data->variable) = features;
            break;
        }
        case WIFI_SVR_CMD_GET_SCAN_INFO_LIST: {
            data->retCode = ParseScanInfos(reply, *((std::vector<WifiScanInfo> *)data->variable));
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
    return g_wifiScanCallbackStub.OnRemoteRequest(code, data);
}

static void OnRemoteSrvDied(void *arg)
{
    WIFI_LOGE("%{public}s called.", __func__);
    WifiScanProxy *client = WifiScanProxy::GetInstance();
    if (client != nullptr) {
        client->OnRemoteDied();
    }
    return;
}

WifiScanProxy *WifiScanProxy::g_instance = nullptr;
WifiScanProxy::WifiScanProxy() : remote_(nullptr), remoteDied_(false)
{}

WifiScanProxy::~WifiScanProxy()
{}

WifiScanProxy *WifiScanProxy::GetInstance(void)
{
    if (g_instance != nullptr) {
        return g_instance;
    }

    WifiScanProxy *tempInstance = new(std::nothrow) WifiScanProxy();
    g_instance = tempInstance;
    return g_instance;
}

void WifiScanProxy::ReleaseInstance(void)
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

ErrCode WifiScanProxy::Init(void)
{
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(WIFI_SERVICE_LITE, WIFI_FEATRUE_SCAN);
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
    svcIdentity_ = SAMGR_GetRemoteIdentity(WIFI_SERVICE_LITE, WIFI_FEATRUE_SCAN);
    result = AddDeathRecipient(svcIdentity_, OnRemoteSrvDied, nullptr, &deadId);
    if (result != 0) {
        WIFI_LOGE("Register SA Death Callback failed, errorCode[%d]", result);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanProxy::SetScanControlInfo(const ScanControlInfo &info)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_BIG];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_BIG, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteInt32(&request, info.scanForbidList.size());
    for (auto iter = info.scanForbidList.begin(); iter != info.scanForbidList.end(); iter++) {
        (void)WriteInt32(&request, iter->scanScene);
        (void)WriteInt32(&request, static_cast<int>(iter->scanMode));
        (void)WriteInt32(&request, iter->forbidTime);
        (void)WriteInt32(&request, iter->forbidCount);
    }

    (void)WriteInt32(&request, info.scanIntervalList.size());
    for (auto iter2 = info.scanIntervalList.begin(); iter2 != info.scanIntervalList.end(); iter2++) {
        (void)WriteInt32(&request, iter2->scanScene);
        (void)WriteInt32(&request, static_cast<int>(iter2->scanMode));
        (void)WriteBool(&request, iter2->isSingle);
        (void)WriteInt32(&request, static_cast<int>(iter2->intervalMode));
        (void)WriteInt32(&request, iter2->interval);
        (void)WriteInt32(&request, iter2->count);
    }

    owner.funcId = WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGW("Set Attr(%{public}d) failed", WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiScanProxy::Scan()
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);

    owner.funcId = WIFI_SVR_CMD_FULL_SCAN;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_FULL_SCAN, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGW("Set Attr(%{public}d) failed", WIFI_SVR_CMD_FULL_SCAN);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiScanProxy::AdvanceScan(const WifiScanParams &params)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, params.ssid.c_str());
    (void)WriteString(&request, params.bssid.c_str());
    (void)WriteInt32(&request, params.freqs.size());
    for (std::size_t i = 0; i < params.freqs.size(); i++) {
        (void)WriteInt32(&request, params.freqs[i]);
    }
    (void)WriteUint32(&request, params.band);

    owner.funcId = WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGW("Set Attr(%{public}d) failed", WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode WifiScanProxy::IsWifiClosedScan(bool &bOpen)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    owner.variable = &bOpen;
    owner.funcId = WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGW("Set Attr(%{public}d) failed", WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiScanProxy::GetScanInfoList(std::vector<WifiScanInfo> &result)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    owner.variable = &result;
    owner.funcId = WIFI_SVR_CMD_GET_SCAN_INFO_LIST;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_SCAN_INFO_LIST, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGW("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_SCAN_INFO_LIST);
        return WIFI_OPT_FAILED;
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

ErrCode WifiScanProxy::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback)
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

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteRemoteObject(&request, &g_sid);

    owner.funcId = WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("RegisterCallBack failed, error code is %{public}d", error);
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGD("RegisterCallBack is finished: result=%{public}d", owner.exception);
    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    g_wifiScanCallbackStub.RegisterCallBack(callback);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanProxy::GetSupportedFeatures(long &features)
{
    if (remoteDied_ || remote_ == nullptr) {
        WIFI_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return WIFI_OPT_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    (void)WriteInt32(&request, 0);
    owner.variable = &features;
    owner.funcId = WIFI_SVR_CMD_GET_SUPPORTED_FEATURES;
    int error = remote_->Invoke(remote_, WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, &request, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, error);
        return ErrCode(error);
    }

    if (owner.exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(owner.retCode);
}

void WifiScanProxy::OnRemoteDied(void)
{
    WIFI_LOGW("Remote service is died!");
    remoteDied_ = true;
    g_wifiScanCallbackStub.SetRemoteDied(true);
}
}  // namespace Wifi
}  // namespace OHOS
