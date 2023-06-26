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

#include "wifi_scan_stub_lite.h"
#include "define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_scan_callback_proxy.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanStubLite");

namespace OHOS {
namespace Wifi {
WifiScanStub::WifiScanStub()
{}

WifiScanStub::~WifiScanStub()
{}

int WifiScanStub::CheckInterfaceToken(uint32_t code, IpcIo *req)
{
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(req, &length);
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH ||interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            WIFI_LOGE("Scan stub token verification error: %{public}d", code);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

int WifiScanStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub::OnRemoteRequest,code:%{public}u", code);
    if (req == nullptr || reply == nullptr) {
        WIFI_LOGE("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return ERR_FAILED;
    }
    if (CheckInterfaceToken(code, req) == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    int exception = ERR_FAILED;
    (void)ReadInt32(req, &exception);
    if (exception) {
        return WIFI_OPT_FAILED;
    }

    int ret = -1;
    switch (code) {
        case WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO: {
            ret = OnSetScanControlInfo(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_FULL_SCAN: {
            ret = OnScan(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN: {
            ret = OnScanByParams(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE: {
            ret = OnIsWifiClosedScan(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_GET_SCAN_INFO_LIST: {
            ret = OnGetScanInfoList(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK: {
            ret = OnRegisterCallBack(code, req, reply);
            break;
        }
        case WIFI_SVR_CMD_GET_SUPPORTED_FEATURES: {
            ret = OnGetSupportedFeatures(code, req, reply);
            break;
        }
        default: {
            ret = -1;
        }
    }
    return ret;
}

int WifiScanStub::OnSetScanControlInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    int tmpInt;
    constexpr int MAX_SIZE = 1024;
    ScanControlInfo info;
    int forbidListSize = 0;
    (void)ReadInt32(req, &forbidListSize);
    if (forbidListSize > MAX_SIZE) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < forbidListSize; i++) {
        ScanForbidMode scanForbidMode;
        (void)ReadInt32(req, &scanForbidMode.scanScene);
        (void)ReadInt32(req, &tmpInt);
        scanForbidMode.scanMode = static_cast<ScanMode>(tmpInt);
        (void)ReadInt32(req, &scanForbidMode.forbidTime);
        (void)ReadInt32(req, &scanForbidMode.forbidCount);
        info.scanForbidList.push_back(scanForbidMode);
    }

    int intervalSize = 0;
    (void)ReadInt32(req, &intervalSize);
    if (intervalSize > MAX_SIZE) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < intervalSize; i++) {
        ScanIntervalMode scanIntervalMode;
        (void)ReadInt32(req, &scanIntervalMode.scanScene);
        (void)ReadInt32(req, &tmpInt);
        scanIntervalMode.scanMode = static_cast<ScanMode>(tmpInt);
        (void)ReadBool(req, &scanIntervalMode.isSingle);
        (void)ReadInt32(req, &tmpInt);
        scanIntervalMode.intervalMode = static_cast<IntervalMode>(tmpInt);
        (void)ReadInt32(req, &scanIntervalMode.interval);
        (void)ReadInt32(req, &scanIntervalMode.count);
        info.scanIntervalList.push_back(scanIntervalMode);
    }

    ErrCode ret = SetScanControlInfo(info);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnScan(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    ErrCode ret = Scan();
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnScanByParams(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    constexpr int MAX_FREQS_SIZE = 512;
    WifiScanParams params;
    params.ssid = (char *)ReadString(req, &readLen);
    params.bssid = (char *)ReadString(req, &readLen);
    int size = 0;
    (void)ReadInt32(req, &size);
    if (size > MAX_FREQS_SIZE) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    int tmp;
    for (int i = 0; i < size; i++) {
        (void)ReadInt32(req, &tmp);
        params.freqs.push_back(tmp);
    }
    (void)ReadUint32(req, &params.band);

    ErrCode ret = AdvanceScan(params);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnIsWifiClosedScan(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    bool bOpen = false;
    ErrCode ret = IsWifiClosedScan(bOpen);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteBool(reply, bOpen);
    }
    return ret;
}

int WifiScanStub::OnGetScanInfoList(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    std::vector<WifiScanInfo> result;
    ErrCode ret = GetScanInfoList(result);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret != WIFI_OPT_SUCCESS) {
        return ret;
    }

    unsigned int size = result.size();
    (void)WriteInt32(reply, size);
    for (unsigned int i = 0; i < size; ++i) {
        (void)WriteString(reply, result[i].bssid.c_str());
        (void)WriteString(reply, result[i].ssid.c_str());
        (void)WriteString(reply, result[i].capabilities.c_str());
        (void)WriteInt32(reply, result[i].frequency);
        (void)WriteInt32(reply, result[i].rssi);
        (void)WriteUint64(reply, result[i].timestamp);
        (void)WriteInt32(reply, result[i].band);
        (void)WriteInt32(reply, static_cast<int>(result[i].securityType));
        (void)WriteInt32(reply, static_cast<int>(result[i].channelWidth));
        (void)WriteInt32(reply, result[i].centerFrequency0);
        (void)WriteInt32(reply, result[i].centerFrequency1);
        (void)WriteUint64(reply, result[i].features);
        (void)WriteInt32(reply, result[i].infoElems.size());
        for (unsigned int m = 0; m < result[i].infoElems.size(); ++m) {
            (void)WriteUint32(reply, result[i].infoElems[m].id);
            (void)WriteInt32(reply, result[i].infoElems[m].content.size());
            for (unsigned int n = 0; n < result[i].infoElems[m].content.size(); ++n) {
                (void)WriteInt8(reply, result[i].infoElems[m].content[n]);
            }
        }
    }
    return ret;
}

int WifiScanStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = WIFI_OPT_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        WIFI_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return ret;
    }

    std::shared_ptr<IWifiScanCallback> callback_ = std::make_shared<WifiScanCallbackProxy>(&sid);
    WIFI_LOGD("create new WifiScanCallbackProxy!");
    ret = RegisterCallBack(callback_);

    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return 0;
}

int WifiScanStub::OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    long features = 0;
    int ret = GetSupportedFeatures(features);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        (void)WriteUint64(reply, features);
    }

    return ret;
}
}  // namespace Wifi
}  // namespace OHOS
