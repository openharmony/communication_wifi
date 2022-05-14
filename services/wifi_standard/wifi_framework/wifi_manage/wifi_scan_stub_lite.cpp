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
#include "liteipc_adapter.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_scan_callback_proxy.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanStubLite");

namespace OHOS {
namespace Wifi {
WifiScanStub::WifiScanStub() : callback_(nullptr)
{}

WifiScanStub::~WifiScanStub()
{}

int WifiScanStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub::OnRemoteRequest,code:%{public}u", code);
    if (req == nullptr || reply == nullptr) {
        WIFI_LOGD("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return LITEIPC_EINVAL;
    }

    int exception = IpcIoPopInt32(req);
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

std::shared_ptr<IWifiScanCallback> WifiScanStub::GetCallback() const
{
    return callback_;
}

int WifiScanStub::OnSetScanControlInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    constexpr int MAX_SIZE = 1024;
    ScanControlInfo info;
    int forbidListSize = IpcIoPopInt32(req);
    if (forbidListSize > MAX_SIZE) {
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < forbidListSize; i++) {
        int tmp = IpcIoPopInt32(req);
        int modeMapSize = IpcIoPopInt32(req);
        std::vector<ScanForbidMode> scanModeList;
        for (int j = 0; j < modeMapSize; j++) {
            ScanForbidMode scanForbidMode;
            scanForbidMode.scanMode = static_cast<ScanMode>(IpcIoPopInt32(req));
            scanForbidMode.forbidTime = IpcIoPopInt32(req);
            scanForbidMode.forbidCount = IpcIoPopInt32(req);
            scanModeList.push_back(scanForbidMode);
        }
        if (tmp < 0 || tmp >= int(SCAN_SCENE_MAX)) {
            continue;
        }
        info.scanForbidMap.insert(std::pair<int, std::vector<ScanForbidMode>>(tmp, scanModeList));
    }

    int intervalSize = IpcIoPopInt32(req);
    if (intervalSize > MAX_SIZE) {
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < intervalSize; i++) {
        ScanIntervalMode scanIntervalMode;
        scanIntervalMode.scanScene = IpcIoPopInt32(req);
        scanIntervalMode.scanMode = static_cast<ScanMode>(IpcIoPopInt32(req));
        scanIntervalMode.isSingle = IpcIoPopBool(req);
        scanIntervalMode.intervalMode = static_cast<IntervalMode>(IpcIoPopInt32(req));
        scanIntervalMode.interval = IpcIoPopInt32(req);
        scanIntervalMode.count = IpcIoPopInt32(req);
        info.scanIntervalList.push_back(scanIntervalMode);
    }

    ErrCode ret = SetScanControlInfo(info);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnScan(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    ErrCode ret = Scan();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnScanByParams(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    constexpr int MAX_FREQS_SIZE = 512;
    WifiScanParams params;
    params.ssid = (char *)IpcIoPopString(req, &readLen);
    params.bssid = (char *)IpcIoPopString(req, &readLen);
    int size = IpcIoPopInt32(req);
    if (size > MAX_FREQS_SIZE) {
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < size; i++) {
        int tmp = IpcIoPopInt32(req);
        params.freqs.push_back(tmp);
    }
    params.band = IpcIoPopInt32(req);

    ErrCode ret = AdvanceScan(params);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    return ret;
}

int WifiScanStub::OnIsWifiClosedScan(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    bool bOpen = false;
    ErrCode ret = IsWifiClosedScan(bOpen);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushBool(reply, bOpen);
    }
    return ret;
}

int WifiScanStub::OnGetScanInfoList(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    std::vector<WifiScanInfo> result;
    ErrCode ret = GetScanInfoList(result);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret != WIFI_OPT_SUCCESS) {
        return ret;
    }

    unsigned int size = result.size();
    IpcIoPushInt32(reply, size);
    for (unsigned int i = 0; i < size; ++i) {
        IpcIoPushString(reply, result[i].bssid.c_str());
        IpcIoPushString(reply, result[i].ssid.c_str());
        IpcIoPushString(reply, result[i].capabilities.c_str());
        IpcIoPushInt32(reply, result[i].frequency);
        IpcIoPushInt32(reply, result[i].rssi);
        IpcIoPushInt64(reply, result[i].timestamp);
        IpcIoPushInt32(reply, result[i].band);
        IpcIoPushInt32(reply, static_cast<int>(result[i].securityType));
        IpcIoPushInt32(reply, static_cast<int>(result[i].channelWidth));
        IpcIoPushInt32(reply, result[i].centerFrequency0);
        IpcIoPushInt32(reply, result[i].centerFrequency1);
        IpcIoPushInt64(reply, result[i].features);
        IpcIoPushInt32(reply, result[i].infoElems.size());
        for (unsigned int m = 0; m < result[i].infoElems.size(); ++m) {
            IpcIoPushInt32(reply, result[i].infoElems[m].id);
            IpcIoPushInt32(reply, result[i].infoElems[m].content.size());
            for (unsigned int n = 0; n < result[i].infoElems[m].content.size(); ++n) {
                IpcIoPushInt8(reply, result[i].infoElems[m].content[n]);
            }
        }
    }
    return ret;
}

int WifiScanStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = WIFI_OPT_FAILED;
    SvcIdentity *sid = IpcIoPopSvc(req);
    if (sid == nullptr) {
        WIFI_LOGE("sid is null");
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, ret);
        return ret;
    }
#ifdef __LINUX__
    BinderAcquire(sid->ipcContext, sid->handle);
#endif

    callback_ = std::make_shared<WifiScanCallbackProxy>(sid);
    WIFI_LOGD("create new WifiScanCallbackProxy!");
    ret = RegisterCallBack(callback_);

    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    return 0;
}

int WifiScanStub::OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("WifiScanStub run %{public}s code %{public}u", __func__, code);
    long features = 0;
    int ret = GetSupportedFeatures(features);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt64(reply, features);
    }

    return ret;
}
}  // namespace Wifi
}  // namespace OHOS
