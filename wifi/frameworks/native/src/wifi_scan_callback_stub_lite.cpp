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

#include "wifi_scan_callback_stub.h"
#include "define.h"
#include "wifi_errcode.h"
#include "wifi_logger.h"
#include "wifi_msg.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanCallbackStubLite");
namespace OHOS {
namespace Wifi {
WifiScanCallbackStub::WifiScanCallbackStub() : userCallback_(nullptr), mRemoteDied(false)
{}

WifiScanCallbackStub::~WifiScanCallbackStub()
{}

int WifiScanCallbackStub::OnRemoteRequest(uint32_t code, IpcIo *data)
{
    int ret = WIFI_OPT_FAILED;
    WIFI_LOGD("OnRemoteRequest code:%{public}u!", code);
    if (mRemoteDied || data == nullptr) {
        WIFI_LOGD("Failed to %{public}s,mRemoteDied:%{public}d data:%{public}d!",
            __func__, mRemoteDied, data == nullptr);
        return ret;
    }

    int exception = IpcIoPopInt32(data);
    if (exception) {
        WIFI_LOGD("OnRemoteRequest exception! %{public}d!", exception);
        return ret;
    }
    switch (code) {
        case WIFI_CBK_CMD_SCAN_STATE_CHANGE: {
            WIFI_LOGD("OnRemoteRequest code:%{public}u", code);
            ret = RemoteOnWifiScanStateChanged(code, data);
            break;
        }
        default: {
            ret = WIFI_OPT_FAILED;
        }
    }
    return ret;
}

void WifiScanCallbackStub::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &userCallback)
{
    if (userCallback_ != nullptr) {
        WIFI_LOGD("Callback has registered!");
        return;
    }
    userCallback_ = userCallback;
}

bool WifiScanCallbackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void WifiScanCallbackStub::SetRemoteDied(bool val)
{
    mRemoteDied = val;
}

void WifiScanCallbackStub::OnWifiScanStateChanged(int state)
{
    WIFI_LOGD("OnWifiScanStateChanged,state:%{public}d", state);

    if (userCallback_) {
        userCallback_->OnWifiScanStateChanged(state);
    }
}

int WifiScanCallbackStub::RemoteOnWifiScanStateChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int stateCode = IpcIoPopInt32(data);
    OnWifiScanStateChanged(stateCode);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
