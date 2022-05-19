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

#include "wifi_scan_callback_proxy.h"
#include "define.h"
#include "liteipc_adapter.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanCallbackProxyLite");

namespace OHOS {
namespace Wifi {
WifiScanCallbackProxy::WifiScanCallbackProxy(SvcIdentity *sid) : sid_(sid)
{}

WifiScanCallbackProxy::~WifiScanCallbackProxy()
{
    if (sid_ != nullptr) {
#ifdef __LINUX__
        BinderRelease(sid_->ipcContext, sid_->handle);
#endif
        free(sid_);
        sid_ = nullptr;
    }
}

void WifiScanCallbackProxy::OnWifiScanStateChanged(int state)
{
    WIFI_LOGD("OnWifiScanStateChanged, state:%{public}d", state);
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, state);
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_SCAN_STATE_CHANGE, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    switch (ret) {
        case LITEIPC_OK:
            WIFI_LOGD("OnWifiScanStateChanged callback sucessed!");
            break;
        default: {
            WIFI_LOGE("OnWifiScanStateChanged,connect done failed, error: %{public}d!", ret);
            break;
        }
    }
}
}  // namespace Wifi
}  // namespace OHOS
