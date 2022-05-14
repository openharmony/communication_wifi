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

#ifndef OHOS_WIFI_DEVICE_STUB_LITE_H
#define OHOS_WIFI_DEVICE_STUB_LITE_H

#include <map>
#include "i_wifi_device.h"
#include "i_wifi_device_callback.h"
#include "serializer.h"

namespace OHOS {
namespace Wifi {
class WifiDeviceStub : public IWifiDevice {
public:
    WifiDeviceStub();
    virtual ~WifiDeviceStub();

    using HandleFunc = void (WifiDeviceStub::*)(uint32_t code, IpcIo *req, IpcIo *reply);
    using HandleFuncMap = std::map<int, HandleFunc>;

    virtual int OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply);

private:
    void InitHandleMap();
    void OnEnableWifi(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnDisableWifi(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnInitWifiProtect(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetWifiProtectRef(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnPutWifiProtectRef(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnAddDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnUpdateDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnRemoveDevice(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnRemoveAllDevice(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetDeviceConfigs(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnEnableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnDisableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnConnectTo(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnConnect2To(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnReConnect(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnReAssociate(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnDisconnect(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnStartWps(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnCancelWps(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnIsWifiActive(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetWifiState(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetLinkedInfo(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetIpInfo(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnSetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetSignalLevel(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnGetDeviceMacAdd(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnIsWifiConnected(uint32_t code, IpcIo *req, IpcIo *reply);
    void OnSetLowLatencyMode(uint32_t code, IpcIo *req, IpcIo *reply);

private:
    void ReadWifiDeviceConfig(IpcIo *req, WifiDeviceConfig &config);
    void ReadIpAddress(IpcIo *req, WifiIpAddress &address);
    void WriteWifiDeviceConfig(IpcIo *reply, const WifiDeviceConfig &config);
    void WriteIpAddress(IpcIo *reply, const WifiIpAddress &address);

private:
    HandleFuncMap handleFuncMap_;
    std::shared_ptr<IWifiDeviceCallBack> callback_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif