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

#ifndef OHOS_MOCK_WIFI_SUPPLICANT_HAL_INTERFACE_H
#define OHOS_MOCK_WIFI_SUPPLICANT_HAL_INTERFACE_H
#include <string>
#include "supplicant_event_callback.h"
#include "wifi_error_no.h"
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {
class MockWifiSupplicantHalInterface {
public:
    static MockWifiSupplicantHalInterface &GetInstance(void);
    void SetRetResult(WifiErrorNo retResult);
    WifiErrorNo GetRetResult();
private:
    MockWifiSupplicantHalInterface();
    WifiErrorNo mRetResult;
};

class WifiSupplicantHalInterface {
public:
    static WifiSupplicantHalInterface &GetInstance(void);
    WifiErrorNo StartSupplicant(void) const;
    WifiErrorNo StopSupplicant(void) const;
    WifiErrorNo ConnectSupplicant(void) const;
    WifiErrorNo DisconnectSupplicant(void) const;
    WifiErrorNo RequestToSupplicant(const std::string &request) const;
    WifiErrorNo RegisterSupplicantEventCallback(SupplicantEventCallback &callback);
    WifiErrorNo UnRegisterSupplicantEventCallback(void);
    WifiErrorNo SetPowerSave(bool enable) const;
    WifiErrorNo WpaSetCountryCode(const std::string &countryCode) const;
    WifiErrorNo WpaGetCountryCode(std::string &countryCode) const;
    const SupplicantEventCallback &GetCallbackInst(void) const;
    WifiErrorNo WpaSetSuspendMode(bool mode) const;
    WifiErrorNo WpaSetPowerMode(bool mode, int instId) const;
    void NotifyScanResultEvent(uint32_t event);
private:
    SupplicantEventCallback mCallback;
};
}  // namespace Wifi
}  // namespace OHOS

#endif