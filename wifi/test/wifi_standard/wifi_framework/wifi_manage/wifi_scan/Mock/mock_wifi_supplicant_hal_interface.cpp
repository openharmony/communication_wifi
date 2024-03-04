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
#include "mock_wifi_scan_interface.h"

namespace OHOS {
namespace Wifi {

MockWifiScanInterface &MockWifiScanInterface::GetInstance(void)
{
    static MockWifiScanInterface inst;
    return inst;
}

namespace WifiSupplicantHalInterface {

WifiErrorNo UnRegisterSupplicantEventCallback()
{
    return MockWifiScanInterface::GetInstance().pSupplicant.unCallback ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo RegisterSupplicantEventCallback(SupplicantEventCallback &callback)
{
    return MockWifiScanInterface::GetInstance().pSupplicant.callback ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}
};
}  // namespace Wifi
}  // namespace OHOS