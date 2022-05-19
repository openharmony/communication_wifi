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
#ifndef OHOS_I_WIFI_SCAN_CALLBACK_H
#define OHOS_I_WIFI_SCAN_CALLBACK_H

#include <string>
#ifndef OHOS_ARCH_LITE
#include <string_ex.h>
#include <iremote_broker.h>
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "define.h"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class IWifiScanCallback {
#else
class IWifiScanCallback : public IRemoteBroker {
#endif
public:
    virtual void OnWifiScanStateChanged(int state) = 0;

#ifndef OHOS_ARCH_LITE
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IWifiScanCallback");
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif

