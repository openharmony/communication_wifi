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

#ifndef I_WIFI_COUNTRY_CODE_CHANGE_LISTENER_H
#define I_WIFI_COUNTRY_CODE_CHANGE_LISTENER_H

#include <functional>
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "state_machine.h"

namespace OHOS {
namespace Wifi {
class IWifiCountryCodeChangeListener {
public:
    IWifiCountryCodeChangeListener(const std::string &name, StateMachine &stateMachineObj)
        : m_stateMachineObj(stateMachineObj), m_listenerModuleName(name) {}
    virtual ~IWifiCountryCodeChangeListener() = default;
    virtual ErrCode OnWifiCountryCodeChanged(const std::string &wifiCountryCode) = 0;
    virtual std::string GetListenerModuleName() = 0;
    StateMachine &m_stateMachineObj;
protected:
    std::string m_lastWifiCountryCode;
    std::string m_listenerModuleName;
};
}
}
#endif