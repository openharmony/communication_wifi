
/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "mock_wifi_app_state_aware.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace Wifi {

WifiAppStateAware &WifiAppStateAware::GetInstance()
{
    static WifiAppStateAware gWifiAppStateAware;
    return gWifiAppStateAware;
}

WifiAppStateAware::WifiAppStateAware()
{}
WifiAppStateAware::~WifiAppStateAware()
{}

bool WifiAppStateAware::IsForegroundApp(int32_t uid)
{
    return true;
}

bool WifiAppStateAware::IsForegroundApp(const std::string &bundleName)
{
    return true;
}

}
}