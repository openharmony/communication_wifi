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

#ifndef OHOS_WIFIINTERFACEINFO_H
#define OHOS_WIFIINTERFACEINFO_H

#include <string>

namespace OHOS {
namespace Wifi {
typedef enum InterfaceType { IFACE_TYPE_AP, IFACE_TYPE_STA_FOR_CONNECTIVITY, IFACE_TYPE_STA_FOR_SCAN } InterfaceType;

class WifiInterfaceInfo {
public:
    WifiInterfaceInfo()
    {}
    ~WifiInterfaceInfo()
    {}

    int id;
    InterfaceType type;
    std::string name;
    bool isUp = false;
    long featureSet = 0;
};
}  // namespace Wifi
}  // namespace OHOS

#endif