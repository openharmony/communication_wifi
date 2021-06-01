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

#ifndef OHOS_WIFIINTERFACEMANAGER_H
#define OHOS_WIFIINTERFACEMANAGER_H

#include <map>
#include <string>
#include "wifi_interface_info.h"

namespace OHOS {
namespace Wifi {
typedef std::map<int, WifiInterfaceInfo *> MAP_INT_INTERFACEINFO;
class WifiInterfaceManager {
public:
    /**
     * @Description Construct a new Wifi Interface Manager object.
     *
     */
    WifiInterfaceManager();
    /**
     * @Description Destroy the Wifi Interface Manager object.
     *
     */
    ~WifiInterfaceManager();
    /**
     * @Description Apply for WifiInterfaceInfo* memory based on the type value.
     *
     * @param type
     * @return WifiInterfaceInfo*
     */
    WifiInterfaceInfo *AllocInteface(InterfaceType type);
    /**
     * @Description Get the Interface object.
     *
     * @param id
     * @return WifiInterfaceInfo*
     */
    WifiInterfaceInfo *GetInterface(const int &id);
    /**
     * @Description Get the Interface object.
     *
     * @param ifaceName
     * @return WifiInterfaceInfo*
     */
    WifiInterfaceInfo *GetInterface(const std::string &ifaceName);
    /**
     * @Description Remove Interface by id.
     *
     * @param id
     * @return true
     * @return false
     */
    bool RemoveInterface(const int &id);
    /**
     * @Description Check is any interface exist.
     *
     * @return true
     * @return false
     */
    bool IsAnyInterfaceExist();

private:
    int m_nextIndex;
    MAP_INT_INTERFACEINFO m_interfaceMap;
};
}  // namespace Wifi
}  // namespace OHOS

#endif