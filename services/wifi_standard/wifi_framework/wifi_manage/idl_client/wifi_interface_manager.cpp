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

#include "wifi_interface_manager.h"

namespace OHOS {
namespace Wifi {
WifiInterfaceManager::WifiInterfaceManager()
{
    m_interfaceMap.clear();
    m_nextIndex = 0;
}

WifiInterfaceManager::~WifiInterfaceManager()
{
    if (!m_interfaceMap.empty()) {
        MAP_INT_INTERFACEINFO::iterator itor = m_interfaceMap.begin();
        while (itor != m_interfaceMap.end()) {
            WifiInterfaceInfo *pInfo = itor->second;
            delete pInfo;
            pInfo = nullptr;
        }

        m_interfaceMap.clear();
    }
}

WifiInterfaceInfo *WifiInterfaceManager::AllocInteface(InterfaceType type)
{
    WifiInterfaceInfo *pInfo = new WifiInterfaceInfo();
    pInfo->type = type;
    pInfo->id = m_nextIndex;
    m_interfaceMap.insert(std::make_pair(m_nextIndex, pInfo));
    m_nextIndex++;
    return pInfo;
}

WifiInterfaceInfo *WifiInterfaceManager::GetInterface(const int &id)
{
    WifiInterfaceInfo *pInfo = nullptr;
    MAP_INT_INTERFACEINFO::iterator itor = m_interfaceMap.begin();
    while (itor != m_interfaceMap.end()) {
        pInfo = itor->second;
        if (pInfo->id == id) {
            break;
        }
    }

    return pInfo;
}

WifiInterfaceInfo *WifiInterfaceManager::GetInterface(const std::string &ifaceName)
{
    WifiInterfaceInfo *pInfo = nullptr;
    MAP_INT_INTERFACEINFO::iterator itor = m_interfaceMap.begin();
    while (itor != m_interfaceMap.end()) {
        pInfo = itor->second;
        if (pInfo->name == ifaceName) {
            break;
        }
    }

    return pInfo;
}

bool WifiInterfaceManager::RemoveInterface(const int &id)
{
    MAP_INT_INTERFACEINFO::iterator itor = m_interfaceMap.begin();
    while (itor != m_interfaceMap.end()) {
        if (itor->second->id == id) {
            WifiInterfaceInfo *pInfo = itor->second;
            delete pInfo;
            pInfo = nullptr;
            break;
        }
    }

    m_interfaceMap.erase(id);
    return true;
}

bool WifiInterfaceManager::IsAnyInterfaceExist()
{
    if (m_interfaceMap.empty()) {
        return false;
    }

    return true;
}
}  // namespace Wifi
}  // namespace OHOS