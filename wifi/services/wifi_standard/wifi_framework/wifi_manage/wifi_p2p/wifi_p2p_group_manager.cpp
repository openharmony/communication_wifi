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
#include "wifi_p2p_group_manager.h"
#include <algorithm>
#include "wifi_settings.h"
#include "wifi_logger.h"

    DEFINE_WIFILOG_P2P_LABEL("WifiP2pGroupManager");

namespace OHOS {
namespace Wifi {
WifiP2pGroupManager::WifiP2pGroupManager() : groupsInfo(), currentGroup(), groupMutex(), p2pConnInfo()
{}

void WifiP2pGroupManager::Initialize()
{
    std::unique_lock<std::mutex> lock(groupMutex);
    WifiSettings::GetInstance().GetWifiP2pGroupInfo(groupsInfo);
    WifiSettings::GetInstance().GetP2pInfo(p2pConnInfo);
}

void WifiP2pGroupManager::StashGroups()
{
    std::unique_lock<std::mutex> lock(groupMutex);
    RefreshGroupsFromCurrentGroup();
    WifiSettings::GetInstance().SetWifiP2pGroupInfo(groupsInfo);
}

bool WifiP2pGroupManager::AddGroup(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (*it == group) {
            return true;
        }
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WIFI_LOGD("%{public}s: add a group, Name:%{private}s", __func__, group.GetGroupName().c_str());
    AddMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, group);
#endif
    groupsInfo.push_back(group);
    return true;
}

bool WifiP2pGroupManager::AddOrUpdateGroup(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (*it == group) {
        #ifdef SUPPORT_RANDOM_MAC_ADDR
            WIFI_LOGD("%{public}s: remove a group, Name:%{private}s", __func__, group.GetGroupName().c_str());
            RemoveMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, group);
        #endif
            groupsInfo.erase(it);
            break;
        }
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WIFI_LOGD("%{public}s: add a group, Name:%{private}s", __func__, group.GetGroupName().c_str());
    AddMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, group);
#endif
    groupsInfo.push_back(group);
    return true;
}
bool WifiP2pGroupManager::RemoveGroup(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (*it == group) {
        #ifdef SUPPORT_RANDOM_MAC_ADDR
            WIFI_LOGD("%{public}s: remove a group, Name:%{private}s", __func__, group.GetGroupName().c_str());
            RemoveMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, group);
        #endif
            groupsInfo.erase(it);
            return true;
        }
    }
    return false;
}
int WifiP2pGroupManager::ClearAll()
{
    std::unique_lock<std::mutex> lock(groupMutex);
    int groupSize = groupsInfo.size();
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WIFI_LOGD("%{public}s: clear all group, size:%{public}d", __func__, groupSize);
    for (auto iter = groupsInfo.begin(); iter != groupsInfo.end(); ++iter) {
        RemoveMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, *iter);
    }
#endif
    groupsInfo.clear();
    return groupSize;
}

void WifiP2pGroupManager::UpdateWpaGroup(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (it->GetGroupName() == group.GetGroupName() &&
            it->GetOwner().GetDeviceAddress() == group.GetOwner().GetDeviceAddress()) {
            WIFI_LOGD("UpdateWpaGroup: ssid equal, return");
            return;
        }
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WIFI_LOGD("%{public}s: update wpa group, Name:%{private}s", __func__, group.GetGroupName().c_str());
    AddMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, group);
#endif
    groupsInfo.push_back(group);
}

int WifiP2pGroupManager::RemoveClientFromGroup(int networkId, const std::string &deviceAddress)
{
    WifiP2pDevice device;
    device.SetDeviceAddress(deviceAddress);

    std::unique_lock<std::mutex> lock(groupMutex);
    auto it = groupsInfo.begin();
    for (; it != groupsInfo.end(); ++it) {
        if (networkId == it->GetNetworkId()) {
            if (it->IsContainsDevice(device)) {
                it->RemoveClientDevice(device);
            }
            break;
        }
    }

    if (it != groupsInfo.end()) {
        const std::vector<WifiP2pDevice> &clients = it->GetClientDevices();
        return clients.size();
    } else {
        return -1;
    }
}

const std::vector<WifiP2pGroupInfo> &WifiP2pGroupManager::GetGroups()
{
    std::unique_lock<std::mutex> lock(groupMutex);
    RefreshGroupsFromCurrentGroup();
    return groupsInfo;
}

int WifiP2pGroupManager::GetNetworkIdFromClients(const WifiP2pDevice &device)
{
    std::string deviceAddr = device.GetDeviceAddress();
    std::transform(deviceAddr.begin(), deviceAddr.end(), deviceAddr.begin(), ::tolower);

    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        const std::vector<WifiP2pDevice> &clients = it->GetClientDevices();
        for (auto client = clients.begin(); client != clients.end(); client++) {
            std::string clientAddr = client->GetDeviceAddress();
            std::transform(clientAddr.begin(), clientAddr.end(), clientAddr.begin(), ::tolower);
            if (clientAddr == deviceAddr) {
                return it->GetNetworkId();
            }
        }
    }

    return -1;
}

int WifiP2pGroupManager::GetGroupNetworkId(const WifiP2pDevice &device)
{
    std::string deviceMac = device.GetDeviceAddress();
    std::transform(deviceMac.begin(), deviceMac.end(), deviceMac.begin(), ::tolower);
    std::string ownerMac;
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        ownerMac = it->GetOwner().GetDeviceAddress();
        std::transform(ownerMac.begin(), ownerMac.end(), ownerMac.begin(), ::tolower);
        if (deviceMac == ownerMac) {
            return it->GetNetworkId();
        }
    }
    return -1;
}
int WifiP2pGroupManager::GetGroupNetworkId(const WifiP2pDevice &device, const std::string &ssid)
{
    std::string deviceMac = device.GetDeviceAddress();
    std::transform(deviceMac.begin(), deviceMac.end(), deviceMac.begin(), ::tolower);
    std::string ownerMac;
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        ownerMac = it->GetOwner().GetDeviceAddress();
        std::transform(ownerMac.begin(), ownerMac.end(), ownerMac.begin(), ::tolower);
        if (deviceMac == ownerMac && ssid == it->GetGroupName()) {
            return it->GetNetworkId();
        }
    }
    return -1;
}
std::string WifiP2pGroupManager::GetGroupOwnerAddr(int netId)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (netId == it->GetNetworkId()) {
            return it->GetOwner().GetDeviceAddress();
        }
    }
    return "";
}
bool WifiP2pGroupManager::IsInclude(int netId)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    for (auto it = groupsInfo.begin(); it != groupsInfo.end(); ++it) {
        if (netId == it->GetNetworkId()) {
            return true;
        }
    }
    return false;
}

void WifiP2pGroupManager::RefreshGroupsFromCurrentGroup()
{
    for (auto &group : groupsInfo) {
        if (group == currentGroup) {
            group = currentGroup;
            break;
        }
    }
}

void WifiP2pGroupManager::RefreshCurrentGroupFromGroups()
{
    for (auto &group : groupsInfo) {
        if (group == currentGroup) {
            currentGroup.SetClientDevices(group.GetClientDevices());
            break;
        }
    }
}

void WifiP2pGroupManager::SaveP2pInfo(const WifiP2pLinkedInfo &linkedInfo)
{
    p2pConnInfo = linkedInfo;
}

const WifiP2pLinkedInfo &WifiP2pGroupManager::GetP2pInfo() const
{
    return p2pConnInfo;
}

void WifiP2pGroupManager::UpdateGroupsNetwork(std::map<int, WifiP2pGroupInfo> wpaGroups)
{
    std::unique_lock<std::mutex> lock(groupMutex);
    bool found = false;
    auto group = groupsInfo.begin();
    while (group != groupsInfo.end()) {
        found = false;
        for (auto wpaGroup = wpaGroups.begin(); wpaGroup != wpaGroups.end(); ++wpaGroup) {
            if (group->GetGroupName() == wpaGroup->second.GetGroupName() &&
                group->GetOwner().GetDeviceAddress() == wpaGroup->second.GetOwner().GetDeviceAddress()) {
                group->SetNetworkId(wpaGroup->second.GetNetworkId());
                found = true;
                break;
            }
        }
        /**
         * If the corresponding group cannot be found, the group has been deleted by the WPA.
         */
        if (!found) {
            WIFI_LOGI("The group has been deleted by the WPA.");
        #ifdef SUPPORT_RANDOM_MAC_ADDR
            RemoveMacAddrPairInfo(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, *group);
        #endif
            group = groupsInfo.erase(group);
        } else {
            group++;
        }
    }
}

void WifiP2pGroupManager::SetCurrentGroup(WifiMacAddrInfoType type, const WifiP2pGroupInfo &group)
{
    currentGroup = group;
    WifiSettings::GetInstance().SetCurrentP2pGroupInfo(group);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    AddMacAddrPairInfo(type, group);
#endif
    RefreshCurrentGroupFromGroups();
}

#ifdef SUPPORT_RANDOM_MAC_ADDR
void WifiP2pGroupManager::AddMacAddrPairInfo(WifiMacAddrInfoType type, const WifiP2pGroupInfo &group)
{
    WifiP2pDevice owner = group.GetOwner();
    WIFI_LOGD("%{public}s add mac address, type:%{public}d, GOName:%{private}s, addr:%{private}s, addrType:%{public}d",
        __func__, type, owner.GetDeviceName().c_str(),
        owner.GetDeviceAddress().c_str(), owner.GetDeviceAddressType());
    if (type == WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO) {
        std::string goRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
            WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, owner.GetDeviceAddress());
        WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, owner.GetDeviceAddress(), goRandomMacAddr);
        std::vector<WifiP2pDevice> clientVec = group.GetClientDevices();
        std::string gcRandomMacAddr;
        for (auto iter = clientVec.begin(); iter != clientVec.end(); ++iter) {
            gcRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
                WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, iter->GetDeviceAddress());
            WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, iter->GetDeviceAddress(), gcRandomMacAddr);
        }
    } else if (type == WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO) {
        std::string goRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
            WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, owner.GetDeviceAddress());
        if (!goRandomMacAddr.empty()) {
            WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, owner.GetDeviceAddress(), goRandomMacAddr);
            std::vector<WifiP2pDevice> clientVec = group.GetClientDevices();
            std::string gcRandomMacAddr;
            for (auto iter = clientVec.begin(); iter != clientVec.end(); ++iter) {
                gcRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
                    WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, iter->GetDeviceAddress());
                WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, iter->GetDeviceAddress(), gcRandomMacAddr);
            }
        } else {
            goRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
                WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, owner.GetDeviceAddress());
            WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, owner.GetDeviceAddress(), goRandomMacAddr);
            std::vector<WifiP2pDevice> clientVec = group.GetClientDevices();
            std::string gcRandomMacAddr;
            for (auto iter = clientVec.begin(); iter != clientVec.end(); ++iter) {
                gcRandomMacAddr = WifiSettings::GetInstance().GetRandomMacAddr(
                    WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, iter->GetDeviceAddress());
                WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(type, iter->GetDeviceAddress(), gcRandomMacAddr);
            }
        }
    } else {
        WIFI_LOGW("%{public}s invalid type:%{public}d", __func__, type);
    }
}

void WifiP2pGroupManager::RemoveMacAddrPairInfo(WifiMacAddrInfoType type, const WifiP2pGroupInfo &group)
{
    WifiP2pDevice owner = group.GetOwner();
    WIFI_LOGD("%{public}s del mac address, type:%{public}d, GOName:%{private}s, addr:%{private}s, addrType:%{public}d",
        __func__, type, owner.GetDeviceName().c_str(),
        owner.GetDeviceAddress().c_str(), owner.GetDeviceAddressType());
    WifiMacAddrInfo macAddrInfo;
    macAddrInfo.bssid = owner.GetDeviceAddress();
    macAddrInfo.bssidType = owner.GetDeviceAddressType();
    WifiSettings::GetInstance().RemoveMacAddrPairs(type, macAddrInfo);

    std::vector<WifiP2pDevice> clientVec = group.GetClientDevices();
    for (auto iter = clientVec.begin(); iter != clientVec.end(); ++iter) {
        WifiMacAddrInfo clientMacAddrInfo;
        clientMacAddrInfo.bssid = iter->GetDeviceAddress();
        clientMacAddrInfo.bssidType = iter->GetDeviceAddressType();
        WifiSettings::GetInstance().RemoveMacAddrPairs(type, clientMacAddrInfo);
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS
