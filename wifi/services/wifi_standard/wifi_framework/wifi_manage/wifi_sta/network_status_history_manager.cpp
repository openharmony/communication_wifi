/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include <sstream>
#include "network_status_history_manager.h"

namespace OHOS {
namespace Wifi {

constexpr int THRESHOLD_CHECKED_NUM = 2;
constexpr int SECOND_FROM_LAST = 1;
constexpr int THIRD_FROM_LAST = 2;

void NetworkStatusHistoryManager::Insert(uint32_t &networkStatusHistory, NetworkStatus networkStatus)
{
    networkStatusHistory =
        (networkStatusHistory << ITEM_BIT_NUM | static_cast<int>(networkStatus)) & NETWORK_STATUS_HISTORY_MAX_MASK;
}

void NetworkStatusHistoryManager::Update(uint32_t &networkStatusHistory, NetworkStatus networkStatus)
{
    networkStatusHistory = networkStatusHistory >> ITEM_BIT_NUM;
    Insert(networkStatusHistory, networkStatus);
}

NetworkStatus NetworkStatusHistoryManager::GetLastNetworkStatus(uint32_t networkHistory)
{
    return static_cast<NetworkStatus>(networkHistory & NETWORK_STATUS_MASK);
}

void NetworkStatusHistoryManager::CountNetworkStatus(uint32_t networkStatusHistory,
                                                     int counts[NETWORK_STATUS_NUM])
{
    while (networkStatusHistory != 0) {
        NetworkStatus networkStatus = GetLastNetworkStatus(networkStatusHistory);
        counts[static_cast<int>(networkStatus)]++;
        networkStatusHistory = networkStatusHistory >> ITEM_BIT_NUM;
    }
}

bool NetworkStatusHistoryManager::IsInternetAccessByHistory(uint32_t networkStatusHistory)
{
    int counts[NETWORK_STATUS_NUM] = {0};
    CountNetworkStatus(networkStatusHistory, counts);
    int checkedNum = counts[static_cast<int>(NetworkStatus::HAS_INTERNET)] +
        counts[static_cast<int>(NetworkStatus::PORTAL)] +
        counts[static_cast<int>(NetworkStatus::NO_INTERNET)];
    if (checkedNum == 0) {
        return false;
    }
    if (GetLastNetworkStatus(networkStatusHistory) == NetworkStatus::HAS_INTERNET) {
        return true;
    }
    if (checkedNum == THRESHOLD_CHECKED_NUM) {
        return GetLastNetworkStatus(networkStatusHistory >> SECOND_FROM_LAST *  ITEM_BIT_NUM) ==
        NetworkStatus::HAS_INTERNET;
    }
    return counts[static_cast<int>(NetworkStatus::HAS_INTERNET)] >= checkedNum * RECOVERY_PERCENTAGE;
}

bool NetworkStatusHistoryManager::IsAllowRecoveryByHistory(uint32_t networkStatusHistory)
{
    int counts[NETWORK_STATUS_NUM] = {0};
    CountNetworkStatus(networkStatusHistory, counts);
    int checkedNum = counts[static_cast<int>(NetworkStatus::HAS_INTERNET)] +
        counts[static_cast<int>(NetworkStatus::PORTAL)] +
        counts[static_cast<int>(NetworkStatus::NO_INTERNET)];
    if (checkedNum < THRESHOLD_CHECKED_NUM) {
        return false;
    }
    if (checkedNum == THRESHOLD_CHECKED_NUM) {
        /* get the second from last network status by shifting right */
        return GetLastNetworkStatus(networkStatusHistory >> SECOND_FROM_LAST * ITEM_BIT_NUM) ==
        NetworkStatus::HAS_INTERNET;
    }

    /* get the last networkStatus and get the second from last network status by shifting right */
    if (GetLastNetworkStatus(networkStatusHistory) != NetworkStatus::HAS_INTERNET &&
        GetLastNetworkStatus(networkStatusHistory >>  SECOND_FROM_LAST * ITEM_BIT_NUM) != NetworkStatus::HAS_INTERNET) {
        return false;
    }

    /* get the second from last and third from last network status by shifting right*/
    if (GetLastNetworkStatus(networkStatusHistory >> SECOND_FROM_LAST * ITEM_BIT_NUM) == NetworkStatus::HAS_INTERNET &&
        GetLastNetworkStatus(networkStatusHistory >> THIRD_FROM_LAST * ITEM_BIT_NUM) == NetworkStatus::HAS_INTERNET) {
        return true;
    }
    return counts[static_cast<int>(NetworkStatus::HAS_INTERNET)] >= checkedNum * RECOVERY_PERCENTAGE;
}

bool NetworkStatusHistoryManager::IsPortalByHistory(uint32_t networkStatusHistory)
{
    int counts[NETWORK_STATUS_NUM] = {0};
    CountNetworkStatus(networkStatusHistory, counts);
    return counts[static_cast<int>(NetworkStatus::PORTAL)] > 0;
}

bool NetworkStatusHistoryManager::HasInternetEverByHistory(uint32_t networkStatusHistory)
{
    int counts[NETWORK_STATUS_NUM] = {0};
    CountNetworkStatus(networkStatusHistory, counts);
    return counts[static_cast<int>(NetworkStatus::HAS_INTERNET)] > 0;
}

bool NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(uint32_t networkStatusHistory)
{
    return !networkStatusHistory;
}

std::string NetworkStatusHistoryManager::ToString(uint32_t networkStatusHistory)
{
    std::stringstream networkStatusString;
    while (networkStatusHistory != 0) {
        NetworkStatus networkStatus = GetLastNetworkStatus(networkStatusHistory);
        networkStatusString << static_cast<int>(networkStatus) << "/";
        networkStatusHistory = networkStatusHistory >> ITEM_BIT_NUM;
    }
    return networkStatusString.str();
}
}
}