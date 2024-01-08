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

#ifndef COMMUNICATION_WIFI_NETWORK_STATUS_HISTORY_MANAGER_H
#define COMMUNICATION_WIFI_NETWORK_STATUS_HISTORY_MANAGER_H

#include <string>
#include <cstdint>
namespace OHOS {
namespace Wifi {
enum class NetworkStatus {
    UNKNOWN,
    HAS_INTERNET,
    PORTAL,
    NO_INTERNET
};

class NetworkStatusHistoryManager {
public:

    /**
     * Insert the network status records
     * @param networkStatusHistory  historical network status records
     * @param networkStatus target network status;
     */
    static void Insert(uint32_t &networkStatusHistory, NetworkStatus networkStatus);

    /**
     * Update the network status records
     *
     * @param networkStatusHistory  historical network status records
     * @param networkStatus target status;
     */
    static void Update(uint32_t &networkStatusHistory, NetworkStatus networkStatus);

    /**
     * determine whether to access the internet based on historical network records;
     *
     * @param networkStatusHistory  historical network status records
     * @return whether to access the internet
     */
    static bool IsInternetAccessByHistory(uint32_t networkStatusHistory);

    /**
     * determine whether the access to internet recovery based on historical network records
     *
     * @param networkStatusHistory historical network status records
     * @return whether the access to internet recovery
     */
    static bool IsAllowRecoveryByHistory(uint32_t networkStatusHistory);

    /**
     * determine whether the network is portal based on historical network records
     *
     * @param networkStatusHistory
     * @return
     */
    static bool IsPortalByHistory(uint32_t networkStatusHistory);

    /**
     * determine whether the network has internet ever on historical network records
     *
     * @param networkStatusHistory
     * @return
     */
    static bool HasInternetEverByHistory(uint32_t networkStatusHistory);

    /**
     * determine whether the network has no networkStatus history on historical network records
     *
     * @param networkStatusHistory
     * @return
     */
    static bool IsEmptyNetworkStatusHistory(uint32_t networkStatusHistory);

    /**
     * to Display the networkStatus History;
     *
     * @param networkStatusHistory
     * @return
     */
    static std::string ToString(uint32_t networkStatusHistory);
private:

    /**
     * get the last network status of the network status records given.
     *
     * @param networkHistory historical network status records
     * @return the last network status
     */
    static NetworkStatus GetLastNetworkStatus(uint32_t networkHistory);

    /* the num of enum class NetworkStatus values */
    constexpr static int NETWORK_STATUS_NUM = 4;

    /*!
     * count different network Status records.
     *
     * @param networkStatusHistory historical network status records
     * @param counts 0: UNKNOWN,1:HAS_INTERNET,2:PORTAL,3:NO_INTERNET
     */
    static void CountNetworkStatus(uint32_t networkStatusHistory, int counts[NETWORK_STATUS_NUM]);

    /*!
     * the mask to get the network status from network status history.
     */
    constexpr static unsigned int NETWORK_STATUS_MASK = 0b11;

    /*!
     * the mask to limit the num of network status records.
     */
    constexpr static int NETWORK_STATUS_HISTORY_MAX_MASK = 0xfffff;

    /*!
     * wifi recovery percentage
     */
    constexpr static double RECOVERY_PERCENTAGE = 0.8;

    /**
     * number of bits occupied by each record
     */
    constexpr static int ITEM_BIT_NUM = 2;
};
}
}
#endif
