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

#include "network_selection_utils.h"
#include "network_status_history_manager.h"
#include "wifi_common_util.h"

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
#include "wifi_logger.h"
#include "parameter.h"
#endif

namespace OHOS::Wifi::NetworkSelection {

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
DEFINE_WIFILOG_LABEL("NetworkSelectionUtils")
#endif

bool NetworkSelectionUtils::IsOpenNetwork(const NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_NONE;
};

bool NetworkSelectionUtils::IsOpenAndMaybePortal(const NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return IsOpenNetwork(networkCandidate) && !wifiDeviceConfig.noInternetAccess
        && NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory);
}

bool NetworkSelectionUtils::IsScanResultForOweNetwork(const NetworkCandidate &networkCandidate)
{
    return networkCandidate.interScanInfo.capabilities.find("OWE") != std::string::npos;
}

bool NetworkSelectionUtils::IsBlackListNetwork(const NetworkCandidate &networkCandidate)
{
    constexpr int maxRetryCount = 3;
    return networkCandidate.wifiDeviceConfig.connFailedCount >= maxRetryCount;
}

std::string NetworkSelectionUtils::GetNetworkCandidatesInfo(const std::vector<NetworkCandidate*> &networkCandidates)
{
    std::stringstream networkCandidatesInfo;
    networkCandidatesInfo << "[";
    for (std::size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i)->wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        networkCandidatesInfo << "\"" << networkCandidates.at(i)->ToString() << "\"";
        if (i < networkCandidates.size() - 1) {
            networkCandidatesInfo << ", ";
        }
    }
    networkCandidatesInfo << "]";
    return networkCandidatesInfo.str();
}

std::string NetworkSelectionUtils::GetScoreResultsInfo(const std::vector<ScoreResult> &scoreResults)
{
    std::stringstream scoreMsg;
    scoreMsg << "[ ";
    for (std::size_t i = 0; i < scoreResults.size(); i++) {
        scoreMsg << scoreResults.at(i).ToString();
        if (i < scoreResults.size() - 1) {
            scoreMsg << ", ";
        }
    }
    scoreMsg << " ]";
    return scoreMsg.str();
}

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
bool NetworkSelectionUtils::CheckDeviceTypeByVendorCountry()
{
    constexpr const char* VENDOR_COUNTRY_KEY = "const.cust.custPath";
    constexpr const char* VENDOR_COUNTRY_DEFAULT = "";
    constexpr const int32_t SYS_PARAMETER_SIZE = 256;
    constexpr const int32_t SYSTEM_PARAMETER_ERROR_CODE = 0;
    char param[SYS_PARAMETER_SIZE] = { 0 };
    int errorCode = GetParameter(VENDOR_COUNTRY_KEY, VENDOR_COUNTRY_DEFAULT, param, SYS_PARAMETER_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGE("get vendor country fail, errorCode: %{public}d", errorCode);
        return false;
    }

    WIFI_LOGI("vendor country: %{public}s, errorCode: %{public}d.", param, errorCode);
    auto iter = std::string(param).find("hwit");
    return iter != std::string::npos;
}
#endif
}
