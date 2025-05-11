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
#include "wifi_config_center.h"
#include "wifi_p2p_msg.h"
#include "wifi_logger.h"
#ifndef OHOS_ARCH_LITE
#include "block_connect_service.h"
#endif
#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
#include "parameter.h"
#endif

namespace OHOS::Wifi::NetworkSelection {
namespace {
constexpr int32_t SCAN_5GHZ_BAND = 2;
}

DEFINE_WIFILOG_LABEL("NetworkSelectionUtils")

bool NetworkSelectionUtils::IsOpenNetwork(const NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_NONE;
};

bool NetworkSelectionUtils::IsOpenAndMaybePortal(NetworkCandidate &networkCandidate,
    const std::string &filterName)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (!IsOpenNetwork(networkCandidate)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NOT_OPEN_NETWORK);
        return false;
    }
    if (wifiDeviceConfig.noInternetAccess) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NO_INTERNET);
        return false;
    }
    if (!NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::HAS_NETWORK_HISTORY);
        return false;
    }
    return true;
}

bool NetworkSelectionUtils::IsScanResultForOweNetwork(const NetworkCandidate &networkCandidate)
{
    return networkCandidate.interScanInfo.capabilities.find("OWE") != std::string::npos;
}

bool NetworkSelectionUtils::IsBlackListNetwork(const NetworkCandidate &networkCandidate)
{
#ifndef OHOS_ARCH_LITE
    return BlockConnectService::GetInstance().IsBssidMatchUnusableSet(networkCandidate.interScanInfo.bssid);
#else
    return false;
#endif
}

std::string NetworkSelectionUtils::GetNetworkCandidatesInfo(const std::vector<NetworkCandidate*> &networkCandidates,
    const std::string &filterName)
{
    std::stringstream networkCandidatesInfo;
    networkCandidatesInfo << "[";
    for (std::size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i)->wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        networkCandidatesInfo << "\"" << networkCandidates.at(i)->ToString(filterName) << "\"";
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

bool NetworkSelectionUtils::IsConfigOpenType(const NetworkCandidate &networkCandidate)
{
    return (IsOpenNetwork(networkCandidate) || NetworkSelectionUtils::IsScanResultForOweNetwork(networkCandidate)) &&
        !HasWepKeys(networkCandidate.wifiDeviceConfig);
}

bool NetworkSelectionUtils::HasWepKeys(const WifiDeviceConfig &wifiConfig)
{
    for (int32_t i = 0; i < WEPKEYS_SIZE; i++) {
        if (!wifiConfig.wepKeys[i].empty()) {
            return true;
        }
    }
    return false;
}

bool NetworkSelectionUtils::IsEnterprise(const NetworkCandidate &networkCandidate)
{
    auto &keyMgmt = networkCandidate.wifiDeviceConfig.keyMgmt;
    bool isEnterpriseSecurityType = (keyMgmt == KEY_MGMT_EAP) || (keyMgmt == KEY_MGMT_SUITE_B_192) ||
        (keyMgmt == KEY_MGMT_WAPI_CERT);
    auto &eap = networkCandidate.wifiDeviceConfig.wifiEapConfig.eap;
    return isEnterpriseSecurityType && (eap != EAP_METHOD_NONE);
}

bool NetworkSelectionUtils::IsConfigOpenOrEapType(const NetworkCandidate &networkCandidate)
{
    return IsConfigOpenType(networkCandidate) || IsEnterprise(networkCandidate);
}

bool NetworkSelectionUtils::IsSameFreqAsP2p(const NetworkCandidate &networkCandidate)
{
    WifiP2pGroupInfo group = WifiConfigCenter::GetInstance().GetCurrentP2pGroupInfo();
    auto &interScanInfo = networkCandidate.interScanInfo;
    int32_t p2pFrequency = group.GetFrequency();
    if (interScanInfo.band == SCAN_5GHZ_BAND && p2pFrequency == interScanInfo.frequency) {
        return true;
    } else {
        WIFI_LOGI("IsSameFreqAsP2p, p2p frequency:%{public}d and scanInfo frequency:%{public}d are not same",
            p2pFrequency, interScanInfo.frequency);
    }
    return false;
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
