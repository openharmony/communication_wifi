/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <random>
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "wifi_global_func.h"
#include "wifi_randommac_helper.h"
#ifndef OHOS_ARCH_LITE
#include "display_info.h"
#endif
DEFINE_WIFILOG_LABEL("WifiConfigCenter");

namespace OHOS {
namespace Wifi {
#ifdef DTFUZZ_TEST
static WifiConfigCenter* gWifiConfigCenter = nullptr;
#endif
WifiConfigCenter &WifiConfigCenter::GetInstance()
{
#ifdef DTFUZZ_TEST
    if (gWifiConfigCenter == nullptr) {
        gWifiConfigCenter = new (std::nothrow) WifiConfigCenter();
    }
    if (gWifiConfigCenter == nullptr) {
        static WifiConfigCenter gWifiConfigCenter;
        return gWifiConfigCenter;
    }
    return *gWifiConfigCenter;
#else
    static WifiConfigCenter gWifiConfigCenter;
    return gWifiConfigCenter;
#endif
}

WifiConfigCenter::WifiConfigCenter()
{
    mWifiState.emplace(0, static_cast<int>(WifiState::DISABLED));
    mWifiDetailState.emplace(0, WifiDetailState::STATE_INACTIVE);
    mStaMidState.emplace(0, WifiOprMidState::CLOSED);
    mWifiCloseTime.emplace(0, std::chrono::steady_clock::now());
    mIsAncoConnected.emplace(0, false);
    mWifiIpInfo.emplace(0, IpInfo());
    mWifiIpV6Info.emplace(0, IpV6Info());
    mWifiLinkedInfo.emplace(0, WifiLinkedInfo());
    mWifiMloLinkedInfo.emplace(0, std::vector<WifiLinkedInfo>());
    mLastSelectedNetworkId.emplace(0, INVALID_NETWORK_ID);
    mLastSelectedTimeVal.emplace(0, time(NULL));
    mBssidToTimeoutTime.emplace(0, std::make_pair("", 0));
    mLastDiscReason.emplace(0, DisconnectedReason::DISC_REASON_DEFAULT);
    mScanMidState.emplace(0, WifiOprMidState::CLOSED);
    mScanOnlyMidState.emplace(0, WifiOprMidState::CLOSED);
    mApMidState.emplace(0, WifiOprMidState::CLOSED);
    mHotspotState.emplace(0, static_cast<int>(ApState::AP_STATE_CLOSED));
    powerModel.emplace(0, PowerModel::GENERAL);
}

WifiConfigCenter::~WifiConfigCenter()
{}

int WifiConfigCenter::Init()
{
    if (WifiSettings::GetInstance().Init() < 0) {
        WIFI_LOGE("Init wifi settings failed!");
        return -1;
    }
    wifiScanConfig = std::make_unique<WifiScanConfig>();
    ClearLocalHid2dInfo();
    if (systemMode_ == SystemMode::M_FACTORY_MODE) {
        mPersistWifiState[INSTID_WLAN0] = WIFI_STATE_DISABLED;
    } else {
        mPersistWifiState[INSTID_WLAN0] = WifiSettings::GetInstance().GetOperatorWifiType(INSTID_WLAN0);
    }
    mAirplaneModeState = WifiSettings::GetInstance().GetLastAirplaneMode();
    return 0;
}

std::unique_ptr<WifiScanConfig>& WifiConfigCenter::GetWifiScanConfig()
{
    if (wifiScanConfig == nullptr) {
        wifiScanConfig = std::make_unique<WifiScanConfig>();
    }
    return wifiScanConfig;
}

void WifiConfigCenter::SetWifiSelfcureReset(const bool isReset)
{
    mWifiSelfcureReset = isReset;
}

bool WifiConfigCenter::GetWifiSelfcureReset() const
{
    return mWifiSelfcureReset.load();
}

void WifiConfigCenter::SetWifiSelfcureResetEntered(const bool isReset)
{
    mWifiSelfcureResetEntered = isReset;
}

bool WifiConfigCenter::GetWifiSelfcureResetEntered() const
{
    return mWifiSelfcureResetEntered.load();
}

void WifiConfigCenter::SetLastNetworkId(const int networkId)
{
    mLastNetworkId = networkId;
}

int WifiConfigCenter::GetLastNetworkId() const
{
    return mLastNetworkId.load();
}

void WifiConfigCenter::SetSelectedCandidateNetworkId(const int networkId)
{
    mSelectedCandidateNetworkId = networkId;
}

int WifiConfigCenter::GetSelectedCandidateNetworkId() const
{
    return mSelectedCandidateNetworkId.load();
}

void WifiConfigCenter::SetWifiAllowSemiActive(bool isAllowed)
{
    mWifiAllowSemiActive = isAllowed;
}

bool WifiConfigCenter::GetWifiAllowSemiActive() const
{
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
        WIFI_LOGI("factory mode, not allow semi active.");
        return false;
    }
    return mWifiAllowSemiActive.load();
}

void WifiConfigCenter::SetWifiStopState(bool state)
{
    mWifiStoping = state;
}

bool WifiConfigCenter::GetWifiStopState() const
{
    return mWifiStoping.load();
}

void WifiConfigCenter::SetStaIfaceName(const std::string &ifaceName, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mStaIfaceName[instId] = ifaceName;
}

std::string WifiConfigCenter::GetStaIfaceName(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    WIFI_LOGD("GetStaIfaceName instId:%{public}d mStaIfaceName[instId]:%{public}s ",
        instId, mStaIfaceName[instId].c_str());
    return mStaIfaceName[instId];
}

int WifiConfigCenter::GetWifiState(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiState.find(instId);
    if (iter != mWifiState.end()) {
        return iter->second.load();
    }
    mWifiState[instId] = static_cast<int>(WifiState::DISABLED);
    return mWifiState[instId].load();
}

int WifiConfigCenter::SetWifiState(int state, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiState[instId] = state;
    return 0;
}

WifiDetailState WifiConfigCenter::GetWifiDetailState(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDetailState.find(instId);
    if (iter != mWifiDetailState.end()) {
        return iter->second;
    }
    mWifiDetailState[instId] = WifiDetailState::STATE_UNKNOWN;
    return mWifiDetailState[instId];
}

int WifiConfigCenter::SetWifiDetailState(WifiDetailState state, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiDetailState[instId] = state;
    return 0;
}

WifiOprMidState WifiConfigCenter::GetWifiMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaMidState.find(instId);
    if (iter != mStaMidState.end()) {
        return iter->second.load();
    } else {
        mStaMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mStaMidState[instId].load();
    }
}

bool WifiConfigCenter::SetWifiMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    WIFI_LOGI("SetWifiMidState expState:%{public}d,state:%{public}d,instId:%{public}d",
        (int)expState, (int)state, instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaMidState.find(instId);
    if (iter != mStaMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mStaMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetWifiMidState(WifiOprMidState state, int instId)
{
    WIFI_LOGI("SetWifiMidState ,state:%{public}d,instId:%{public}d", (int)state, instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto ret = mStaMidState.emplace(instId, state);
    if (!ret.second) {
        mStaMidState[instId] = state;
    }
}

void WifiConfigCenter::SetWifiStaCloseTime(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiCloseTime[instId] = std::chrono::steady_clock::now();
}

double WifiConfigCenter::GetWifiStaInterval(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiCloseTime.find(instId);
    if (iter != mWifiCloseTime.end()) {
        std::chrono::steady_clock::time_point curr = std::chrono::steady_clock::now();
        double drMs = std::chrono::duration<double, std::milli>(curr - iter->second).count();
        return drMs;
    }

    return 0;
}

bool WifiConfigCenter::GetWifiConnectedMode(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    return mIsAncoConnected[instId].load();
}

void WifiConfigCenter::SetWifiConnectedMode(bool isAncoConnected, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mIsAncoConnected[instId] = isAncoConnected;
}


int WifiConfigCenter::SetChangeDeviceConfig(ConfigChange value, const WifiDeviceConfig &config)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mLastRemoveDeviceConfig = std::make_pair((int)value, config);
    return WIFI_OPT_SUCCESS;
}

bool WifiConfigCenter::GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    value = (ConfigChange)mLastRemoveDeviceConfig.first;
    config = mLastRemoveDeviceConfig.second;
    return true;
}

int WifiConfigCenter::GetIpInfo(IpInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiIpInfo.find(instId);
    if (iter != mWifiIpInfo.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiConfigCenter::SaveIpInfo(const IpInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiIpInfo[instId] = info;
    return 0;
}

int WifiConfigCenter::GetIpv6Info(IpV6Info &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiIpV6Info.find(instId);
    if (iter != mWifiIpV6Info.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiConfigCenter::SaveIpV6Info(const IpV6Info &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiIpV6Info[instId] = info;
    return 0;
}

std::map<int, WifiLinkedInfo> WifiConfigCenter::GetAllWifiLinkedInfo()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    return mWifiLinkedInfo;
}

int WifiConfigCenter::GetLinkedInfo(WifiLinkedInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiLinkedInfo.find(instId);
    if (iter != mWifiLinkedInfo.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiConfigCenter::SaveLinkedInfo(const WifiLinkedInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiLinkedInfo.find(instId);
    if (iter != mWifiLinkedInfo.end()) {
        WifiChannelWidth channelWidth = iter->second.channelWidth;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
        WifiRiskType riskType = iter->second.riskType;
#endif
        std::string bssid = iter->second.bssid;
        iter->second = info;
        if (bssid == info.bssid) {
            iter->second.channelWidth = channelWidth;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
            iter->second.riskType = riskType;
#endif
        }
    } else {
        mWifiLinkedInfo.emplace(instId, info);
    }

    return 0;
}

int WifiConfigCenter::GetMloLinkedInfo(std::vector<WifiLinkedInfo> &mloInfo, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiMloLinkedInfo.find(instId);
    if (iter != mWifiMloLinkedInfo.end()) {
        if (iter->second.size() != WIFI_MAX_MLO_LINK_NUM) {
            return -1;
        }
        mloInfo = iter->second;
    }
    return 0;
}

int WifiConfigCenter::SaveMloLinkedInfo(const std::vector<WifiLinkedInfo> &mloInfo, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiMloLinkedInfo[instId] = mloInfo;
    return 0;
}
int WifiConfigCenter::SetMacAddress(const std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mMacAddress[instId] = macAddress;
    return 0;
}

int WifiConfigCenter::GetMacAddress(std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mMacAddress.find(instId);
    if (iter != mMacAddress.end()) {
        macAddress = iter->second;
    }
    return 0;
}

void WifiConfigCenter::SetUserLastSelectedNetworkId(int networkId, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mLastSelectedNetworkId[instId] = networkId;
    mLastSelectedTimeVal[instId] = time(NULL);
}

int WifiConfigCenter::GetUserLastSelectedNetworkId(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastSelectedNetworkId.find(instId);
    if (iter != mLastSelectedNetworkId.end()) {
        return iter->second;
    }
    return -1;
}

time_t WifiConfigCenter::GetUserLastSelectedNetworkTimeVal(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastSelectedTimeVal.find(instId);
    if (iter != mLastSelectedTimeVal.end()) {
        return iter->second;
    }
    return 0;
}

std::string WifiConfigCenter::GetConnectTimeoutBssid(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mBssidToTimeoutTime.find(instId);
    if (iter != mBssidToTimeoutTime.end()) {
        const int timeout = 30; // 30s
        if (iter->second.second - static_cast<int>(time(NULL)) > timeout) {
            return "";
        }
        return iter->second.first;
    }
    return "";
}

int WifiConfigCenter::SetConnectTimeoutBssid(std::string &bssid, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    time_t now = time(nullptr);
    if (now == static_cast<time_t>(-1)) {
        LOGE("SetConnectTimeoutBssid: call time failed!");
        return -1;
    }
    mBssidToTimeoutTime[instId] = std::make_pair(bssid, static_cast<int>(now));
    return 0;
}

void WifiConfigCenter::SaveDisconnectedReason(DisconnectedReason discReason, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mLastDiscReason[instId] = discReason;
}

int WifiConfigCenter::GetDisconnectedReason(DisconnectedReason &discReason, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastDiscReason.find(instId);
    if (iter != mLastDiscReason.end()) {
        discReason = iter->second;
    }
    return 0;
}

void WifiConfigCenter::InsertWifiCategoryBlackListCache(int blacklistType, const std::string currentBssid,
    const WifiCategoryBlackListInfo wifiBlackListInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::map<std::string, WifiCategoryBlackListInfo> wifiBlackListCache;
    if (mWifiCategoryBlackListCache.find(blacklistType) != mWifiCategoryBlackListCache.end()) {
        wifiBlackListCache = mWifiCategoryBlackListCache[blacklistType];
    }
    auto iter = wifiBlackListCache.find(currentBssid);
    if (iter != wifiBlackListCache.end()) {
        iter->second = wifiBlackListInfo;
    } else {
        wifiBlackListCache.emplace(std::make_pair(currentBssid, wifiBlackListInfo));
    }
    mWifiCategoryBlackListCache[blacklistType] = wifiBlackListCache;
}

void WifiConfigCenter::RemoveWifiCategoryBlackListCache(int blacklistType, const std::string bssid)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mWifiCategoryBlackListCache.find(blacklistType) == mWifiCategoryBlackListCache.end()) {
        LOGE("%{public}s: dont exist wifi bla type", __func__);
        return;
    }
    std::map<std::string, WifiCategoryBlackListInfo> wifiBlackListCache = mWifiCategoryBlackListCache[blacklistType];
    if (wifiBlackListCache.find(bssid) != wifiBlackListCache.end()) {
        wifiBlackListCache.erase(bssid);
        mWifiCategoryBlackListCache[blacklistType] = wifiBlackListCache;
    } else {
        LOGE("%{public}s: don't exist wifi bla list, bssid: %{public}s", __func__, MacAnonymize(bssid).c_str());
        return;
    }
}

int WifiConfigCenter::GetWifiCategoryBlackListCache(int blacklistType,
    std::map<std::string, WifiCategoryBlackListInfo> &blackListCache)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mWifiCategoryBlackListCache.find(blacklistType) == mWifiCategoryBlackListCache.end()) {
        LOGE("%{public}s: dont exist wifi bla type", __func__);
        return -1;
    }
    blackListCache = mWifiCategoryBlackListCache[blacklistType];
    return 0;
}

void WifiConfigCenter::UpdateWifiConnectFailListCache(int blacklistType, const std::string bssid,
    const WifiCategoryConnectFailInfo wifiConnectFailInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiConnectFailCache.find(bssid);
    if (iter != mWifiConnectFailCache.end()
        && iter->second.actionType >= wifiConnectFailInfo.actionType) {
        iter->second.connectFailTimes++;
    } else {
        mWifiConnectFailCache[bssid] = wifiConnectFailInfo;
    }
}

void WifiConfigCenter::RemoveWifiConnectFailListCache(const std::string bssid)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mWifiConnectFailCache.find(bssid) != mWifiConnectFailCache.end()) {
        mWifiConnectFailCache.erase(bssid);
    } else {
        LOGE("%{public}s: don't exist wifi connect fail list, bssid: %{public}s",
            __func__, MacAnonymize(bssid).c_str());
        return;
    }
}

int WifiConfigCenter::GetWifiConnectFailListCache(std::map<std::string,
    WifiCategoryConnectFailInfo> &connectFailCache)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    connectFailCache = mWifiConnectFailCache;
    return 0;
}

bool WifiConfigCenter::EnableNetwork(int networkId, bool disableOthers, int instId)
{
    if (disableOthers) {
        SetUserLastSelectedNetworkId(networkId, instId);
    }
    return true;
}

WifiOprMidState WifiConfigCenter::GetScanMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanMidState.find(instId);
    if (iter != mScanMidState.end()) {
        return iter->second.load();
    } else {
        mScanMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mScanMidState[instId].load();
    }
}

bool WifiConfigCenter::SetScanMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanMidState.find(instId);
    if (iter != mScanMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mScanMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetScanMidState(WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto ret = mScanMidState.emplace(instId, state);
    if (!ret.second) {
        mScanMidState[instId] = state;
    }
}

WifiOprMidState WifiConfigCenter::GetWifiScanOnlyMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanOnlyMidState.find(instId);
    if (iter != mScanOnlyMidState.end()) {
        return iter->second.load();
    } else {
        mScanOnlyMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mScanOnlyMidState[instId].load();
    }
}

bool WifiConfigCenter::SetWifiScanOnlyMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanOnlyMidState.find(instId);
    if (iter != mScanOnlyMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mScanOnlyMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetWifiScanOnlyMidState(WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto ret = mScanOnlyMidState.emplace(instId, state);
    if (!ret.second) {
        mScanOnlyMidState[instId] = state;
    }
}

int WifiConfigCenter::SetWifiLinkedStandardAndMaxSpeed(WifiLinkedInfo &linkInfo)
{
    std::vector<WifiScanInfo> wifiScanInfoList;
    wifiScanConfig->GetScanInfoListInner(wifiScanInfoList);
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        if (iter->bssid == linkInfo.bssid) {
            linkInfo.wifiStandard = iter->wifiStandard;
            linkInfo.maxSupportedRxLinkSpeed = iter->maxSupportedRxLinkSpeed;
            linkInfo.maxSupportedTxLinkSpeed = iter->maxSupportedTxLinkSpeed;
            break;
        }
    }
    return 0;
}

void WifiConfigCenter::SetMloWifiLinkedMaxSpeed(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto mloIter = mWifiMloLinkedInfo.find(instId);
    if (mloIter == mWifiMloLinkedInfo.end()) {
        return;
    }
    if (mloIter->second.size() != WIFI_MAX_MLO_LINK_NUM) {
        return;
    }
    std::vector<WifiScanInfo> wifiScanInfoList;
    wifiScanConfig->GetScanInfoListInner(wifiScanInfoList);
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        for (auto& mloInfoItem : mWifiMloLinkedInfo[instId]) {
            if (iter->bssid == mloInfoItem.bssid) {
                mloInfoItem.maxSupportedRxLinkSpeed = iter->maxSupportedRxLinkSpeed;
                mloInfoItem.maxSupportedTxLinkSpeed = iter->maxSupportedTxLinkSpeed;
            }
        }
    }
}

bool WifiConfigCenter::CheckScanOnlyAvailable(int instId)
{
    return (WifiSettings::GetInstance().GetScanOnlySwitchState(instId)) && (GetAirplaneModeState() == MODE_STATE_CLOSE);
}

std::string WifiConfigCenter::GetConnectedBssid(int instId)
{
    WifiLinkedInfo linkedInfo;
    GetLinkedInfo(linkedInfo, instId);
    if (linkedInfo.connState == ConnState::CONNECTED) {
        return linkedInfo.bssid;
    }
    return "";
}

void WifiConfigCenter::SetSoftapToggledState(bool state)
{
    mSoftapToggled = state;
}

bool WifiConfigCenter::GetSoftapToggledState() const
{
    return mSoftapToggled.load();
}


int WifiConfigCenter::SetHotspotIdleTimeout(int time)
{
    mHotspotIdleTimeout = time;
    return 0;
}

int WifiConfigCenter::GetHotspotIdleTimeout() const
{
    return mHotspotIdleTimeout.load();
}

void WifiConfigCenter::SetApIfaceName(const std::string &ifaceName)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    mApIfaceName = ifaceName;
}

std::string WifiConfigCenter::GetApIfaceName()
{
    std::unique_lock<std::mutex> lock(mApMutex);
    return mApIfaceName;
}

WifiOprMidState WifiConfigCenter::GetApMidState(int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApMidState.find(id);
    if (iter != mApMidState.end()) {
        return iter->second.load();
    } else {
        mApMidState.emplace(id, WifiOprMidState::CLOSED);
        return mApMidState[id].load();
    }
}

bool WifiConfigCenter::SetApMidState(WifiOprMidState expState, WifiOprMidState state, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApMidState.find(id);
    if (iter != mApMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mApMidState.emplace(id, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetApMidState(WifiOprMidState state, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto ret = mApMidState.emplace(id, state);
    if (!ret.second) {
        mApMidState[id] = state;
    }
}

int WifiConfigCenter::GetHotspotState(int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mHotspotState.find(id);
    if (iter != mHotspotState.end()) {
        return iter->second.load();
    }
    mHotspotState[id] = static_cast<int>(ApState::AP_STATE_CLOSED);
    return mHotspotState[id].load();
}

int WifiConfigCenter::SetHotspotState(int state, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    mHotspotState[id] = state;
    return 0;
}

int WifiConfigCenter::SetPowerModel(const PowerModel& model, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto ret = powerModel.emplace(id, model);
    if (!ret.second) {
        powerModel[id] = model;
    }
    return 0;
}

int WifiConfigCenter::GetPowerModel(PowerModel& model, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = powerModel.find(id);
    if (iter != powerModel.end()) {
        model = iter->second;
    } else {
        powerModel[id] = PowerModel::GENERAL;
        model = powerModel[id];
    }
    return 0;
}

int WifiConfigCenter::GetStationList(std::vector<StationInfo> &results, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    for (auto iter = mConnectStationInfo.begin(); iter != mConnectStationInfo.end(); iter++) {
        results.push_back(iter->second);
    }
    return 0;
}

int WifiConfigCenter::ManageStation(const StationInfo &info, int mode, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mConnectStationInfo.find(info.bssid);
    if (mode == MODE_ADD || mode == MODE_UPDATE) {
        if (iter != mConnectStationInfo.end()) {
            iter->second = info;
        } else {
            mConnectStationInfo.emplace(std::make_pair(info.bssid, info));
        }
#ifdef SUPPORT_RANDOM_MAC_ADDR
        StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, info.bssid, "");
#endif
    } else if (mode == MODE_DEL) {
        if (iter != mConnectStationInfo.end()) {
            mConnectStationInfo.erase(iter);
        }
#ifdef SUPPORT_RANDOM_MAC_ADDR
        RemoveMacAddrPairInfo(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, info.bssid, info.bssidType);
#endif
    } else {
        return -1;
    }
    return 0;
}

int WifiConfigCenter::ClearStationList(int id)
{
#ifdef SUPPORT_RANDOM_MAC_ADDR
    ClearMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO);
#endif
    std::unique_lock<std::mutex> lock(mApMutex);
    mConnectStationInfo.clear();
    return 0;
}

void WifiConfigCenter::SetP2pIfaceName(const std::string &ifaceName)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mP2pIfaceName = ifaceName;
}

std::string WifiConfigCenter::GetP2pIfaceName()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    return mP2pIfaceName;
}

int WifiConfigCenter::SetHid2dUpperScene(int uid, const Hid2dUpperScene &scene)
{
    LOGD("SetHid2dUpperScene uid: %{public}d", uid);
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mHid2dUpperScenePair.insert_or_assign(uid, scene);
    if (scene.setTime != 0) {
        mHid2dSceneLastSetTime = scene.setTime;
    }
    return 0;
}

int WifiConfigCenter::GetHid2dUpperScene(int uid, Hid2dUpperScene &scene)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    auto iter = mHid2dUpperScenePair.find(uid);
    if (iter != mHid2dUpperScenePair.end()) {
        scene = iter->second;
    }
    return 0;
}

int WifiConfigCenter::SetHid2dSceneLastSetTime(int64_t setTime)
{
    mHid2dSceneLastSetTime = setTime;
    return 0;
}

int64_t WifiConfigCenter::GetHid2dSceneLastSetTime()
{
    return mHid2dSceneLastSetTime.load();
}

void WifiConfigCenter::ClearLocalHid2dInfo(int uid)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    Hid2dUpperScene scene;
    scene.mac = "";
    scene.scene = 0;
    scene.fps = 0;
    scene.bw = 0;
    if (uid != 0) {
        mHid2dUpperScenePair.insert_or_assign(uid, scene);
    } else {
        mHid2dUpperScenePair.insert_or_assign(SOFT_BUS_SERVICE_UID, scene);
        mHid2dUpperScenePair.insert_or_assign(CAST_ENGINE_SERVICE_UID, scene);
        mHid2dUpperScenePair.insert_or_assign(MIRACAST_SERVICE_UID, scene);
        mHid2dUpperScenePair.insert_or_assign(SHARE_SERVICE_UID, scene);
        mHid2dUpperScenePair.insert_or_assign(MOUSE_CROSS_SERVICE_UID, scene);
        SetHid2dSceneLastSetTime(0);
    }
}

int WifiConfigCenter::SetLastConnStaFreq(int freq)
{
    lastConnStaFreq_.store(freq);
    return 0;
}

int WifiConfigCenter::GetLastConnStaFreq()
{
    return lastConnStaFreq_.load();
}

int WifiConfigCenter::SetP2pEnhanceState(int state)
{
    p2pEnhanceState_.store(state);
    return 0;
}

int WifiConfigCenter::GetP2pEnhanceState()
{
    return p2pEnhanceState_.load();
}

int WifiConfigCenter::SetP2pEnhanceFreq(int freq)
{
    p2pEnhanceFreq_.store(freq);
    return 0;
}

int WifiConfigCenter::GetP2pEnhanceFreq()
{
    return p2pEnhanceFreq_.load();
}

WifiOprMidState WifiConfigCenter::GetP2pMidState()
{
    return mP2pMidState.load();
}

bool WifiConfigCenter::SetP2pMidState(WifiOprMidState expState, WifiOprMidState state)
{
    return mP2pMidState.compare_exchange_strong(expState, state);
}

void WifiConfigCenter::SetP2pMidState(WifiOprMidState state)
{
    mP2pMidState = state;
}

int WifiConfigCenter::SetP2pState(int state)
{
    mP2pState = state;
    return 0;
}

int WifiConfigCenter::GetP2pState()
{
    return mP2pState.load();
}

int WifiConfigCenter::SetP2pDiscoverState(int state)
{
    mP2pDiscoverState = state;
    return 0;
}

int WifiConfigCenter::GetP2pDiscoverState()
{
    return mP2pDiscoverState.load();
}

int WifiConfigCenter::SetP2pBusinessType(const P2pBusinessType &type)
{
    mP2pBusinessType = type;
    return 0;
}

int WifiConfigCenter::GetP2pBusinessType(P2pBusinessType &type)
{
    type = mP2pBusinessType.load();
    return 0;
}

int WifiConfigCenter::SaveP2pCreatorUid(int uid)
{
    mP2pCreatorUid = uid;
    return 0;
}

int WifiConfigCenter::GetP2pCreatorUid()
{
    return mP2pCreatorUid.load();
}

void WifiConfigCenter::SetExplicitGroup(bool isExplicit)
{
    mExplicitGroup = isExplicit;
}

bool WifiConfigCenter::IsExplicitGroup(void)
{
    return mExplicitGroup.load();
}

int WifiConfigCenter::GetP2pInfo(WifiP2pLinkedInfo &linkedInfo)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    linkedInfo = mWifiP2pInfo;
    return 0;
}

int WifiConfigCenter::SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mWifiP2pInfo = linkedInfo;
    return 0;
}

void WifiConfigCenter::SetCurrentP2pGroupInfo(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    m_P2pGroupInfo = group;
}

WifiP2pGroupInfo WifiConfigCenter::GetCurrentP2pGroupInfo()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    return m_P2pGroupInfo;
}

void WifiConfigCenter::SetCoexSupport(bool isSupport)
{
    mIsSupportCoex = isSupport;
}

bool WifiConfigCenter::GetCoexSupport() const
{
    return mIsSupportCoex.load();
}

void WifiConfigCenter::SetScreenState(const int &state)
{
    mScreenState = state;
}

int WifiConfigCenter::GetScreenState() const
{
    return mScreenState.load();
}

void WifiConfigCenter::SetWlanPage(bool isWlanPage)
{
    isWlanPage_.store(isWlanPage);
}

bool WifiConfigCenter::IsWlanPage() const
{
    return isWlanPage_.load();
}

void WifiConfigCenter::SetThermalLevel(const int &level)
{
    mThermalLevel = level;
}

int WifiConfigCenter::GetThermalLevel() const
{
    return mThermalLevel.load();
}

void WifiConfigCenter::SetPowerIdelState(const int &state)
{
    mPowerIdelState = state;
}

int WifiConfigCenter::GetPowerIdelState() const
{
    return mPowerIdelState.load();
}

void WifiConfigCenter::SetGnssFixState(const int &state)
{
    mGnssFixState = state;
}

int WifiConfigCenter::GetGnssFixState() const
{
    return mGnssFixState.load();
}

void WifiConfigCenter::SetScanGenieState(const int &state)
{
    mScanGenieState = state;
}

int WifiConfigCenter::GetScanGenieState() const
{
    return mScanGenieState.load();
}

bool WifiConfigCenter::SetWifiStateOnAirplaneChanged(const int &state)
{
    mAirplaneModeState = state;
    WifiSettings::GetInstance().SetLastAirplaneMode(state);
    if (WifiSettings::GetInstance().GetWifiFlagOnAirplaneMode()) {
        if (GetPersistWifiState(INSTID_WLAN0) == WIFI_STATE_DISABLED) {
            return true;
        }
        if (GetPersistWifiState(INSTID_WLAN0) == WIFI_STATE_SEMI_ENABLED && state == MODE_STATE_OPEN) {
            SetPersistWifiState(WIFI_STATE_DISABLED, INSTID_WLAN0);
            return true;
        }
        return false;
    }
    if (state == MODE_STATE_OPEN) {
        if (GetPersistWifiState(INSTID_WLAN0) == WIFI_STATE_ENABLED) {
            WifiSettings::GetInstance().SetWifiDisabledByAirplane(true);
        }
        SetPersistWifiState(WIFI_STATE_DISABLED, INSTID_WLAN0);
    } else {
        if (WifiSettings::GetInstance().GetWifiDisabledByAirplane()) {
            SetPersistWifiState(WIFI_STATE_ENABLED, INSTID_WLAN0);
            WifiSettings::GetInstance().SetWifiDisabledByAirplane(false);
        }
    }
    return true;
}

int WifiConfigCenter::GetAirplaneModeState() const
{
    return mAirplaneModeState.load();
}

int WifiConfigCenter::GetWifiToggledEnable(int id)
{
    if (GetAirplaneModeState() == MODE_STATE_OPEN) {
        if (GetPersistWifiState(id) == WIFI_STATE_ENABLED) {
            return WIFI_STATE_ENABLED;
        }
        return WIFI_STATE_DISABLED;
    }
    if (GetPersistWifiState(id) != WIFI_STATE_ENABLED && GetWifiAllowSemiActive()) {
        return WIFI_STATE_SEMI_ENABLED;
    }
    return GetPersistWifiState(id);
}

void WifiConfigCenter::SetWifiToggledState(int state, int id)
{
    if (GetAirplaneModeState() == MODE_STATE_OPEN) {
        WifiSettings::GetInstance().SetWifiDisabledByAirplane(false);
        if (state == WIFI_STATE_ENABLED) {
            WifiSettings::GetInstance().SetWifiFlagOnAirplaneMode(true);
        } else {
            WifiSettings::GetInstance().SetWifiFlagOnAirplaneMode(false);
            state = WIFI_STATE_DISABLED;
        }
    }
    SetPersistWifiState(state, id);
}

void WifiConfigCenter::SetPowerSavingModeState(const int &state)
{
    mPowerSavingModeState = state;
}

int WifiConfigCenter::GetPowerSavingModeState() const
{
    return mPowerSavingModeState.load();
}

void WifiConfigCenter::SetFreezeModeState(int state)
{
    mFreezeModeState = state;
}

int WifiConfigCenter::GetFreezeModeState() const
{
    return mFreezeModeState.load();
}

void WifiConfigCenter::SetScanStyle(int scanStyle)
{
    scanStyle_ = scanStyle;
}
 
int WifiConfigCenter::GetScanStyle() const
{
    return scanStyle_.load();
}
 
void WifiConfigCenter::SetNoChargerPlugModeState(int state)
{
    mNoChargerPlugModeState = state;
}

int WifiConfigCenter::GetNoChargerPlugModeState() const
{
    return mNoChargerPlugModeState.load();
}

void WifiConfigCenter::SetThreadStatusFlag(bool state)
{
    if (state) {
        mThreadStartTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    mThreadStatusFlag_ = state;
}

bool WifiConfigCenter::GetThreadStatusFlag(void) const
{
    return mThreadStatusFlag_.load();
}

uint64_t WifiConfigCenter::GetThreadStartTime(void) const
{
    return mThreadStartTime.load();
}

bool WifiConfigCenter::StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr,
    const std::string &randomAddr)
{
    if (realMacAddr.empty()) {
        return false;
    }

    if (type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) {
        return false;
    }

    std::string randomMacAddr;
    if (randomAddr.empty()) {
        WifiRandomMacHelper::GenerateRandomMacAddressByBssid(realMacAddr, randomMacAddr);
    } else {
        randomMacAddr = randomAddr;
    }
    LOGD("%{public}s: type:%{public}d, address:%{private}s, randomAddr:%{private}s, randomMacAddr:%{private}s",
        __func__, type, realMacAddr.c_str(), randomAddr.c_str(), randomMacAddr.c_str());
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = realMacAddr;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    WifiMacAddrErrCode ret = AddMacAddrPairs(type, realMacAddrInfo, randomMacAddr);
    if (ret == WIFI_MACADDR_OPER_SUCCESS) {
        WifiMacAddrInfo randomMacAddrInfo;
        randomMacAddrInfo.bssid = randomMacAddr;
        randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
        AddMacAddrPairs(type, randomMacAddrInfo, realMacAddr);
    }
    return true;
}

std::string WifiConfigCenter::GetRandomMacAddr(WifiMacAddrInfoType type, std::string bssid)
{
    LOGD("%{public}s: query a random mac address, type:%{public}d, bssid:%{private}s",
        __func__, type, bssid.c_str());
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = bssid;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    std::string randomMacAddr = GetMacAddrPairs(type, realMacAddrInfo);
    if (!randomMacAddr.empty()) {
        LOGD("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, realMacAddrInfo.bssid.c_str(), realMacAddrInfo.bssidType, randomMacAddr.c_str());
        return randomMacAddr;
    } else {
        WifiMacAddrInfo randomMacAddrInfo;
        randomMacAddrInfo.bssid = bssid;
        randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
        randomMacAddr = GetMacAddrPairs(type, realMacAddrInfo);
        if (!randomMacAddr.empty()) {
            LOGD("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                __func__, randomMacAddrInfo.bssid.c_str(), randomMacAddrInfo.bssidType, randomMacAddr.c_str());
            return randomMacAddr;
        }
    }
    return "";
}

int WifiConfigCenter::RemoveMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    LOGD("remove a mac address pair, type:%{public}d, bssid:%{private}s, bssidType:%{public}d",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            DelMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            DelMacAddrPairs(mHotspotMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            DelMacAddrPairs(mP2pDeviceMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            DelMacAddrPairs(mP2pGroupsInfoMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            DelMacAddrPairs(mP2pCurrentgroupMacAddrPair, macAddrInfo);
            break;
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            return -1;
    }
    return 0;
}

std::string WifiConfigCenter::GetMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    LOGD("get a mac address pair, type:%{public}d, bssid:%{private}s, bssidType:%{public}d",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            return GetPairMacAddress(mWifiScanMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            return GetPairMacAddress(mHotspotMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            return GetPairMacAddress(mP2pDeviceMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            return GetPairMacAddress(mP2pGroupsInfoMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            return GetPairMacAddress(mP2pCurrentgroupMacAddrPair, macAddrInfo);
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            return "";
    }
    return "";
}

void WifiConfigCenter::ClearMacAddrPairs(WifiMacAddrInfoType type)
{
    LOGI("%{public}s type:%{public}d", __func__, type);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            mWifiScanMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            mHotspotMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            mP2pDeviceMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            mP2pGroupsInfoMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            mP2pCurrentgroupMacAddrPair.clear();
            break;
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
    }
    return;
}

bool WifiConfigCenter::HasWifiActive()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto &item : mWifiState) {
        int state = item.second.load();
        if (state == static_cast<int>(WifiState::ENABLING) || state == static_cast<int>(WifiState::ENABLED)) {
            LOGD("HasWifiActive: one wifi is active! instId:%{public}d", item.first);
            return true;
        }
    }
    LOGD("HasWifiActive: No wifi is active!");
    return false;
}

void WifiConfigCenter::UpdateLinkedInfo(int instId)
{
    std::vector<WifiScanInfo> wifiScanInfoList;
    wifiScanConfig->GetScanInfoListInner(wifiScanInfoList);
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        if (iter->bssid == mWifiLinkedInfo[instId].bssid) {
            if (mWifiLinkedInfo[instId].channelWidth == WifiChannelWidth::WIDTH_INVALID) {
                mWifiLinkedInfo[instId].channelWidth = iter->channelWidth;
            }
            mWifiLinkedInfo[instId].isHiLinkNetwork = iter->isHiLinkNetwork;
            if (iter->isHiLinkNetwork == HILINK_PRO_NETWORK) {
                mWifiLinkedInfo[instId].isHiLinkProNetwork = true;
            }
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
            mWifiLinkedInfo[instId].riskType = iter->riskType;
#endif
            break;
        }
    }
    WifiCategory category = wifiScanConfig->GetWifiCategoryRecord(mWifiLinkedInfo[instId].bssid);
    mWifiLinkedInfo[instId].supportedWifiCategory = category;
    LOGD("WifiSettings UpdateLinkedInfo.");
}

void WifiConfigCenter::SetPersistWifiState(int state, int instId)
{
    if (instId < 0 || instId >= STA_INSTANCE_MAX_NUM) {
        LOGE("SetPersistWifiState invalid instId %{public}d", instId);
        return;
    }
    mPersistWifiState.at(instId) = state;
    WifiSettings::GetInstance().SetOperatorWifiType(state, instId);
    LOGI("persist wifi state is %{public}d", state);
}

int WifiConfigCenter::GetPersistWifiState(int instId)
{
    if (instId < 0 || instId >= STA_INSTANCE_MAX_NUM) {
        LOGE("GetPersistWifiState invalid instId %{public}d", instId);
        return -1;
    }
    return mPersistWifiState.at(instId);
}

std::string WifiConfigCenter::GetPairMacAddress(std::map<WifiMacAddrInfo, std::string>& macAddrInfoMap,
    const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGD("%{public}s: find the record, realMacAddr:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        return iter->second;
    } else {
        LOGE("%{public}s: record not found, macaddr: %{public}s", __func__, MacAnonymize(macAddrInfo.bssid).c_str());
    }
    return "";
}

WifiMacAddrErrCode WifiConfigCenter::InsertMacAddrPairs(std::map<WifiMacAddrInfo, std::string>& macAddrInfoMap,
    const WifiMacAddrInfo &macAddrInfo, std::string& randomMacAddr)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGD("%{public}s: the record is existed, macAddr:%{private}s, bssidType:%{public}d, value:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        return WIFI_MACADDR_HAS_EXISTED;
    } else {
        macAddrInfoMap.insert(std::make_pair(macAddrInfo, randomMacAddr));
        LOGD("%{public}s: add a mac address pair, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
        return WIFI_MACADDR_OPER_SUCCESS;
    }
}

void WifiConfigCenter::DelMacAddrPairs(std::map<WifiMacAddrInfo, std::string>& macAddrInfoMap,
    const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        if (iter->second.empty()) {
            LOGI("%{public}s: invalid record, bssid:%{private}s, bssidType:%{public}d",
                __func__, iter->first.bssid.c_str(), iter->first.bssidType);
        } else {
            LOGD("%{public}s:find the record, realMacAddr:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        }
        macAddrInfoMap.erase(iter);
    }
}

void WifiConfigCenter::RemoveMacAddrPairInfo(WifiMacAddrInfoType type, std::string bssid, int bssidType)
{
    LOGD("%{public}s: remove a mac address pair, type:%{public}d, bssid:%{private}s",
        __func__, type, bssid.c_str());
    WifiMacAddrInfo randomMacAddrInfo;
    randomMacAddrInfo.bssid = GetRandomMacAddr(type, bssid);
    randomMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS == bssidType ? RANDOM_DEVICE_ADDRESS : REAL_DEVICE_ADDRESS;
    RemoveMacAddrPairs(type, randomMacAddrInfo);

    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = bssid;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS == bssidType ? REAL_DEVICE_ADDRESS : RANDOM_DEVICE_ADDRESS;
    RemoveMacAddrPairs(type, realMacAddrInfo);
}

WifiMacAddrErrCode WifiConfigCenter::AddMacAddrPairs(WifiMacAddrInfoType type,
    const WifiMacAddrInfo &macAddrInfo, std::string randomMacAddr)
{
    if ((type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) || macAddrInfo.bssid.empty()) {
        LOGE("%{public}s: invalid parameter, type:%{public}d, bssid:%{private}s",
            __func__, type, macAddrInfo.bssid.c_str());
        return WIFI_MACADDR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            return InsertMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            return InsertMacAddrPairs(mHotspotMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pDeviceMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pGroupsInfoMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pCurrentgroupMacAddrPair, macAddrInfo, randomMacAddr);
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            break;
    }
    return WIFI_MACADDR_INVALID_PARAM;
}

std::set<int> WifiConfigCenter::GetAllWifiLinkedNetworkId()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::set<int> wifiLinkedNetworkId;
    for (auto iter = mWifiLinkedInfo.begin(); iter != mWifiLinkedInfo.end(); iter++) {
        wifiLinkedNetworkId.insert(iter->second.networkId);
    }
    return wifiLinkedNetworkId;
}

void WifiConfigCenter::SetSystemMode(int systemMode)
{
    systemMode_ = systemMode;
    LOGI("SetSystemMode %{public}d", systemMode_);
}

int WifiConfigCenter::GetSystemMode()
{
    WIFI_LOGD("GetSystemMode %{public}d", systemMode_);
    return systemMode_;
}

void WifiConfigCenter::SetDeviceType(int deviceType)
{
    mDeviceType = deviceType;
}

int WifiConfigCenter::GetDeviceType()
{
    return mDeviceType;
}

bool WifiConfigCenter::IsAllowPopUp()
{
    switch (mDeviceType) {
        case ProductDeviceType::WEARABLE:
            LOGI("Not allow pop up dialog, device type:%{public}d", mDeviceType);
            return false;
        default:
            LOGD("Allow pop up dialog, device type:%{public}d", mDeviceType);
            return true;
    }
}

bool WifiConfigCenter::IsAllowPcPopUp()
{
    switch (mDeviceType) {
        case ProductDeviceType::PC:
            LOGI("Not allow pop up dialog, device type:%{public}d", mDeviceType);
            return false;
        default:
            LOGD("Allow pop up dialog, device type:%{public}d", mDeviceType);
            return true;
    }
}

bool WifiConfigCenter::IsNeedFastScan(void)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    return isNeedFastScan;
}

void WifiConfigCenter::SetFastScan(bool fastScan)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    isNeedFastScan = fastScan;
}
 
int WifiConfigCenter::GetLocalOnlyHotspotConfig(HotspotConfig &hotspotConfig)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    hotspotConfig = localOnlyHotspotConfig_;
    return 0;
}
 
void WifiConfigCenter::SetLocalOnlyHotspotConfig(const HotspotConfig &hotspotConfig)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    localOnlyHotspotConfig_ = hotspotConfig;
}

void WifiConfigCenter::SetNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    networkControlInfoRecord = networkControlInfo;
}
 
WifiNetworkControlInfo WifiConfigCenter::GetNetworkControlInfo()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    return networkControlInfoRecord;
}

void WifiConfigCenter::SetDfsControlData(DfsControlData dfsControlData)
{
    dfsControlData_ = dfsControlData;
}
 
DfsControlData WifiConfigCenter::GetDfsControlData()
{
    return dfsControlData_;
}

void WifiConfigCenter::SetBrowserState(bool browser)
{
    browserOn_ = browser;
}
 
bool WifiConfigCenter::GetBrowserState()
{
    return browserOn_;
}

bool WifiConfigCenter::IsSameKeyMgmt(std::string scanKeyMgmt, std::string keyMgmt)
{
    LOGI("IsSamekeyMgmt scanKeyMgmt:%{public}s, keyMgmt:%{public}s", scanKeyMgmt.c_str(), keyMgmt.c_str());
    if (scanKeyMgmt != "WPA-PSK+SAE") {
        if (scanKeyMgmt == keyMgmt) {
            return true;
        }
        if (scanKeyMgmt == "SAE" && keyMgmt == "WPA-PSK") {
            return true;
        }
        if (keyMgmt == "SAE" && scanKeyMgmt == "WPA-PSK") {
            return true;
        }
    } else {
        return IsSameKeyMgmt("SAE", keyMgmt) || IsSameKeyMgmt("WPA-PSK", keyMgmt);
    }
    return false;
}

#ifndef OHOS_ARCH_LITE
void WifiConfigCenter::SetScreenDispalyState(int32_t orientation)
{
    screenDisplayOrientation.store(orientation);
}
 
bool WifiConfigCenter::IsScreenLandscape()
{
    return screenDisplayOrientation.load() == static_cast<int32_t>(Rosen::DisplayOrientation::LANDSCAPE) ||
           screenDisplayOrientation.load() == static_cast<int32_t>(Rosen::DisplayOrientation::LANDSCAPE_INVERTED);
}
#endif
}  // namespace Wifi
}  // namespace OHOS
