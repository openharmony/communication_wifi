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

#include "self_cure_utils.h"
#include "net_conn_client.h"
#include "net_handle.h"
#include "netsys_controller.h"
#include "self_cure_common.h"
#include "self_cure_msg.h"
#include "wifi_logger.h"
#include "self_cure_state_machine.h"
#include "wifi_config_center.h"
#include "wifi_country_code_manager.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_chr_adapter.h"
#include <fstream>
#include <cstdlib>

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;
DEFINE_WIFILOG_LABEL("SelfCureUtils");
SelfCureUtils::SelfCureUtils()
{
    WIFI_LOGI("SelfCureUtils()");
}

SelfCureUtils::~SelfCureUtils()
{
    WIFI_LOGI("~SelfCureUtils()");
}

SelfCureUtils& SelfCureUtils::GetInstance()
{
    static SelfCureUtils instance;
    return instance;
}

void SelfCureUtils::RegisterDnsResultCallback()
{
    dnsResultCallback_ = std::make_unique<SelfCureDnsResultCallback>().release();
    int32_t regDnsResult = NetsysController::GetInstance().RegisterDnsResultCallback(dnsResultCallback_, 0);
    WIFI_LOGI("RegisterDnsResultCallback result = %{public}d", regDnsResult);
}

void SelfCureUtils::UnRegisterDnsResultCallback()
{
    WIFI_LOGI("UnRegisterDnsResultCallback");
    if (dnsResultCallback_ != nullptr) {
        NetsysController::GetInstance().UnregisterDnsResultCallback(dnsResultCallback_);
    }
}

int32_t SelfCureUtils::GetCurrentDnsFailedCounter()
{
    if (dnsResultCallback_ == nullptr) {
        WIFI_LOGE("dnsResultCallback_ is null");
        return -1;
    }
    return dnsResultCallback_->dnsFailedCounter_;
}

void SelfCureUtils::ClearDnsFailedCounter()
{
    if (dnsResultCallback_ == nullptr) {
        WIFI_LOGE("dnsResultCallback_ is null");
        return;
    }
    dnsResultCallback_->dnsFailedCounter_ = 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::OnDnsResultReport(uint32_t size,
    const std::list<NetsysNative::NetDnsResultReport> netDnsResultReport)
{
    int32_t wifiNetId = GetWifiNetId();
    int32_t defaultNetId = GetDefaultNetId();
    for (auto &it : netDnsResultReport) {
        int32_t netId = static_cast<int32_t>(it.netid_);
        int32_t targetNetId = netId > 0 ? netId : (defaultNetId > 0 ? defaultNetId : 0);
        if (wifiNetId > 0 && wifiNetId == targetNetId) {
            if (it.queryresult_ != 0) {
                dnsFailedCounter_++;
            }
        }
    }
    WIFI_LOGD("OnDnsResultReport, wifiNetId: %{public}d, defaultNetId: %{public}d, dnsFailedCounter_: %{public}d",
        wifiNetId, defaultNetId, dnsFailedCounter_);
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetWifiNetId()
{
    std::list<sptr<NetHandle>> netList;
    int32_t ret = NetConnClient::GetInstance().GetAllNets(netList);
    if (ret != 0) {
        return 0;
    }

    for (auto iter : netList) {
        NetAllCapabilities netAllCap;
        NetConnClient::GetInstance().GetNetCapabilities(*iter, netAllCap);
        if (netAllCap.bearerTypes_.count(BEARER_WIFI) > 0) {
            return iter->GetNetId();
        }
    }
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetDefaultNetId()
{
    NetHandle defaultNet;
    NetConnClient::GetInstance().GetDefaultNet(defaultNet);
    return defaultNet.GetNetId();
}

int32_t SelfCureUtils::GetSelfCureType(int32_t currentCureLevel)
{
    SelfCureType ret = SelfCureType::SCE_TYPE_INVALID;
    switch (currentCureLevel) {
        case WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC:
            ret = SelfCureType::SCE_TYPE_REASSOC;
            break;
        case WIFI_CURE_RESET_LEVEL_WIFI6:
            ret = SelfCureType::SCE_TYPE_WIFI6;
            break;
        case WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP:
            ret = SelfCureType::SCE_TYPE_STATIC_IP;
            break;
        case WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY:
            ret = SelfCureType::SCE_TYPE_MULTI_GW;
            break;
        case WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC:
            ret = SelfCureType::SCE_TYPE_RANDMAC;
            break;
        case WIFI_CURE_RESET_LEVEL_HIGH_RESET:
            ret = SelfCureType::SCE_TYPE_RESET;
            break;
        case WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON:
            ret = SelfCureType::SCE_TYPE_RESET_WIFI_ON;
            break;
        default:
            break;
    }
    return static_cast<int32_t>(ret);
}

std::string SelfCureUtils::GetNextIpAddr(const std::string& gateway, const std::string& currentAddr,
                                         const std::vector<std::string>& testedAddr)
{
    std::vector<uint32_t> ipAddr;
    if (gateway.empty() || currentAddr.empty() || testedAddr.size() ==0) {
        WIFI_LOGI("gateway is empty or currentAddr is empty or testedAddr.size() == 0");
        return "";
    }
    uint32_t newIp = 0;
    uint32_t getCnt = 1;
    ipAddr = TransIpAddressToVec(currentAddr);
    uint32_t iMAX = 250;
    uint32_t iMIN = 101;
    while (getCnt++ < GET_NEXT_IP_MAC_CNT) {
        std::vector<uint32_t> gwAddr;
        bool reduplicate = false;
        time_t now = time(nullptr);
        if (now >= 0) {
            srand(now);
        }
        uint32_t randomNum = 0;
        int32_t fd = open("/dev/random", O_RDONLY); /* Obtain the random number by reading /dev/random */
        if (fd > 0) {
            read(fd, &randomNum, sizeof(uint32_t));
        }
        close(fd);
        uint32_t rand = (randomNum > 0 ? randomNum : -randomNum) % 100;
        newIp = rand + iMIN;
        gwAddr = TransIpAddressToVec(gateway);
        if (newIp == (gwAddr[VEC_POS_3] & 0xFF) || newIp == (ipAddr[VEC_POS_3] & 0xFF)) {
            continue;
        }
        for (size_t i = 0; i < testedAddr.size(); i++) {
            std::vector<uint32_t> tmp = TransIpAddressToVec(testedAddr[i]);
            if (newIp == (tmp[VEC_POS_3] & 0xFF)) {
                reduplicate = true;
                break;
            }
        }
        if (newIp > 0 && !reduplicate) {
            break;
        }
    }
    if (newIp > 1 && newIp <= iMAX && getCnt < GET_NEXT_IP_MAC_CNT) {
        ipAddr[VEC_POS_3] = newIp;
        return TransVecToIpAddress(ipAddr);
    }
    return "";
}

void SelfCureUtils::UpdateSelfCureHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                              bool success)
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    auto now = std::chrono::system_clock::now();
    int64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        if (success) {
            historyInfo.staticIpSelfCureFailedCnt = 0;
            historyInfo.lastStaticIpSelfCureFailedTs = 0;
        } else {
            historyInfo.staticIpSelfCureFailedCnt += 1;
            historyInfo.lastStaticIpSelfCureFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if (success) {
            historyInfo.reassocSelfCureFailedCnt = 0;
            historyInfo.lastReassocSelfCureFailedTs = 0;
        } else {
            historyInfo.reassocSelfCureFailedCnt += 1;
            historyInfo.lastReassocSelfCureFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        if (success) {
            historyInfo.randMacSelfCureFailedCnt = 0;
            historyInfo.lastRandMacSelfCureFailedCntTs = 0;
        } else {
            historyInfo.randMacSelfCureFailedCnt += 1;
            historyInfo.lastRandMacSelfCureFailedCntTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        if (success) {
            historyInfo.resetSelfCureFailedCnt = 0;
            historyInfo.lastResetSelfCureFailedTs = 0;
        } else {
            historyInfo.resetSelfCureFailedCnt += 1;
            historyInfo.lastResetSelfCureFailedTs = currentMs;
        }
    }
}

void SelfCureUtils::UpdateSelfCureConnectHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                     bool success)
{
    auto now = std::chrono::system_clock::now();
    int64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if (success) {
            historyInfo.reassocSelfCureConnectFailedCnt = 0;
            historyInfo.lastReassocSelfCureConnectFailedTs = 0;
        } else {
            historyInfo.reassocSelfCureConnectFailedCnt += 1;
            historyInfo.lastReassocSelfCureConnectFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        if (success) {
            historyInfo.randMacSelfCureConnectFailedCnt = 0;
            historyInfo.lastRandMacSelfCureConnectFailedCntTs = 0;
        } else {
            historyInfo.randMacSelfCureConnectFailedCnt += 1;
            historyInfo.lastRandMacSelfCureConnectFailedCntTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        if (success) {
            historyInfo.resetSelfCureConnectFailedCnt = 0;
            historyInfo.lastResetSelfCureConnectFailedTs = 0;
        } else {
            historyInfo.resetSelfCureConnectFailedCnt += 1;
            historyInfo.lastResetSelfCureConnectFailedTs = currentMs;
        }
    }
}

bool AllowSelfCure(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel)
{
    auto now = std::chrono::system_clock::now();
    int64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if ((historyInfo.reassocSelfCureConnectFailedCnt == 0) ||
            ((historyInfo.reassocSelfCureConnectFailedCnt >= 1) &&
             ((currentMs - historyInfo.lastReassocSelfCureConnectFailedTs) > DELAYED_DAYS_LOW))) {
            return true;
        }
    } else {
        if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
            if ((historyInfo.resetSelfCureConnectFailedCnt == 0) ||
                ((historyInfo.resetSelfCureConnectFailedCnt >= 1) &&
                 ((currentMs - historyInfo.lastResetSelfCureConnectFailedTs) > DELAYED_DAYS_LOW))) {
                return true;
            }
        }
    }
    return false;
}

static bool DealStaticIp(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, int64_t currentMs)
{
    if (historyInfo.staticIpSelfCureFailedCnt <= SELF_CURE_FAILED_FOUR_CNT ||
        (historyInfo.staticIpSelfCureFailedCnt == SELF_CURE_FAILED_FIVE_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.staticIpSelfCureFailedCnt == SELF_CURE_FAILED_SIX_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.staticIpSelfCureFailedCnt >= SELF_CURE_FAILED_SEVEN_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_HIGH))) {
        return true;
    }
    return false;
}

static bool DealMiddleReassoc(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, int64_t currentMs)
{
    if ((historyInfo.reassocSelfCureFailedCnt == 0 ||
        (historyInfo.reassocSelfCureFailedCnt == SELF_CURE_FAILED_ONE_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.reassocSelfCureFailedCnt == SELF_CURE_FAILED_TWO_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.reassocSelfCureFailedCnt >= SELF_CURE_FAILED_THREE_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_HIGH))) &&
        AllowSelfCure(historyInfo, requestCureLevel)) {
        return true;
    }
    return false;
}

static bool DealRandMacReassoc(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, int64_t currentMs)
{
    if (historyInfo.randMacSelfCureFailedCnt < SELF_CURE_RAND_MAC_MAX_COUNT) {
        return true;
    }
    return false;
}

static bool DealHighReset(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, int64_t currentMs)
{
    if ((historyInfo.resetSelfCureFailedCnt <= SELF_CURE_FAILED_ONE_CNT ||
        (historyInfo.resetSelfCureFailedCnt == SELF_CURE_FAILED_TWO_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.resetSelfCureFailedCnt == SELF_CURE_FAILED_THREE_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.resetSelfCureFailedCnt >= SELF_CURE_FAILED_FOUR_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_HIGH))) &&
        AllowSelfCure(historyInfo, requestCureLevel)) {
        return true;
    }
    return false;
}

bool SelfCureUtils::SelfCureAcceptable(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel)
{
    auto now = std::chrono::system_clock::now();
    int64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (currentMs <= 0) {
        WIFI_LOGE("Get current time error");
    }
    bool ifAcceptable = false;
    switch (requestCureLevel) {
        case WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP:
            ifAcceptable = DealStaticIp(historyInfo, WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC:
            ifAcceptable = DealMiddleReassoc(historyInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC:
            ifAcceptable = DealRandMacReassoc(historyInfo, WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_HIGH_RESET:
            ifAcceptable = DealHighReset(historyInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET, currentMs);
            break;
        default:
            break;
    }
    return ifAcceptable;
}

std::vector<std::string> SelfCureUtils::TransStrToVec(std::string str, char c)
{
    size_t pos = 0;
    std::vector<std::string> vec;
    while ((pos = str.find(c)) != std::string::npos) {
        vec.push_back(str.substr(0, pos));
        str.erase(0, pos + 1);
    }
    vec.push_back(str);
    return vec;
}

std::string SelfCureUtils::TransVecToIpAddress(const std::vector<uint32_t>& vec)
{
    std::string address = "";
    if (vec.size() != IP_ADDR_SIZE) {
        return address;
    }
    std::ostringstream stream;
    stream << vec[VEC_POS_0] << "." << vec[VEC_POS_1] << "." << vec[VEC_POS_2] << "." << vec[VEC_POS_3];
    address = stream.str();
    return address;
}

std::vector<uint32_t> SelfCureUtils::TransIpAddressToVec(std::string addr)
{
    if (addr.empty()) {
        WIFI_LOGE("addr is empty");
        return {0, 0, 0, 0};
    }
    size_t pos = 0;
    std::vector<uint32_t> currAddr;
    while ((pos = addr.find('.')) != std::string::npos) {
        std::string addTmp = addr.substr(0, pos);
        currAddr.push_back(CheckDataLegal(addTmp));
        addr.erase(0, pos + 1);
    }
    currAddr.push_back(CheckDataLegal(addr));
    if (currAddr.size() != IP_ADDR_SIZE) {
        WIFI_LOGE("TransIpAddressToVec failed");
        return {0, 0, 0, 0};
    }
    return currAddr;
}

int SelfCureUtils::String2InternetSelfCureHistoryInfo(const std::string selfCureHistory,
                                                      WifiSelfCureHistoryInfo &info)
{
    WifiSelfCureHistoryInfo selfCureHistoryInfo;
    if (selfCureHistory.empty()) {
        WIFI_LOGE("InternetSelfCureHistoryInfo is empty!");
        info = selfCureHistoryInfo;
        return -1;
    }
    std::vector<std::string> histories = TransStrToVec(selfCureHistory, '|');
    if (histories.size() != SELFCURE_HISTORY_LENGTH) {
        WIFI_LOGE("self cure history length = %{public}lu", (unsigned long) histories.size());
        info = selfCureHistoryInfo;
        return -1;
    }
    if (SetSelfCureFailInfo(selfCureHistoryInfo, histories, SELFCURE_FAIL_LENGTH) != 0) {
        WIFI_LOGE("set self cure history information failed!");
    }
    if (SetSelfCureConnectFailInfo(selfCureHistoryInfo, histories, SELFCURE_FAIL_LENGTH) != 0) {
        WIFI_LOGE("set self cure connect history information failed!");
    }
    info = selfCureHistoryInfo;
    return 0;
}

int SelfCureUtils::SetSelfCureFailInfo(WifiSelfCureHistoryInfo &info,
                                       std::vector<std::string>& histories, int cnt)
{
    if (histories.empty() || histories.size() != SELFCURE_HISTORY_LENGTH || cnt != SELFCURE_FAIL_LENGTH) {
        WIFI_LOGE("SetSelfCureFailInfo return");
        return -1;
    }
    // 0 to 12 is history subscript, which record the selfcure failed info, covert array to calss member
    for (int i = 0; i < cnt; i++) {
        if (i == SelfCureHistoryOrder::POS_STATIC_IP_FAILED_CNT) {
            info.staticIpSelfCureFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_STATIC_IP_FAILED_TS) {
            info.lastStaticIpSelfCureFailedTs = CheckDataTolonglong(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_REASSOC_FAILED_CNT) {
            info.reassocSelfCureFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_REASSOC_FAILED_TS) {
            info.lastReassocSelfCureFailedTs = CheckDataTolonglong(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_RANDMAC_FAILED_CNT) {
            info.randMacSelfCureFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_RANDMAC_FAILED_TS) {
            info.lastRandMacSelfCureFailedCntTs = CheckDataTolonglong(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_RESET_FAILED_CNT) {
            info.resetSelfCureFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == SelfCureHistoryOrder::POS_RESET_FAILED_TS) {
            info.lastResetSelfCureFailedTs = CheckDataTolonglong(histories[i]);
        } else {
            WIFI_LOGE("SetSelfCureFailInfo, exception happen.");
        }
    }
    return 0;
}

int SelfCureUtils::SetSelfCureConnectFailInfo(WifiSelfCureHistoryInfo &info,
                                              std::vector<std::string>& histories, int cnt)
{
    if (histories.empty() || histories.size() != SELFCURE_HISTORY_LENGTH || cnt != SELFCURE_FAIL_LENGTH) {
        WIFI_LOGE("SetSelfCureFailInfo return");
        return -1;
    }
    // 12 to 17 is history subscript, which record the selfcure connect failed info, covert array to calss member
    for (int i = cnt; i < SELFCURE_HISTORY_LENGTH; i++) {
        if (i == POS_REASSOC_CONNECT_FAILED_CNT) {
            info.reassocSelfCureConnectFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == POS_REASSOC_CONNECT_FAILED_TS) {
            info.lastReassocSelfCureConnectFailedTs = CheckDataTolonglong(histories[i]);
        } else if (i == POS_RANDMAC_CONNECT_FAILED_CNT) {
            info.randMacSelfCureConnectFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == POS_RANDMAC_CONNECT_FAILED_TS) {
            info.lastRandMacSelfCureConnectFailedCntTs = CheckDataTolonglong(histories[i]);
        } else if (i == POS_RESET_CONNECT_FAILED_CNT) {
            info.resetSelfCureConnectFailedCnt = CheckDataLegal(histories[i]);
        } else if (i == POS_RESET_CONNECT_FAILED_TS) {
            info.lastResetSelfCureConnectFailedTs = CheckDataTolonglong(histories[i]);
        } else {
            WIFI_LOGE("SetSelfCureConnectFailInfo, exception happen.");
        }
    }
    return 0;
}

bool SelfCureUtils::IsIpConflictDetect()
{
    WIFI_LOGI("IsIpConflictDetect enter");
    ArpChecker arpChecker;
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress);
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo);
    std::string targetIp = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    std::string senderIp = "0.0.0.0";
    if (targetIp.empty() || ifName.empty()) {
        WIFI_LOGE("targetIp or ifName is empty");
        return false;
    }
    arpChecker.Start(ifName, macAddress, senderIp, targetIp);
    for (int i = 0; i < DEFAULT_SLOW_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true)) {
            WIFI_LOGW("IsIpConflictDetect, ip conflicted!");
            return true;
        }
    }
    return false;
}

std::string SelfCureUtils::GetSelfCureHistory()
{
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("GetSelfCureHistory Get current link info failed!");
        return "";
    }
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(wifiLinkedInfo.networkId, config) != 0) {
        WIFI_LOGE("GetSelfCureHistory Get device config failed!, netId: %{public}d", wifiLinkedInfo.networkId);
        return "";
    }
    return config.internetSelfCureHistory;
}

void SelfCureUtils::ReportNoInternetChrEvent()
{
    WIFI_LOGI("ReportNoInternetChrEvent enter");
    std::string selfcureHistory = GetSelfCureHistory();
    int resetState = (WifiConfigCenter::GetInstance().GetWifiSelfcureResetEntered() ? 1 : 0);
    NetworkFailReason networkFailReason = NetworkFailReason::DNS_STATE_UNREACHABLE;
    if (IsIpConflictDetect()) {
        networkFailReason = NetworkFailReason::IP_STATE_CONFLICT;
    }
    EnhanceWriteWifiAccessIntFailedHiSysEvent(1, networkFailReason, resetState, selfcureHistory);
}

void SelfCureUtils::ReportIpv6ChrEvent()
{
    WIFI_LOGI("ReportIpv6ChrEvent enter");
    int64_t nowTime = GetElapsedMicrosecondsSinceBoot();
    if (lastReportIpv6Time_ > 0 &&
        (nowTime - lastReportIpv6Time_) < IPV6_CHR_EVENT_MIN_INTERVAL) {
        WIFI_LOGD("ReportIpv6ChrEvent too frequently, return");
        return;
    }
    lastReportIpv6Time_ = nowTime;
    // write sys event
    std::string selfcureHistory = GetSelfCureHistory();
    int resetState = (WifiConfigCenter::GetInstance().GetWifiSelfcureResetEntered() ? 1 : 0);
    EnhanceWriteWifiAccessIntFailedHiSysEvent(static_cast<int>(EventAccessInternetFailReason::IPV6_FAILED),
        NetworkFailReason::IPV6_STATE_FAILED_DISABLE, resetState, selfcureHistory);
}

bool SelfCureUtils::IsIpv6SelfCureSupported()
{
#ifdef FEATURE_IPV6_SELF_CURE
    if (WifiConfigCenter::GetInstance().GetDeviceType() != ProductDeviceType::PHONE) {
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool SelfCureUtils::HasIpv6Disabled(int instId)
{
    return ipv6Disabled_[instId];
}

void SelfCureUtils::SetIpv6Disabled(bool disabled, int instId)
{
    ipv6Disabled_[instId] = disabled;
}

bool SelfCureUtils::DisableIpv6(int instId)
{
    WIFI_LOGI("Attempting to disable IPv6 on instance %{public}d", instId);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName(instId);
    // write sys event
    std::string selfcureHistory = GetSelfCureHistory();
    int resetState = (WifiConfigCenter::GetInstance().GetWifiSelfcureResetEntered() ? 1 : 0);
    EnhanceWriteWifiAccessIntFailedHiSysEvent(static_cast<int>(EventAccessInternetFailReason::IPV6_FAILED),
        instId == 0 ? NetworkFailReason::IPV6_STATE_UNREACHABLE : NetworkFailReason::IPV6_STATE_UNREACHABLE_WLAN1,
        resetState, selfcureHistory);
    // Use NetManagerStandard API to disable IPv6 on WiFi interface
    int result = NetManagerStandard::NetsysController::GetInstance().SetEnableIpv6(ifName, 0);
    if (result == 0) {
        WIFI_LOGI("IPv6 disabled successfully on interface %{public}s", ifName.c_str());
        SetIpv6Disabled(true, instId);
        return true;
    } else {
        WIFI_LOGE("Failed to disable IPv6 on interface %{public}s, result: %{public}d", ifName.c_str(), result);
        SetIpv6Disabled(false, instId);
        return false;
    }
}

} // namespace Wifi
} // namespace OHOS