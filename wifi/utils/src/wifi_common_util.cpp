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

#include "wifi_common_util.h"
#include <sstream>
#include <iterator>
#include <regex>
#ifndef OHOS_ARCH_LITE
#include "app_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "common_timer_errors.h"
#endif
#include "wifi_logger.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonUtil");

constexpr int PRIFIX_IP_LEN = 3;
constexpr int PRIFIX_P2P_LEN = 3;
constexpr int PRIFIX_CHBA_LEN = 4;
constexpr int PRIFIX_WLAN1_LEN = 5;
constexpr int FREQ_2G_MIN = 2412;
constexpr int FREQ_2G_MAX = 2472;
constexpr int FREQ_5G_MIN = 5170;
constexpr int FREQ_5G_MAX = 5825;
constexpr int CHANNEL_14_FREQ = 2484;
constexpr int CHANNEL_14 = 14;
constexpr int CENTER_FREQ_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_5G_MIN = 34;
constexpr int MIN_24G_CHANNEL = 1;
constexpr int MAX_24G_CHANNEL = 13;
constexpr int MIN_5G_CHANNEL = 36;
constexpr int MAX_5G_CHANNEL = 165;
constexpr int FREQ_CHANNEL_1 = 2412;
constexpr int FREQ_CHANNEL_36 = 5180;
constexpr int SECOND_TO_MICROSECOND = 1000 * 1000;
constexpr int MICROSECOND_TO_NANOSECOND = 1000;
static std::pair<std::string, int> g_brokerProcessInfo;

static std::string DataAnonymize(const std::string str, const char delim,
    const char hiddenCh, const int startIdx = 0)
{
    std::string s = str;
    constexpr auto minDelimSize = 2;
    constexpr auto minKeepSize = 6;
    if (std::count(s.begin(), s.end(), delim) < minDelimSize) {
        if (s.size() <= minKeepSize) {
            return std::string(s.size(), hiddenCh);
        }
        auto idx1 = 2;
        const auto idx2 = static_cast<int>(s.size() - 4);
        while (idx1++ < idx2) {
            s[idx1] = hiddenCh;
        }
        return s;
    }

    std::string::size_type begin = s.find_first_of(delim);
    std::string::size_type end = s.find_last_of(delim);
    int idx = 0;
    while (idx++ < startIdx && begin < end) {
        begin = s.find_first_of(delim, begin + 1);
    }
    while (begin++ != end) {
        if (s[begin] != delim) {
            s[begin] = hiddenCh;
        }
    }
    return s;
}

std::string MacAnonymize(const std::string str)
{
    return DataAnonymize(str, ':', '*', 1);
}

std::string IpAnonymize(const std::string str)
{
    return DataAnonymize(str, '.', '*');
}

std::string SsidAnonymize(const std::string str)
{
    if (str.empty()) {
        return str;
    }

    std::string s = str;
    constexpr char hiddenChar = '*';
    constexpr size_t minHiddenSize = 3;
    constexpr size_t headKeepSize = 3;
    constexpr size_t tailKeepSize = 3;
    auto func = [hiddenChar](char& c) { c = hiddenChar; };
    if (s.size() < minHiddenSize) {
        std::for_each(s.begin(), s.end(), func);
        return s;
    }

    if (s.size() < (minHiddenSize + headKeepSize + tailKeepSize)) {
        size_t beginIndex = 1;
        size_t hiddenSize = s.size() - minHiddenSize + 1;
        hiddenSize = hiddenSize > minHiddenSize ? minHiddenSize : hiddenSize;
        std::for_each(s.begin() + beginIndex, s.begin() + beginIndex + hiddenSize, func);
        return s;
    }
    std::for_each(s.begin() + headKeepSize, s.begin() + s.size() - tailKeepSize, func);
    return s;
}

static unsigned char ConvertStrChar(char ch)
{
    constexpr int numDiffForHexAlphabet = 10;
    if (ch >= '0' && ch <= '9') {
        return (ch - '0');
    }
    if (ch >= 'A' && ch <= 'F') {
        return (ch - 'A' + numDiffForHexAlphabet);
    }
    if (ch >= 'a' && ch <= 'f') {
        return (ch - 'a' + numDiffForHexAlphabet);
    }
    return 0;
}

errno_t MacStrToArray(const std::string& strMac, unsigned char mac[WIFI_MAC_LEN])
{
    constexpr int strMacLen = 18;
    char tempArray[strMacLen] = { 0 };
    errno_t ret = memcpy_s(tempArray, strMacLen, strMac.c_str(), strMac.size() + 1);
    if (ret != EOK) {
        return ret;
    }

    int idx = 0;
    constexpr int bitWidth = 4;
    char *ptr = nullptr;
    char *p = strtok_s(tempArray, ":", &ptr);
    while ((p != nullptr) && (idx < WIFI_MAC_LEN)) {
        mac[idx++] = (ConvertStrChar(*p) << bitWidth) | ConvertStrChar(*(p + 1));
        p = strtok_s(nullptr, ":", &ptr);
    }
    return EOK;
}

static char ConvertArrayChar(unsigned char ch)
{
    constexpr int maxDecNum = 9;
    constexpr int numDiffForHexAlphabet = 10;
    if (ch <= maxDecNum) {
        return '0' + ch;
    }
    if (ch <= 0xf) {
        return ch + 'a' - numDiffForHexAlphabet;
    }
    return '0';
}

std::string MacArrayToStr(const unsigned char mac[WIFI_MAC_LEN])
{
    constexpr int bitWidth = 4;
    constexpr int noColonBit = 5;
    std::stringstream ss;
    for (int i = 0; i != WIFI_MAC_LEN; ++i) {
        ss << ConvertArrayChar(mac[i] >> bitWidth) << ConvertArrayChar(mac[i] & 0xf);
        if (i != noColonBit) {
            ss << ":";
        }
    }
    return ss.str();
}

bool IsMacArrayEmpty(const unsigned char mac[WIFI_MAC_LEN])
{
    for (int i = 0; i != WIFI_MAC_LEN; ++i) {
        if (mac[i] != 0) {
            return false;
        }
    }
    return true;
}

unsigned int Ip2Number(const std::string& strIp)
{
    std::string::size_type front = 0;
    std::string::size_type back = 0;
    unsigned int number = 0;
    int size = 32;
    constexpr int sectionSize = 8;

    std::string ip(strIp + '.');
    while ((back = ip.find_first_of('.', back)) != (std::string::size_type)std::string::npos) {
        number |= std::stol(ip.substr(front, back - front).c_str()) << (size -= sectionSize);
        front = ++back;
    }
    return number;
}

std::string Number2Ip(unsigned int intIp)
{
    constexpr int fourthPartMoveLen = 24;
    constexpr int thirdPartMoveLen = 16;
    constexpr int secondPartMoveLen = 8;

    std::string ip;
    ip.append(std::to_string((intIp & 0xff000000) >> fourthPartMoveLen));
    ip.push_back('.');
    ip.append(std::to_string((intIp & 0x00ff0000) >> thirdPartMoveLen));
    ip.push_back('.');
    ip.append(std::to_string((intIp & 0x0000ff00) >> secondPartMoveLen));
    ip.push_back('.');
    ip.append(std::to_string(intIp & 0x000000ff));
    return ip;
}

std::vector<std::string> StrSplit(const std::string& str, const std::string& delim) {
    std::regex re(delim);
    std::sregex_token_iterator
        first{ str.begin(), str.end(), re, -1 },
        last;
    return { first, last };
}

int64_t GetElapsedMicrosecondsSinceBoot()
{
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    return static_cast<int64_t>(times.tv_sec) * SECOND_TO_MICROSECOND + times.tv_nsec / MICROSECOND_TO_NANOSECOND;
}

#ifndef OHOS_ARCH_LITE
sptr<AppExecFwk::IBundleMgr> GetBundleManager()
{
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        WIFI_LOGE("Get system ability manager failed!");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(systemManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
}

std::string GetBundleName()
{
    sptr<AppExecFwk::IBundleMgr> bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        WIFI_LOGE("bundle instance is null!");
        return "";
    }

    AppExecFwk::BundleInfo bundleInfo;
    auto ret = bundleInstance->GetBundleInfoForSelf(0, bundleInfo);
    if (ret != OHOS::ERR_OK) {
        WIFI_LOGE("GetBundleInfoForSelf failed! ret[%{public}d]", ret);
        return "";
    }

    WIFI_LOGI("Get bundle name uid[%{public}d]: %{public}s", bundleInfo.uid, bundleInfo.name.c_str());
    return bundleInfo.name;
}

int GetCallingPid()
{
    return IPCSkeleton::GetCallingPid();
}

int GetCallingUid()
{
    return IPCSkeleton::GetCallingUid();
}

int GetCallingTokenId()
{
    return IPCSkeleton::GetCallingTokenID();
}

std::string GetBrokerProcessNameByPid(const int uid, const int pid)
{
    std::string processName = "";
    if (g_brokerProcessInfo.second == pid) {
        processName = g_brokerProcessInfo.first;
    }
    return processName;
}

void SetWifiBrokerProcess(int pid, std::string processName)
{
    WIFI_LOGD("enter SetWifiBrokerProcess");
    g_brokerProcessInfo = make_pair(processName, pid);
}

TimeStats::TimeStats(const std::string desc): m_desc(desc)
{
    m_startTime = std::chrono::steady_clock::now();
    WIFI_LOGI("[Time stats][start] %{public}s.", m_desc.c_str());
}

TimeStats::~TimeStats()
{
    auto us = std::chrono::duration_cast<std::chrono::microseconds>
        (std::chrono::steady_clock::now() - m_startTime).count();
    constexpr int TIME_BASE = 1000;
    WIFI_LOGI("[Time stats][end] %{public}s, time cost:%{public}lldus, %{public}lldms, %{public}llds",
        m_desc.c_str(), us, us / TIME_BASE, us / TIME_BASE / TIME_BASE);
}
#endif

int FrequencyToChannel(int freq)
{
    WIFI_LOGD("FrequencyToChannel: %{public}d", freq);
    int channel = INVALID_FREQ_OR_CHANNEL;
    if (freq >= FREQ_2G_MIN && freq <= FREQ_2G_MAX) {
        channel = (freq - FREQ_2G_MIN) / CENTER_FREQ_DIFF + CHANNEL_2G_MIN;
    } else if (freq == CHANNEL_14_FREQ) {
        channel = CHANNEL_14;
    } else if (freq >= FREQ_5G_MIN && freq <= FREQ_5G_MAX) {
        channel = (freq - FREQ_5G_MIN) / CENTER_FREQ_DIFF + CHANNEL_5G_MIN;
    }
    return channel;
}

int ChannelToFrequency(int channel)
{
    WIFI_LOGI("ChannelToFrequency: %{public}d", channel);
    if (channel >= MIN_24G_CHANNEL && channel <= MAX_24G_CHANNEL) {
        return ((channel - MIN_24G_CHANNEL) * CENTER_FREQ_DIFF + FREQ_CHANNEL_1);
    }
    if (MIN_5G_CHANNEL <= channel && channel <= MAX_5G_CHANNEL) {
        return ((channel - MIN_5G_CHANNEL) * CENTER_FREQ_DIFF + FREQ_CHANNEL_36);
    }
    return INVALID_FREQ_OR_CHANNEL;
}

bool IsOtherVapConnect()
{
    WIFI_LOGD("Enter IsOtherVapConnect");
    int n;
    int ret;
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    bool p2pOrHmlConnected = false;
    bool hotspotEnable = false;
    if (getifaddrs(&ifaddr) == -1) {
        WIFI_LOGE("getifaddrs failed, error is %{public}d", errno);
        return false;
    }
    for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        /* For an AF_INET interface address, display the address */
        int family = ifa->ifa_addr->sa_family;
        char ipAddress[NI_MAXHOST] = {0}; /* IP address storage */
        if (family == AF_INET) {
            ret = getnameinfo(ifa->ifa_addr,
                sizeof(struct sockaddr_in),
                ipAddress,
                NI_MAXHOST,
                nullptr,
                0,
                NI_NUMERICHOST);
            if (ret != 0) {
                WIFI_LOGE("getnameinfo() failed: %{public}s\n", gai_strerror(ret));
                return false;
            }
        }
        if (strncmp("192", ipAddress, PRIFIX_IP_LEN) != 0 && strncmp("172", ipAddress, PRIFIX_IP_LEN) != 0) {
            continue;
        }
        if ((strncmp("p2p", ifa->ifa_name, PRIFIX_P2P_LEN) == 0 ||
             strncmp("chba", ifa->ifa_name, PRIFIX_CHBA_LEN) == 0)) {
            p2pOrHmlConnected = true;
        }
        if (strncmp("wlan1", ifa->ifa_name, PRIFIX_WLAN1_LEN) == 0) {
            hotspotEnable = true;
        }
    }
    freeifaddrs(ifaddr);
    return p2pOrHmlConnected && hotspotEnable;
}

}  // namespace Wifi
}  // namespace OHOS
