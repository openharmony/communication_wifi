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
#include <fstream>
#include <sstream>
#include <iterator>
#include <regex>
#include <sstream>

#ifndef OHOS_ARCH_LITE
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
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
#include <cerrno>

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
constexpr int MICROSECOND_TO_NANOSECOND = 1000;
constexpr char HIDDEN_CHAR_SHOW_AS = '*';
constexpr int PASSWORD_MIN_LEN = 8;
constexpr int PASSWORD_NO_HIDDEN_LEN = 2;
constexpr int STRING_MAC_LEN = 18;

constexpr uint32_t BASE_BIN = 2;
constexpr uint32_t BASE_HEX = 16;
constexpr uint32_t MAX_INT32_LENGTH = 11; // -2147483648 ~ 2147483647
constexpr uint32_t MAX_INT64_LENGTH = 20; // -9223372036854775808 ~ 9223372036854775807
constexpr uint32_t MAX_UINT32_LENGTH = 10; // 0 ~ 4294967295
constexpr uint32_t MAX_INT32_LENGTH_BIN = 32;
constexpr uint32_t MAX_INT32_LENGTH_HEX = 8;

const uint32_t BASE64_UNIT_ONE_PADDING = 1;
const uint32_t BASE64_UNIT_TWO_PADDING = 2;
const uint32_t BASE64_SRC_UNIT_SIZE = 3;
const uint32_t BASE64_DEST_UNIT_SIZE = 4;

static std::pair<std::string, int> g_brokerProcessInfo;
static constexpr uint8_t STEP_2BIT = 2;
static constexpr uint8_t HEX_OFFSET = 4;
static constexpr char HEX_TABLE[] = "0123456789ABCDEF";

static BeaconLostInfo g_beaconLostInfo = {0, 0, "", 0, 0, 0};
static BeaconAbnormalInfo g_beaconAbnormalInfo = {0, 0, "", std::vector<uint8_t>(BEACON_LENGTH_RSSI)};

constexpr int BEACON_LOST_MIN_CNT = 5; // 12s/(3s/time)
constexpr int BEACON_LOST_MIN_CNT_OFF_SCREEN = 3;
constexpr int BEACON_ABN_MIN_CNT = 3; // 5s/(3s/time)

constexpr int IP_ADDRESS_FIRST_BYTE_OFFSET = 24;
constexpr int IP_ADDRESS_SECOND_BYTE_OFFSET = 16;
constexpr int IP_ADDRESS_THIRD_BYTE_OFFSET = 8;
constexpr int IP_ADDRESS_BYTE_LEN = 4;
constexpr int IP_ADDRESS_FIRST_BYTE_INDEX = 0;
constexpr int IP_ADDRESS_SECOND_BYTE_INDEX = 1;
constexpr int IP_ADDRESS_THIRD_BYTE_INDEX = 2;
constexpr int IP_ADDRESS_FOURTH_BYTE_INDEX = 3;
constexpr int32_t UID_CALLINGUID_TRANSFORM_DIVISOR = 200000;

constexpr int DEFAULT_USER_ID = 100;

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

std::string PassWordAnonymize(const std::string str)
{
    if (str.size() < PASSWORD_MIN_LEN) {
        WIFI_LOGE("Password should not shorter than 8");
        return "";
    }
    std::string s = str;
    auto func = [](char& c) { c = HIDDEN_CHAR_SHOW_AS; };
    std::for_each(s.begin() + PASSWORD_NO_HIDDEN_LEN, s.end() - PASSWORD_NO_HIDDEN_LEN, func);
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
    char tempArray[STRING_MAC_LEN] = { 0 };
    errno_t ret = memcpy_s(tempArray, STRING_MAC_LEN, strMac.c_str(), strMac.size() + 1);
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
    std::string::size_type start = 0;
    std::string::size_type end = 0;
    std::vector<std::string> subStrList;
    std::string ip(strIp + '.');
    while ((end = ip.find_first_of('.', start)) != (std::string::size_type)std::string::npos) {
        subStrList.push_back(ip.substr(start, end - start));
        start = end + 1;
    }

    unsigned int number = 0;
    if (subStrList.size() != IP_ADDRESS_BYTE_LEN) {
        WIFI_LOGE("ip address format check error");
        return number;
    }

    number = static_cast<unsigned long>(
        (CheckDataLegal(subStrList[IP_ADDRESS_FIRST_BYTE_INDEX]) << IP_ADDRESS_FIRST_BYTE_OFFSET) |
        (CheckDataLegal(subStrList[IP_ADDRESS_SECOND_BYTE_INDEX]) << IP_ADDRESS_SECOND_BYTE_OFFSET) |
        (CheckDataLegal(subStrList[IP_ADDRESS_THIRD_BYTE_INDEX]) << IP_ADDRESS_THIRD_BYTE_OFFSET) |
        CheckDataLegal(subStrList[IP_ADDRESS_FOURTH_BYTE_INDEX]));
    return number;
}

std::string Number2Ip(unsigned int intIp)
{
    std::string ip;
    ip.append(std::to_string((intIp & 0xff000000) >> IP_ADDRESS_FIRST_BYTE_OFFSET));
    ip.push_back('.');
    ip.append(std::to_string((intIp & 0x00ff0000) >> IP_ADDRESS_SECOND_BYTE_OFFSET));
    ip.push_back('.');
    ip.append(std::to_string((intIp & 0x0000ff00) >> IP_ADDRESS_THIRD_BYTE_OFFSET));
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

int64_t GetCurrentTimeSeconds()
{
    auto now = std::chrono::system_clock::now();
    auto nowMs = std::chrono::time_point_cast<std::chrono::seconds>(now);
    auto value = nowMs.time_since_epoch();
    return value.count();
}

int64_t GetCurrentTimeMilliSeconds()
{
    auto now = std::chrono::system_clock::now();
    auto nowMs = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto value = nowMs.time_since_epoch();
    return value.count();
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
        return "";
    }

    WIFI_LOGI("Get bundle name uid[%{public}d]: %{public}s", bundleInfo.uid, bundleInfo.name.c_str());
    return bundleInfo.name;
}

std::string GetBundleAppIdByBundleName(const int callingUid, const std::string &bundleName)
{
    int userId = static_cast<int32_t>(GetCallingUid() / UID_CALLINGUID_TRANSFORM_DIVISOR);
    sptr<AppExecFwk::IBundleMgr> bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        WIFI_LOGE("bundle instance is null!");
        return "";
    }
 
    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::GetBundleInfoFlag bundleInfoFlag = AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO;
    auto ret = bundleInstance->GetBundleInfoV9(bundleName, static_cast<int32_t>(bundleInfoFlag), bundleInfo, userId);
    if (ret != OHOS::ERR_OK) {
        return "";
    }
    return bundleInfo.signatureInfo.appIdentifier;
}

bool IsBundleInstalled(const std::string &bundleName)
{
    sptr<AppExecFwk::IBundleMgr> bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        WIFI_LOGE("bundle instance is null!");
        return false;
    }

    AppExecFwk::BundleInfo bundleInfo;
    bool isInstalled = bundleInstance->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
        bundleInfo, DEFAULT_USER_ID);
    WIFI_LOGI("Bundle %{public}s is Installed: %{public}d", bundleName.c_str(), isInstalled);
    return isInstalled;
}

ErrCode GetBundleNameByUid(const int uid, std::string &bundleName)
{
    sptr<AppExecFwk::IBundleMgr> bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        WIFI_LOGE("%{public}s bundle instance is null!", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    if (!bundleInstance->GetBundleNameForUid(uid, bundleName)) {
        WIFI_LOGD("%{public}s get bundleName failed", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode GetAllBundleName(std::vector<std::string> &bundleNameList)
{
    return WIFI_OPT_SUCCESS;
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

bool IsBeaconLost(std::string bssid, WifiSignalPollInfo checkInfo, int32_t screenState)
{
    const int64_t checkTime = checkInfo.timeStamp;
    const int checkRssi = checkInfo.signal;
    const unsigned int checkRxBytes = checkInfo.rxBytes;
    
    // 检查 BSSID、RSSI 和 RxBytes 是否与初始值一致
    if (g_beaconLostInfo.bssid != bssid || g_beaconLostInfo.rssi != checkRssi
        || g_beaconLostInfo.rxBytes != checkRxBytes || g_beaconLostInfo.screenState != screenState) {
        g_beaconLostInfo = { 0, 0, bssid, checkRssi, checkRxBytes, screenState };
        return false;
    }
    if (checkInfo.ext.size() < BEACON_LENGTH_RSSI) {
        g_beaconLostInfo.time = 0;
        g_beaconLostInfo.cnt = 0;
        return false;
    }
     // 检查 RSSI 是否无效
    const auto* extData = checkInfo.ext.data();
    bool isInvalid = std::all_of(extData, extData + BEACON_LENGTH_RSSI, [](uint8_t num) {
            int8_t val = static_cast<int8_t>(num);
            return val == BEACON_LOST_RSSI0 || val == BEACON_LOST_RSSI1 || val == 0;
        }) && std::any_of(extData, extData + BEACON_LENGTH_RSSI,
        [](uint8_t num) { return static_cast<int8_t>(num) == BEACON_LOST_RSSI0; });
    if (!isInvalid) {
        g_beaconLostInfo.time = 0;
        g_beaconLostInfo.cnt = 0;
        return false;
    }
    g_beaconLostInfo.cnt += 1;
    if (g_beaconLostInfo.time == 0) {
        g_beaconLostInfo.time = checkTime;
        return false;
    }
    int64_t accumulateTime = checkTime - g_beaconLostInfo.time;
    if (accumulateTime <= 0) {
        g_beaconLostInfo.time = checkTime;
        g_beaconLostInfo.cnt = 1;
        return false;
    }
    int64_t timePeriod = (screenState == MODE_STATE_OPEN) ? SIGNAL_RECORD_12S : SIGNAL_RECORD_3S;
    int32_t minCount = (screenState == MODE_STATE_OPEN) ? BEACON_LOST_MIN_CNT : BEACON_LOST_MIN_CNT_OFF_SCREEN;
    if (accumulateTime >= timePeriod && g_beaconLostInfo.cnt >= minCount) {
        g_beaconLostInfo.time = checkTime;
        g_beaconLostInfo.cnt = 1;
        return true;
    }
    return false;
}

bool IsBeaconAbnormal(std::string bssid, WifiSignalPollInfo checkInfo)
{
    const int64_t checkTime = checkInfo.timeStamp;
    // 检查 BSSID是否与初始值一致
    if (g_beaconAbnormalInfo.bssid != bssid) {
        g_beaconAbnormalInfo.bssid = bssid;
        g_beaconAbnormalInfo.time = 0;
        g_beaconAbnormalInfo.cnt = 0;
        return false;
    }
    if (checkInfo.ext.size() < BEACON_LENGTH_RSSI) {
        g_beaconAbnormalInfo.time = 0;
        g_beaconAbnormalInfo.cnt = 0;
        return false;
    }
    // 检查未平滑rssi数组是否相等
    bool areVectorsEqual = true;
    for (int i = 0; i < BEACON_LENGTH_RSSI; i++) {
        if (g_beaconAbnormalInfo.rssiArr[i] != checkInfo.ext[i]) {
            g_beaconAbnormalInfo.rssiArr[i] = checkInfo.ext[i];
            areVectorsEqual = false;
        }
    }
    if (!areVectorsEqual) {
        g_beaconAbnormalInfo.time = checkTime;
        g_beaconAbnormalInfo.cnt = 1;
        return false;
    }
    g_beaconAbnormalInfo.cnt += 1;
    if (g_beaconAbnormalInfo.time == 0) {
        g_beaconAbnormalInfo.time = checkTime;
        return false;
    }
    int64_t accumulateTime = checkTime - g_beaconAbnormalInfo.time;
    if (accumulateTime <= 0) {
        g_beaconAbnormalInfo.time = checkTime;
        g_beaconAbnormalInfo.cnt = 1;
        return false;
    }
    if (accumulateTime >= SIGNAL_RECORD_5S && g_beaconAbnormalInfo.cnt >= BEACON_ABN_MIN_CNT) {
        g_beaconAbnormalInfo.time = checkTime;
        g_beaconAbnormalInfo.cnt = 1;
        return true;
    }
    return false;
}

static int Hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10; // convert to decimal
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10; // convert to decimal
    }
    return -1;
}

int Hex2byte(const char *hex)
{
    int a = Hex2num(*hex++);
    if (a < 0) {
        return -1;
    }
    int b = Hex2num(*hex++);
    if (b < 0) {
        return -1;
    }
    return (a << 4) | b; // convert to binary
}

int HexString2Byte(const char *hex, uint8_t *buf, size_t len)
{
    size_t i;
    int a;
    const char *ipos = hex;
    uint8_t *opos = buf;

    for (i = 0; i < len; i++) {
        a = Hex2byte(ipos);
        if (a < 0) {
            return -1;
        }
        *opos++ = a;
        ipos += 2; // convert to binary
    }
    return 0;
}

void Byte2HexString(const uint8_t* byte, uint8_t bytesLen, char* hexstr, uint8_t hexstrLen)
{
    if ((byte == nullptr) || (hexstr == nullptr)) {
        WIFI_LOGE("%{public}s: invalid parameter", __func__);
        return;
    }

    if (hexstrLen < bytesLen * 2) { // verify length
        WIFI_LOGE("%{public}s: invalid byteLen:%{public}d or hexStrLen:%{public}d",
            __func__, bytesLen, hexstrLen);
        return;
    }

    WIFI_LOGI("%{public}s byteLen:%{public}d, hexStrLen:%{public}d", __func__, bytesLen, hexstrLen);
    uint8_t hexstrIndex = 0;
    for (uint8_t i = 0; i < bytesLen; i++) {
        if (snprintf_s(hexstr + hexstrIndex, hexstrLen - hexstrIndex, hexstrLen - hexstrIndex - 1,
            "%02x", byte[i]) <= 0) {
            WIFI_LOGI("%{public}s: failed to snprintf_s", __func__);
        }
        hexstrIndex += 2; // offset
        if (hexstrIndex >= hexstrLen) {
            break;
        }
    }
}

bool DecodeBase64(const std::string &input, std::vector<uint8_t> &output)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGD("%{public}s input:%{private}s, length:%{public}zu", __func__, input.c_str(), input.length());
    if (input.length() % BASE64_DEST_UNIT_SIZE != 0) {
        WIFI_LOGE("%{public}s: wrong data length for base64 encode string", __func__);
        return false;
    }
    uint32_t decodedLen = input.length() * BASE64_SRC_UNIT_SIZE / BASE64_DEST_UNIT_SIZE;
    if (input.at(input.length() - BASE64_UNIT_ONE_PADDING) == '=') {
        decodedLen--;
        if (input.at(input.length() - BASE64_UNIT_TWO_PADDING) == '=') {
            decodedLen--;
        }
    }
    output.resize(decodedLen);

    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        WIFI_LOGE("%{public}s: failed to create b64", __func__);
        return false;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(input.c_str(), input.length());
    if (bio == nullptr) {
        WIFI_LOGE("%{public}s: failed to create bio", __func__);
        BIO_free(b64);
        return false;
    }
    bio = BIO_push(b64, bio);
    if (BIO_read(bio, &output[0], input.length()) != static_cast<int32_t>(decodedLen)) {
        WIFI_LOGE("%{public}s: wrong data length for decoded buffer", __func__);
        BIO_free_all(bio);
        return false;
    }
    BIO_free_all(bio);
#endif
    return true;
}

std::string EncodeBase64(const std::vector<uint8_t> &input)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGD("%{public}s: size:%{public}zu", __func__, input.size());
    if (input.empty()) {
        WIFI_LOGE("%{public}s: wrong data length for string to encode.", __func__);
        return "";
    }
    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        WIFI_LOGE("%{public}s: failed to create b64", __func__);
        return "";
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        WIFI_LOGE("%{public}s: failed to create bio", __func__);
        BIO_free(b64);
        return "";
    }
    bio = BIO_push(b64, bio);
    BIO_write(bio, &input[0], input.size());
    BIO_flush(bio);

    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string output = "";
    if (bptr != nullptr) {
        std::vector<char> outputBuffer {};
        WIFI_LOGI("%{public}s: length is %{public}zu", __func__, bptr->length);
        outputBuffer.insert(outputBuffer.end(), bptr->data, bptr->data + bptr->length);
        outputBuffer[bptr->length] = 0;
        output = static_cast<char*>(&outputBuffer[0]);
    }
    BIO_free_all(bio);
    return output;
#else
    return "";
#endif
}

std::vector<std::string> GetSplitInfo(const std::string &input, const std::string &delimiter)
{
    size_t start = 0;
    size_t pos = 0;
    std::vector<std::string> results;
    if (input.empty() || delimiter.empty()) {
        WIFI_LOGE("%{public}s: invalid input or delimiter", __func__);
        return results;
    }

    if (input.length() < delimiter.length()) {
        WIFI_LOGE("%{public}s: invalid input length", __func__);
        return results;
    }

    WIFI_LOGD("%{public}s input:%{private}s, delimiter:%{public}s", __func__, input.c_str(), delimiter.c_str());
    while ((pos = input.find(delimiter, start)) != std::string::npos) {
        if (pos > start) {
            results.push_back(input.substr(start, pos - start));
        }
        start = pos + delimiter.length();
    }
    if (start < input.length()) {
        results.push_back(input.substr(start));
    }
    WIFI_LOGD("%{public}s size:%{public}zu", __func__, results.size());
    return results;
}

std::string HexToString(const std::string &str)
{
    std::string result;
    if (str.length() <= 0) {
        return result;
    }
    for (size_t i = 0; i < str.length() - 1; i += STEP_2BIT) {
        std::string byte = str.substr(i, STEP_2BIT);
        char chr = 0;
        int strTemp = CheckDataLegalHex(byte);
        if (strTemp > 0) {
            chr = static_cast<char>(strTemp);
        }
        result.push_back(chr);
    }
    return result;
}

std::string StringToHex(const std::string &data)
{
    std::stringstream ss;
    for (std::string::size_type i = 0; i < data.size(); ++i) {
        unsigned char temp = static_cast<unsigned char>(data[i]) >> HEX_OFFSET;
        ss << HEX_TABLE[temp] << HEX_TABLE[static_cast<unsigned char>(data[i]) & 0xf];
    }
    return ss.str();
}

int CheckDataLegalBin(const std::string &data)
{
    if (data.empty() || data.size() > MAX_INT32_LENGTH_BIN) {
        WIFI_LOGE("CheckDataLegalBin: invalid data:%{private}s", data.c_str());
        return 0;
    }
 
    std::regex pattern("[0-1]+");
    if (!std::regex_match(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long int num = std::strtol(data.c_str(), &endptr, BASE_BIN);
    if (errno == ERANGE) {
        WIFI_LOGE("CheckDataLegalBin errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
 
    return static_cast<int>(num);
}
 
int CheckDataLegalHex(const std::string &data)
{
    if (data.empty() || data.size() > MAX_INT32_LENGTH_HEX) {
        WIFI_LOGE("CheckDataLegalHex: invalid data:%{private}s", data.c_str());
        return 0;
    }
 
    std::regex pattern("[0-9a-fA-F]+");
    if (!std::regex_match(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long int num = std::strtol(data.c_str(), &endptr, BASE_HEX);
    if (errno == ERANGE) {
        WIFI_LOGE("CheckDataLegalHex errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
 
    return static_cast<int>(num);
}

int CheckDataLegal(std::string &data, int base)
{
    if (data.empty() || data.size() > MAX_INT32_LENGTH) {
        WIFI_LOGE("CheckDataLegal: invalid data:%{private}s", data.c_str());
        return 0;
    }
 
    std::regex pattern("-?\\d+");
    if (!std::regex_match(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long int num = std::strtol(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        WIFI_LOGE("CheckDataLegal errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }

    return static_cast<int>(num);
}

unsigned int CheckDataToUint(std::string &data, int base)
{
    if (data.empty() || data.size() > MAX_UINT32_LENGTH) {
        WIFI_LOGE("CheckDataToUint: invalid data:%{private}s", data.c_str());
        return 0;
    }
    std::regex pattern("\\d+");
    if (!std::regex_match(data, pattern)) {
        WIFI_LOGE("CheckDataToUint regex unsigned int value fail, data:%{private}s", data.c_str());
        return 0;
    }

    errno = 0;
    char *endptr = nullptr;
    unsigned long int num = std::strtoul(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        WIFI_LOGE("CheckDataToUint errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }

    return static_cast<unsigned int>(num);
}

long long CheckDataTolonglong(std::string &data, int base)
{
    if (data.empty() || data.size() > MAX_INT64_LENGTH) {
        WIFI_LOGE("CheckDataTolonglong: invalid data:%{private}s", data.c_str());
        return 0;
    }
 
    std::regex pattern("-?\\d+");
    if (!std::regex_match(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long long int num = std::strtoll(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        WIFI_LOGE("CheckDataTolonglong errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
    return num;
}

unsigned long StringToUlong(const std::string &word)
{
    unsigned long result;
    std::istringstream(word) >> result;
    return result;
}

float StringToFloat(const std::string &word)
{
    float result;
    std::istringstream(word) >> result;
    return result;
}

double StringToDouble(const std::string &word)
{
    double result;
    std::istringstream(word) >> result;
    return result;
}

uint32_t GenerateStandardErrCode(uint8_t subSystem, uint16_t errCode)
{
    uint8_t standardSubSystem = subSystem & 0x1F;
    return (WIFI_SYSTEM_ID << SYSTEM_OFFSET | standardSubSystem << SUB_SYSTEM_OFFSET | errCode);
}

bool InternalHiLinkNetworkToBool(int isHiLinkNetwork)
{
    return (isHiLinkNetwork > 0 && isHiLinkNetwork <= INTERNAL_HILINK_MAX_VALUE) ? true : false;
}

std::string Ipv4IntAnonymize(uint32_t ipInt)
{
    // convert uint32_t to string
    std::string address;
    if (ipInt == 0) {
        return address;
    }
    std::ostringstream stream;
    stream << ((ipInt >> BITS_24) & 0xFF) << "." << ((ipInt >> BITS_16) & 0xFF) << "."
    << ((ipInt >> BITS_8) & 0xFF) << "." << (ipInt & 0xFF);
    address = stream.str();
    return IpAnonymize(address);
}

std::string Ipv6Anonymize(std::string str)
{
    return DataAnonymize(str, ':', '*', 1);
}
}  // namespace Wifi
}  // namespace OHOS
