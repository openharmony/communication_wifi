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
#endif
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonUtil");

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
    while (p != nullptr) {
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

    std::string bundleName;
    int uid = IPCSkeleton::GetCallingUid();
    if (!bundleInstance->GetBundleNameForUid(uid, bundleName)) {
        WIFI_LOGE("Get bundle name failed!");
    }
    WIFI_LOGI("Get bundle name uid[%{public}d]: %{public}s", uid, bundleName.c_str());
    return bundleName;
}

bool IsSystemApp()
{
    sptr<AppExecFwk::IBundleMgr> bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        return false;
    }

    int uid = IPCSkeleton::GetCallingUid();
    bool isSysApp = bundleInstance->CheckIsSystemAppByUid(uid);
    WIFI_LOGI("Is system App uid[%{public}d]: %{public}d", uid, isSysApp);
    return isSysApp;
}

int GetCallingPid()
{
    return IPCSkeleton::GetCallingPid();
}

int GetCallingUid()
{
    return IPCSkeleton::GetCallingUid();
}

bool IsForegroundApp(const int uid)
{
    using namespace OHOS::AppExecFwk;
    using namespace OHOS::AppExecFwk::Constants;
    constexpr int32_t UID_CALLINGUID_TRANSFORM_DIVISOR = 200000;
    int32_t userId = static_cast<int32_t>(uid / UID_CALLINGUID_TRANSFORM_DIVISOR);

    auto appMgrClient = std::make_unique<AppMgrClient>();
    if (appMgrClient == nullptr) {
        return false;
    }
    appMgrClient->ConnectAppMgrService();
    AppMgrResultCode ret;
    std::vector<RunningProcessInfo> infos;
    ret = appMgrClient->GetProcessRunningInfosByUserId(infos, userId);
    if (ret != AppMgrResultCode::RESULT_OK) {
        WIFI_LOGE("GetProcessRunningInfosByUserId fail, ret = [%{public}d]", ret);
        return false;
    }

    auto iter = std::find_if(infos.begin(), infos.end(), [&uid](const RunningProcessInfo &rhs) {
        return ((rhs.uid_ == uid) && (rhs.state_ == AppProcessState::APP_STATE_FOREGROUND ||
                rhs.state_ == AppProcessState::APP_STATE_FOCUS));
    });
    if (iter != infos.end()) {
        return true;
    }
    return false;
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
    WIFI_LOGI("FrequencyToChannel: %{public}d", freq);
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

}  // namespace Wifi
}  // namespace OHOS
