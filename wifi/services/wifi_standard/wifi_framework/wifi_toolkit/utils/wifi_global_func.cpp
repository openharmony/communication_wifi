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
#include "wifi_global_func.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <random>
#include "wifi_log.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_define.h"
#endif
#ifdef INIT_LIB_ENABLE
#include "parameter.h"
#endif
#undef LOG_TAG
#define LOG_TAG "WifiGlobalFunc"

namespace OHOS {
namespace Wifi {
constexpr int ASCALL_NUM_START_INDEX = 48;  // the range of numbers in the ascll table
constexpr int ASCALL_NUM_END_INDEX = 57;
constexpr int FREP_2G_MIN = 2412;
constexpr int FREP_2G_MAX = 2472;
constexpr int FREP_5G_MIN = 5170;
constexpr int FREP_5G_MAX = 5825;
constexpr int CHANNEL_14_FREP = 2484;
constexpr int CHANNEL_14 = 14;
constexpr int CENTER_FREP_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_2G_MAX = 14;  // 2484
constexpr int CHANNEL_5G_MIN = 34;
constexpr int CHANNEL_5G_MAX = 165;  // 5825
#ifndef INIT_LIB_ENABLE
constexpr int EC_INVALID = -9;  // using sysparam_errno.h, invalid param value
#endif

std::string GetRandomStr(int len)
{
    std::random_device rd;
    std::string res;
    char rndbuf[MAX_PSK_LEN + 1] = {0};
    int rndnum;
    if (len > MAX_PSK_LEN) {
        len = MAX_PSK_LEN;
    }
    for (int n = 0; n < len; ++n) {
        rndnum = std::abs((int)rd());
        switch (rndnum % HEX_TYPE_LEN) {
            case 0:
                rndbuf[n] = ((rndnum % ('z' - 'a' + 1)) + 'a');
                break;
            case 1:
                rndbuf[n] = ((rndnum % ('Z' - 'A' + 1)) + 'A');
                break;
            default:
                rndbuf[n] = ((rndnum % ('9' - '0' + 1)) + '0');
                break;
        }
    }
    res = rndbuf;
    return res;
}

int GetRandomInt(int start, int end)
{
    if (end <= start) {
        return start;
    }
    std::random_device rd;
    std::mt19937 e{rd()};
    std::uniform_int_distribution<int> dist{start, end};
    return dist(e);
}

bool IsAllowScanAnyTime(const ScanControlInfo &info)
{
    for (auto forbidIter = info.scanForbidList.begin(); forbidIter != info.scanForbidList.end(); forbidIter++) {
        if (forbidIter->scanMode == ScanMode::ANYTIME_SCAN && forbidIter->scanScene == SCAN_SCENE_ALL) {
            return false;
        }
    }
    return true;
}

std::vector<int> SplitStringToIntVector(const std::string &str, const std::string &split)
{
    std::vector<int> res;
    if (str.empty() || split.empty()) {
        return res;
    }
    std::string::size_type begPos = 0;
    std::string::size_type endPos = 0;
    std::string tmpStr;
    while ((endPos = str.find(split, begPos)) != std::string::npos) {
        if (endPos > begPos) {
            tmpStr = str.substr(begPos, endPos - begPos);
            if (IsValidateNum(tmpStr)) {
                res.push_back(ConvertStringToInt(tmpStr));
            }
        }
        begPos = endPos + split.size();
    }
    tmpStr = str.substr(begPos);
    if (!tmpStr.empty() && IsValidateNum(tmpStr)) {
        res.push_back(ConvertStringToInt(tmpStr));
    }
    return res;
}

ConnState ConvertConnStateInternal(OperateResState resState, bool &isReport)
{
    switch (resState) {
        case OperateResState::CONNECT_CONNECTING:
            isReport = true;
            return ConnState::CONNECTING;
        case OperateResState::SPECIAL_CONNECTED:
            isReport = true;
            return ConnState::SPECIAL_CONNECT;
        case OperateResState::CONNECT_AP_CONNECTED:
            isReport = true;
            return ConnState::CONNECTED;
        case OperateResState::CONNECT_NETWORK_ENABLED:
        case OperateResState::CONNECT_CHECK_PORTAL:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::CONNECT_NETWORK_DISABLED:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::DISCONNECT_DISCONNECTING:
            isReport = true;
            return ConnState::DISCONNECTING;
        case OperateResState::DISCONNECT_DISCONNECTED:
            isReport = true;
            return ConnState::DISCONNECTED;
        case OperateResState::CONNECT_PASSWORD_WRONG:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::CONNECT_CONNECTION_FULL:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::CONNECT_CONNECTION_REJECT:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::CONNECT_CONNECTING_TIMEOUT:
            isReport = false;
            return ConnState::UNKNOWN;
        case OperateResState::CONNECT_OBTAINING_IP:
            isReport = true;
            return ConnState::OBTAINING_IPADDR;
        case OperateResState::CONNECT_OBTAINING_IP_FAILED:
        case OperateResState::CONNECT_ASSOCIATING:
        case OperateResState::CONNECT_ASSOCIATED:
            isReport = false;
            return ConnState::UNKNOWN;
        default:
            isReport = true;
            return ConnState::UNKNOWN;
    }
}

static int8_t IsValidHexCharAndConvert(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + ('9' - '0' + 1);
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + ('9' - '0' + 1);
    }
    return -1;
}

int CheckMacIsValid(const std::string &macStr)
{
    if (macStr.length() != MAC_STRING_SIZE) {
        return -1;
    }
    /* Verification format */
    for (int i = 0, j = 0; i < MAC_STRING_SIZE; ++i) {
        if (j == 0 || j == 1) {
            int8_t v = IsValidHexCharAndConvert(macStr[i]);
            if (v < 0) {
                return -1;
            }
            ++j;
        } else {
            if (macStr[i] != ':') {
                return -1;
            }
            j = 0;
        }
    }
    return 0;
}

void SplitString(const std::string &str, const std::string &split, std::vector<std::string> &vec)
{
    if (split.empty()) {
        vec.push_back(str);
        return;
    }
    std::string::size_type begPos = 0;
    std::string::size_type endPos = 0;
    std::string tmpStr;
    while ((endPos = str.find(split, begPos)) != std::string::npos) {
        if (endPos > begPos) {
            tmpStr = str.substr(begPos, endPos - begPos);
            vec.push_back(tmpStr);
        }
        begPos = endPos + split.size();
    }
    tmpStr = str.substr(begPos);
    if (!tmpStr.empty()) {
        vec.push_back(tmpStr);
    }
    return;
}

std::string Vec2Stream(const std::string &prefix, const std::vector<char> &vecChar, const std::string &sufffix)
{
    std::ostringstream ss;
    constexpr int hexCharLen = 2;
    ss << prefix;
    int temp = 0;
    for (std::size_t i = 0; i < vecChar.size(); i++) {
        temp = (unsigned char)(vecChar[i]);
        ss << std::setfill('0') << std::setw(hexCharLen) << std::hex << std::uppercase << temp << " ";
    }
    ss << sufffix;
    return ss.str();
}

bool IsValidateNum(const std::string &str)
{
    if (str.empty()) {
        return false;
    }
    for (char item : str) {
        if (item >= ASCALL_NUM_START_INDEX && item <= ASCALL_NUM_END_INDEX) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

int TransformFrequencyIntoChannel(int freq)
{
    if (freq >= FREP_2G_MIN && freq <= FREP_2G_MAX) {
        return (freq - FREP_2G_MIN) / CENTER_FREP_DIFF + CHANNEL_2G_MIN;
    } else if (freq == CHANNEL_14_FREP) {
        return CHANNEL_14;
    } else if (freq >= FREP_5G_MIN && freq <= FREP_5G_MAX) {
        return (freq - FREP_5G_MIN) / CENTER_FREP_DIFF + CHANNEL_5G_MIN;
    }
    return -1;
}

int HexStringToVec(const std::string &str, std::vector<char> &vec)
{
    unsigned len = str.length();
    if ((len & 1) != 0) {
        return -1;
    }
    const int hexShiftNum = 4;
    for (unsigned i = 0; i + 1 < len; ++i) {
        int8_t high = IsValidHexCharAndConvert(str[i]);
        int8_t low = IsValidHexCharAndConvert(str[++i]);
        if (high < 0 || low < 0) {
            return -1;
        }
        char tmp = ((high << hexShiftNum) | (low & 0x0F));
        vec.push_back(tmp);
    }
    return 0;
}

int HexStringToVec(const std::string &str, uint8_t plainText[], uint32_t plainLength, uint32_t &resultLength)
{
    std::vector<char> result;
    result.clear();
    int ret = HexStringToVec(str, result);
    if (ret == -1 || result.size() > plainLength) {
        return -1;
    }
    for (std::vector<char>::size_type i = 0; i < result.size(); ++i) {
        plainText[i] = result[i];
    }
    resultLength = result.size();
    return 0;
}

static char ConvertArrayChar(uint8_t ch)
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

std::string ConvertArrayToHex(const uint8_t plainText[], uint32_t size)
{
    constexpr int bitWidth = 4;
    std::stringstream ss;
    for (uint32_t i = 0; i < size; i++) {
        ss << ConvertArrayChar(plainText[i] >> bitWidth) << ConvertArrayChar (plainText[i] & 0xf);
    }
    return ss.str();
}

static bool ValidateChar(const char ch)
{
    if (ch == '\n' || ch == '\r') {
        return false;
    }
    return true;
}

std::string ValidateString(const std::string  &str)
{
    std::stringstream ss;
    ss << "\"";
    for (char ch : str) {
        if (ValidateChar(ch)) {
            ss << ch;
        }
    }
    ss << "\"";
    return ss.str();
}

void TransformFrequencyIntoChannel(const std::vector<int> &freqVector, std::vector<int> &chanVector)
{
    int channel;
    for (size_t i = 0; i < freqVector.size(); ++i) {
        if (freqVector[i] >= FREP_2G_MIN && freqVector[i] <= FREP_2G_MAX) {
            channel = (freqVector[i] - FREP_2G_MIN) / CENTER_FREP_DIFF + CHANNEL_2G_MIN;
        } else if (freqVector[i] == CHANNEL_14_FREP) {
            channel = CHANNEL_14;
        } else if (freqVector[i] >= FREP_5G_MIN && freqVector[i] <= FREP_5G_MAX) {
            channel = (freqVector[i] - FREP_5G_MIN) / CENTER_FREP_DIFF + CHANNEL_5G_MIN;
        } else {
            LOGW("Invalid Freq:%d", freqVector[i]);
            continue;
        }
        chanVector.push_back(channel);
    }
}

BandType TransformFreqToBand(int freq)
{
    if (freq <= CHANNEL_14_FREP) {
        return BandType::BAND_2GHZ;
    } else if (freq <= FREP_5G_MAX) {
        return BandType::BAND_5GHZ;
    }
    return BandType::BAND_NONE;  // not supported currently 6/60GHZ
}

BandType TransformChannelToBand(int channel)
{
    if (channel <= CHANNEL_2G_MAX) {
        return BandType::BAND_2GHZ;
    } else if (channel <= CHANNEL_5G_MAX) {
        return BandType::BAND_5GHZ;
    }
    return BandType::BAND_NONE;  // not supported currently 6/60GHZ
}

bool IsValid24GHz(int freq)
{
    return freq > 2400 && freq < 2500;
}

bool IsValid5GHz(int freq)
{
    return freq > 4900 && freq < 5900;
}

bool IsValid24GChannel(int channel)
{
    return channel >= CHANNEL_2G_MIN && channel <= CHANNEL_2G_MAX;
}

bool IsValid5GChannel(int channel)
{
    return channel >= CHANNEL_5G_MIN && channel <= CHANNEL_5G_MAX;
}

#ifndef OHOS_ARCH_LITE
bool IsValidCountryCode(const std::string &wifiCountryCode)
{
    if (wifiCountryCode.empty()) {
        return false;
    }
    for (size_t i = 0; i < std::size(MCC_TABLE); i++) {
        if (strcasecmp(wifiCountryCode.c_str(), MCC_TABLE[i].iso) == 0) {
            return true;
        }
    }
    return false;
}

bool ConvertMncToIso(int mnc, std::string &wifiCountryCode)
{
    int left = 0;
    int right = std::size(MCC_TABLE) - 1;
    if (MCC_TABLE[left].mnc > mnc || MCC_TABLE[right].mnc < mnc) {
        return false;
    }
    while (left < right) {
        int mid = (left + right) >> 1;
        if (MCC_TABLE[mid].mnc < mnc) {
            left = mid + 1;
        } else if (MCC_TABLE[mid].mnc > mnc) {
            right = mid - 1;
        } else {
            left = mid;
        }
        if (MCC_TABLE[left].mnc == mnc) {
            wifiCountryCode = MCC_TABLE[left].iso;
            return true;
        }
    }
    return false;
}
#endif

void StrToUpper(std::string &str)
{
    std::for_each(std::begin(str), std::end(str), [](auto &c) {
        c = std::toupper(c);
    });
}

int ConvertCharToInt(const char &c)
{
    int result = 0;
    std::stringstream ss;
    ss << c;
    ss >> result;
    return result;
}

int ConvertStringToInt(const std::string str)
{
    int result = 0;
    std::stringstream ss;
    ss << str;
    ss >> result;
    return result;
}

int GetParamValue(const char *key, const char *def, char *value, uint32_t len)
{
#ifdef INIT_LIB_ENABLE
    return GetParameter(key, def, value, len);
#else
    return EC_INVALID;
#endif
}

int SetParamValue(const char *key, const char *value)
{
#ifdef INIT_LIB_ENABLE
    return SetParameter(key, value);
#else
    return EC_INVALID;
#endif
}

int WatchParamValue(const char *keyprefix, ParameterChgPtr callback, void *context)
{
#ifdef INIT_LIB_ENABLE
    return WatchParameter(keyprefix, callback, context);
#else
    return EC_INVALID;
#endif
}

bool IsFreqDbac(int freqA, int freqB)
{
    if (freqA == freqB) {
        return false;
    }
    if (IsValid5GHz(freqA) && IsValid5GHz(freqB)) {
        return true;
    }
    if (IsValid24GHz(freqA) && IsValid24GHz(freqB)) {
        return true;
    }
    return false;
}

bool IsChannelDbac(int channelA, int channelB)
{
    if (channelA == channelB) {
        return false;
    }
    if (IsValid5GChannel(channelA) && IsValid5GChannel(channelB)) {
        return true;
    }
    if (IsValid24GChannel(channelA) && IsValid24GChannel(channelB)) {
        return true;
    }
    return false;
}
}  // namespace Wifi
}  // namespace OHOS
