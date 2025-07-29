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
#include "wifi_common_util.h"
#include "wifi_log.h"
#ifndef OHOS_ARCH_LITE
#include "cJSON.h"
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
constexpr int PROP_FACTORY_RUN_MODE_LEN = 10;
constexpr int FACTORY_MODE_LEN = 7;
constexpr const char* FACTORY_RUN_MODE = "const.runmode";
constexpr const char* FACTORY_MODE = "factory";
constexpr const char* FACTORY_MODE_DEFAULT = "0";
constexpr int PROP_STARTUP_WIFI_ENABLE_LEN = 16;
constexpr int STARTUP_WIFI_ENABLE_LEN = 4;
constexpr const char* PROP_STARTUP_WIFI_ENABLE = "const.wifi.startup_wifi_enable";
constexpr const char* DEFAULT_STARTUP_WIFI_ENABLE = "false";
constexpr const char* STARTUP_WIFI_ENABLE = "true";
constexpr int PROP_PRODUCT_DEVICE_TYPE_LEN = 30;
constexpr int PRODUCT_DEVICE_TYPE_LEN = 5;
constexpr const char* PRODUCT_DEVICE_TYPE = "const.product.devicetype";
constexpr const char* DEFAULT_PRODUCT_DEVICE_TYPE = "default";
constexpr const char* PHONE_PRODUCT_DEVICE_TYPE = "phone";
constexpr const char* WEARABLE_PRODUCT_DEVICE_TYPE = "wearable";
constexpr const char* TABLET_PRODUCT_DEVICE_TYPE = "table";
constexpr const char* TV_PRODUCT_DEVICE_TYPE = "tv";
constexpr const char* PC_PRODUCT_DEVICE_TYPE = "2in1";
constexpr const char* VENDOR_COUNTRY_KEY = "const.cust.custPath";
constexpr const char* VENDOR_COUNTRY_DEFAULT = "";
constexpr const int32_t SYS_PARAMETER_SIZE = 256;
constexpr const int32_t PARAMETER_ERROR_CODE = 0;

constexpr int PROP_FSS_ENABLE_LEN = 16;
constexpr int FSS_ENABLE_LEN = 4;
constexpr const char* PROP_FSS_ENABLE = "const.wifi.hw_fss_enable";
constexpr const char* DEFAULT_FSS_ENABLE = "false";
constexpr const char* FSS_ENABLE = "true";
#ifndef INIT_LIB_ENABLE
constexpr int EC_INVALID = -9;  // using sysparam_errno.h, invalid param value
#endif
constexpr int ASCALL_MINUS_SIGN_INDEX = 45;

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
                res.push_back(CheckDataLegal(tmpStr));
            }
        }
        begPos = endPos + split.size();
    }
    tmpStr = str.substr(begPos);
    if (!tmpStr.empty() && IsValidateNum(tmpStr)) {
        res.push_back(CheckDataLegal(tmpStr));
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
    for (auto it = str.begin(); it != str.end(); ++it) {
        if (it == str.begin() && *it == ASCALL_MINUS_SIGN_INDEX) {
            continue;
        } else if (*it >= ASCALL_NUM_START_INDEX && *it <= ASCALL_NUM_END_INDEX) {
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
    for (unsigned i = 0; i + 1 < len;) {
        int8_t high = IsValidHexCharAndConvert(str[i]);
        int8_t low = IsValidHexCharAndConvert(str[i + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        char tmp = ((static_cast<uint8_t>(high) << hexShiftNum) | (static_cast<uint8_t>(low) & 0x0F));
        vec.push_back(tmp);
        i += 2; //2:拼接char类型的高四位和第四位
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
    unsigned int left = 0;
    unsigned int right = static_cast<size_t>(std::size(MCC_TABLE) - 1);
    if (MCC_TABLE[left].mnc > mnc || MCC_TABLE[right].mnc < mnc) {
        return false;
    }
    while (left < right) {
        unsigned int mid = static_cast<size_t>(left + right) >> 1;
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

bool IsPskEncryption(const std::string &keyMgmt)
{
    return keyMgmt == KEY_MGMT_WPA_PSK || keyMgmt == KEY_MGMT_SAE;
}

bool IsFactoryMode()
{
    char preValue[PROP_FACTORY_RUN_MODE_LEN] = {0};
    int errCode = GetParamValue(FACTORY_RUN_MODE, FACTORY_MODE_DEFAULT, preValue, PROP_FACTORY_RUN_MODE_LEN);
    if (errCode > 0) {
        if (strncmp(preValue, FACTORY_MODE, FACTORY_MODE_LEN) == 0) {
            return true;
        }
    }
    return false;
}

int GetDeviceType()
{
    char preValue[PROP_PRODUCT_DEVICE_TYPE_LEN] = {0};
    int errCode = GetParamValue(
        PRODUCT_DEVICE_TYPE, DEFAULT_PRODUCT_DEVICE_TYPE, preValue, PROP_PRODUCT_DEVICE_TYPE_LEN);
    if (errCode > 0) {
        if (strncmp(preValue, PHONE_PRODUCT_DEVICE_TYPE, PRODUCT_DEVICE_TYPE_LEN) == 0) {
            return ProductDeviceType::PHONE;
        }
        if (strncmp(preValue, WEARABLE_PRODUCT_DEVICE_TYPE, PRODUCT_DEVICE_TYPE_LEN) == 0) {
            return ProductDeviceType::WEARABLE;
        }
        if (strncmp(preValue, TABLET_PRODUCT_DEVICE_TYPE, PRODUCT_DEVICE_TYPE_LEN) == 0) {
            return ProductDeviceType::TABLET;
        }
        if (strncmp(preValue, TV_PRODUCT_DEVICE_TYPE, PRODUCT_DEVICE_TYPE_LEN) == 0) {
            return ProductDeviceType::TV;
        }
        if (strncmp(preValue, PC_PRODUCT_DEVICE_TYPE, PRODUCT_DEVICE_TYPE_LEN) == 0) {
            return ProductDeviceType::PC;
        }
    }
    return ProductDeviceType::DEFAULT;
}

bool CheckDeviceTypeByVendorCountry()
{
    char param[SYS_PARAMETER_SIZE] = { 0 };
    int errorCode = GetParamValue(VENDOR_COUNTRY_KEY, VENDOR_COUNTRY_DEFAULT, param, SYS_PARAMETER_SIZE);
    if (errorCode <= PARAMETER_ERROR_CODE) {
        LOGE("get vendor country fail, errorCode: %{public}d", errorCode);
        return false;
    }

    LOGI("vendor country: %{public}s, errorCode: %{public}d.", param, errorCode);
    auto iter = std::string(param).find("hwit");
    return iter != std::string::npos;
}

bool IsStartUpWifiEnableSupport()
{
    LOGI("Enter IsStartUpWifiEnableSupport");
    char preValue[PROP_STARTUP_WIFI_ENABLE_LEN] = {0};
    int errCode = GetParamValue(PROP_STARTUP_WIFI_ENABLE, DEFAULT_STARTUP_WIFI_ENABLE,
        preValue, PROP_STARTUP_WIFI_ENABLE_LEN);
    if (errCode > 0) {
        if (strncmp(preValue, STARTUP_WIFI_ENABLE, STARTUP_WIFI_ENABLE_LEN) == 0) {
            LOGI("param startup_wifi_enable is true.");
            return true;
        }
    }
    return false;
}

bool IsSignalSmoothingEnable()
{
    LOGI("Enter IsSignalSmoothingEnable");
    char preValue[PROP_FSS_ENABLE_LEN] = {0};
    int errCode = GetParamValue(PROP_FSS_ENABLE, DEFAULT_FSS_ENABLE,
        preValue, PROP_FSS_ENABLE_LEN);
    if (errCode > 0) {
        if (strncmp(preValue, FSS_ENABLE, FSS_ENABLE_LEN) == 0) {
            LOGI("param fss_enable is true.");
            return true;
        }
    }
    return false;
}

#ifndef OHOS_ARCH_LITE
bool ParseJsonKey(const cJSON *jsonValue, const std::string &key, std::string &value)
{
    if (!cJSON_IsArray(jsonValue)) {
        return false;
    }
    int nSize = cJSON_GetArraySize(jsonValue);
    for (int i = 0; i < nSize; ++i) {
        cJSON *item = cJSON_GetArrayItem(jsonValue, i);
        if (item == nullptr || !cJSON_IsObject(item)) {
            return false;
        }
        cJSON *keyItem = cJSON_GetObjectItem(item, key.c_str());
        if (keyItem == nullptr) {
            return false;
        }
        if (cJSON_IsString(keyItem) && keyItem->valuestring != nullptr) {
            value = keyItem->valuestring;
            return true;
        } else if (cJSON_IsNumber(keyItem)) {
            value = std::to_string(keyItem->valueint);
            return true;
        } else {
            return false;
        }
    }
    return false;
}

bool ParseJson(const std::string &jsonString, const std::string &type, const std::string &key, std::string &value)
{
    cJSON *root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        LOGE("ParseJson failed to parse json data.");
        return false;
    }
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return false;
    }
    int nSize = cJSON_GetArraySize(root);
    for (int i = 0; i < nSize; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (item == nullptr || !cJSON_IsObject(item)) {
            continue;
        }
        cJSON *typeItem = cJSON_GetObjectItem(item, type.c_str());
        if (typeItem == nullptr) {
            continue;
        }
        if (ParseJsonKey(typeItem, key, value)) {
            cJSON_Delete(root);
            return true;
        }
    }
    cJSON_Delete(root);
    return false;
}

void ConvertDecStrToHexStr(const std::string &inData, std::string &outData)
{
    std::stringstream ss(inData);
    std::string token;
    constexpr int hexCharLen = 2;
    std::stringstream temp;
    while (getline(ss, token, ',')) {
        int num = CheckDataLegal(token);
        temp << std::setfill('0') << std::setw(hexCharLen) << std::hex << num;
    }
    outData = temp.str();
}

void SplitStringBySubstring(const std::string &inData, std::string &outData, const std::string &subBegin,
    const std::string &subEnd)
{
    auto posBegin = inData.find(subBegin);
    auto posEnd = inData.find(subEnd);
    if (posBegin == std::string::npos || posEnd == std::string::npos) {
        LOGE("SplitStringBySubstring find substring fail.");
        return;
    }
    if (posEnd < posBegin + subEnd.length()) {
        LOGE("SplitStringBySubstring data length is invaild.");
        return;
    }
    outData = inData.substr(posBegin, posEnd - posBegin + subEnd.length());
    return;
}

int GetBssidCounter(const WifiDeviceConfig &config, const std::vector<WifiScanInfo> &scanResults)
{
    int counter = 0;
    if (scanResults.empty()) {
        LOGI("scanResults ie empty.");
        return 0;
    }

    std::string currentSsid = config.ssid;
    std::string configKey = config.keyMgmt;
    if (currentSsid.empty() || configKey.empty()) {
        return 0;
    }
    for (WifiScanInfo nextResult : scanResults) {
        std::string scanSsid = nextResult.ssid;
        std::string capabilities = nextResult.capabilities;
        if (currentSsid == scanSsid && IsSameEncryptType(capabilities, configKey)) {
            counter += 1;
        }
    }
    return counter;
}

bool IsSameEncryptType(const std::string& scanInfoKeymgmt, const std::string& deviceKeymgmt)
{
    if (deviceKeymgmt == "WPA-PSK") {
        return scanInfoKeymgmt.find("PSK") != std::string::npos;
    } else if (deviceKeymgmt == "WPA-EAP") {
        return scanInfoKeymgmt.find("EAP") != std::string::npos;
    } else if (deviceKeymgmt == "SAE") {
        return scanInfoKeymgmt.find("SAE") != std::string::npos;
    } else if (deviceKeymgmt == "NONE") {
        return (scanInfoKeymgmt.find("PSK") == std::string::npos) &&
               (scanInfoKeymgmt.find("EAP") == std::string::npos) && (scanInfoKeymgmt.find("SAE") == std::string::npos);
    } else {
        return false;
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS
