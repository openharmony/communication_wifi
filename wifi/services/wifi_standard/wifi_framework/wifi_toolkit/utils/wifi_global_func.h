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

#ifndef OHOS_WIFI_GLOBAL_FUNC_H
#define OHOS_WIFI_GLOBAL_FUNC_H

#include <vector>
#include <random>
#include <string>
#include "wifi_errcode.h"
#include "wifi_ap_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
constexpr int MAC_STRING_SIZE = 17;
constexpr int MIN_SSID_LEN = 1;
constexpr int MAX_SSID_LEN = 32;
constexpr int MIN_PSK_LEN = 8;
constexpr int MAX_PSK_LEN = 63;
constexpr int HEX_TYPE_LEN = 3; /* 3 hex type: 0 a A */
constexpr int MAX_AP_CONN = 32;
constexpr int MAX_CONFIGS_NUM = 1000;
typedef void (*ParameterChgPtr)(const char *key, const char *value, void *context);

/**
 * @Description Get a random string
 *
 * @param len - Random string length
 * @return std::string - Random String
 */
std::string GetRandomStr(int len);

/**
 * @Description get a random num
 *
 * @param start - The lower limit of the range of random numbers
 * @param end - The upper limit of the range of random numbers
 * @return random num
 */
int GetRandomInt(int start, int end);

/**
 * @Description If allowed scan always according the scan control policy
 *
 * @param info - ScanControlInfo object
 * @return true - allowed
 * @return false - not allowed
 */
bool IsAllowScanAnyTime(const ScanControlInfo &info);

/**
 * @Description Internal transition from OperateResState struct to ConnState
 *
 * @param resState - OperateResState state
 * @param isReport - true : need report; flase : not report
 * @return ConnState - convert output connection state
 */
ConnState ConvertConnStateInternal(OperateResState resState, bool &isReport);

/**
 * @Description Check whether the MAC address is valid
 *
 * @param macStr - input the mac address
 * @return int - 0 Valid; -1 Invalid
 */
int CheckMacIsValid(const std::string &macStr);

/**
 * @Description Split string to vector accord split
 *
 * @param str - input string
 * @param split - split string
 * @param vec - return string vector
 */
void SplitString(const std::string &str, const std::string &split, std::vector<std::string> &vec);

/**
 * @Description Converts a numeric vector to a character array.
 *
 * @param vec - Input numeric vector.[in]
 * @param pChar - Character array.[out]
 * @param len - Length of character array.[out]
 * @param memSize - Character array's memory size.[in]
 * @return int - 0 Valid; -1 Invalid
 */
template <typename T>
int Vec2Char(const std::vector<T> &vec, T *pChar, int& len, int memSize)
{
    if (pChar == nullptr) {
        len = 0;
        return -1;
    }

    const int vecSize = static_cast<int>(vec.size());
    if (vecSize > memSize) {
        pChar = nullptr;
        len = 0;
        return -1;
    }

    for (int i = 0; i < vecSize; i++) {
        pChar[i] = vec[i];
    }
    len = vecSize;
    return 0;
}

/**
 * @Description Converts a character array to a numeric vector.
 *
 * @param pChar - Character array.[in]
 * @param len - Length of character array.[in]
 * @param vec - Input numeric vector.[out]
 * @return int - 0 Valid; -1 Invalid
 */
template <typename T>
int Char2Vec(const T *pChar, int len, std::vector<T> &vec)
{
    vec.clear();
    if (pChar == nullptr || len < 0) {
        return -1;
    }

    for (int i = 0; i < len; i++) {
        vec.push_back(pChar[i]);
    }

    return 0;
}

/**
 * @Description Converts a char/unsigned char/byte/int8 vector to a hexadecimal character array. A numeric
 * value is converted to two characters. e.g. 0x3F -> '3' 'F'
 *
 * @param vec - Input numeric vector.
 * @param pHexChar - Character array.
 * @param memSize - Character array's memory size.
 * @return int - 0 Valid; -1 Invalid
 */
template<typename T>
int Val2HexChar(const std::vector<T> &vec, char *pHexChar, unsigned memSize)
{
    unsigned size = vec.size();
    unsigned doubleSize = (size << 1);
    if (doubleSize >= memSize) {
        return -1;
    }
    const std::string hexStr = "0123456789ABCDEF";
    const unsigned highBit = 4;
    int pos = 0;
    for (unsigned i = 0; i < size; ++i) {
        unsigned char tmp = vec[i];
        pHexChar[pos] = hexStr[(tmp >> highBit) & 0x0F];
        ++pos;
        pHexChar[pos] = hexStr[tmp & 0x0F];
        ++pos;
    }
    pHexChar[pos] = '\0';
    return 0;
}

template <typename T>
std::string JoinVecToString(const std::vector<T> &vec, const std::string &delimiter)
{
    std::stringstream ss;
    std::copy(vec.begin(), vec.end(), std::ostream_iterator<T>(ss, delimiter.c_str()));
    std::string joinedStr = ss.str();
    if (joinedStr.size() > delimiter.size()) {
        joinedStr.erase(joinedStr.size() - delimiter.size());
    }
    return joinedStr;
}

/**
 * @Description splitting numeric strings based on characters
 *
 * @param str - split string
 * @param split - characters used for splitting
 * @return number vector
 */
std::vector<int> SplitStringToIntVector(const std::string &str, const std::string &split);

/**
 * @Description  Output vecChar to stream.
 * @param prefix  - prefix string[in]
 * @param vecChar - vector char[in]
 * @param suffix  - suffix string[in]
 */
std::string Vec2Stream(const std::string &prefix, const std::vector<char> &vecChar, const std::string &sufffix = "");

/**
 * @Description Convert a hex type string to vector.
 *
 * @param str - input hex string, eg: 010203...
 * @param vec - output vector result, eg: [1,2,3,...]
 * @return int - convert result, 0 success, -1 failed
 */
int HexStringToVec(const std::string &str, std::vector<char> &vec);

/**
 * @Description Convert a hex type string to uint8_t*.
 *
 * @param str - input hex string, eg: 010203...
 * @param plainText - output uint8_t* result, eg: [1,2,3,...]
 * @param plainLength - input maxLength of uint8_t* result, eg: 256
 * @param resultLength - output Length of uint8_t* result, eg: 16
 * @return int - convert result, 0 success, -1 failed
 */
int HexStringToVec(const std::string &str, uint8_t plainText[], uint32_t plainLength, uint32_t &resultLength);

/**
 * @Description Convert a uint8_t* to Hex string.
 *
 * @param plainText - input uint8_t*, eg: [1,2,3,...]
 * @param size - input uint8_t* size, eg: 16
 * @return string - convert Hex string, eg: 010203...
 */
std::string ConvertArrayToHex(const uint8_t plainText[], uint32_t size);

/**
 * @Description Convert a string to validate string for write.
 *
 * @param str - input string
 * @return string - validate string wrapped by ""
 */
std::string ValidateString(const std::string  &str);

/**
 * @Description is unm
 *
 * @param str - input string
 * @return result
 */
bool IsValidateNum(const std::string &str);

/**
 * @Description transform freq to bandType
 *
 * @param freq - freq
 * @return BandType
 */
BandType TransformFreqToBand(int freq);

/**
 * @Description transform channel to bandType
 *
 * @param channel - channel
 * @return BandType
 */
BandType TransformChannelToBand(int channel);

/**
 * @Description Check is a valid 5G frequency.
 *
 * @param freq - Frequency input
 * @return true - valid
 * @return false - invalid
 */
bool IsValid5GHz(int freq);

/**
 * @Description Check is a valid 2.4G frequency.
 *
 * @param freq - Frequency input
 * @return true - valid
 * @return false - invalid
 */
bool IsValid24GHz(int freq);

/**
 * @Description Check is a valid 2.4G channel.
 *
 * @param channel - channel input
 * @return true - valid
 * @return false - invalid
 */
bool IsValid24GChannel(int channel);

/**
 * @Description Check is a valid 5G channel.
 *
 * @param channel - channel input
 * @return true - valid
 * @return false - invalid
 */
bool IsValid5GChannel(int channel);

/**
 * @Description  Convert frequency to channel number.
 * @param freq - frequency to convert
 * @return success: channel num    failed: -1
 */
int TransformFrequencyIntoChannel(int freq);

/**
 * @Description Convert the frequency in the container into a channel.
 *
 * @param freqVector - frequency vector input
 * @param chanVector - Channel vector output
 */
void TransformFrequencyIntoChannel(const std::vector<int> &freqVector, std::vector<int> &chanVector);

/**
 * @Description transform freq to band
 *
 * @param freq - freq
 * @return band
 */
BandType TransformFreqToBand(int freq);

/**
 * @Description transform channel to band
 *
 * @param channel - channel
 * @return band
 */
BandType TransformChannelToBand(int channel);

#ifndef OHOS_ARCH_LITE
/**
 * @Description Check whether the country code is valid.
 *
 * @param wifiCountryCode - country code to be determined
 * @return true - valid
 * @return false - invalid
 */
bool IsValidCountryCode(const std::string &wifiCountryCode);

/**
 * @Description Convert the country code from mnc to iso.
 *
 * @param wifiCountryCode - country code to be convert
 * @return true - convert success
 * @return false - convert fail
 */
bool ConvertMncToIso(int mnc, std::string &wifiCountryCode);
#endif

/**
 * @Description Convert the letters to upper.
 *
 * @param str - input lowercase letters and output upper letters
 */
void StrToUpper(std::string &str);

/**
 * @Description Converting char to numbers
 *
 * @param c - char
 * @return numbers
 */
int ConvertCharToInt(const char &c);

/**
 * @Description Converting string to numbers
 *
 * @param str - string
 * @return numbers
 */
int ConvertStringToInt(const std::string str);

/**
 * @Description Obtains a system parameter matching the specified key.
 *
 * @param key - Indicates the key for the system parameter to query.
 * The value can contain lowercase letters, digits, underscores (_), and dots (.).
 * Its length cannot exceed 32 bytes (including the end-of-text character in the string).
 * @param def - Indicates the default value to return when no query result is found.
 * This parameter is specified by the caller.
 * @param value - Indicates the data buffer that stores the query result.
 * This parameter is applied for and released by the caller and can be used as an output parameter.
 * @param len - Indicates the length of the data in the buffer.
 * @return Returns the number of bytes of the system parameter if the operation is successful;
 * returns -9 if a parameter is incorrect; returns -1 in other scenarios.
 */
int GetParamValue(const char *key, const char *def, char *value, uint32_t len);

/**
 * @Description Sets or updates a system parameter.
 *
 * @param key Indicates the key for the parameter to set or update.
 * The value can contain lowercase letters, digits, underscores (_), and dots (.).
 * Its length cannot exceed 32 bytes (including the end-of-text character in the string).
 * @param value Indicates the system parameter value.
 * Its length cannot exceed 128 bytes (including the end-of-text character in the string).
 * @return Returns 0 if the operation is successful;
 * returns -9 if a parameter is incorrect; returns -1 in other scenarios.
 */
int SetParamValue(const char *key, const char *value);

/**
 * @Description Watch for system parameter values.
 *
 * @param keyPrefix - Indicates the key prefix for the parameter to be watched.
 * If keyPrefix is not a full name, "A.B." for example, it means to watch for all parameter started with "A.B.".
 * @param callback - Indicates value change callback.
 * If callback is NULL, it means to cancel the watch.
 * @param context - context.
 * @return Returns 0 if the operation is successful;
 */
int WatchParamValue(const char *keyprefix, ParameterChgPtr callback, void *context);

/**
 * @Description are the two frequencies dbac
 *
 * @param freqA - one freq
 * @param freqB - other freq
 * @return true - dbac
 * @return false - not dbac
 */
bool IsFreqDbac(int freqA, int freqB);

/**
 * @Description are the two channels dbac
 *
 * @param freqA - one channel
 * @param freqB - other channel
 * @return true - dbac
 * @return false - not dbac
 */
bool IsChannelDbac(int channelA, int channelB);
}  // namespace Wifi
}  // namespace OHOS
#endif