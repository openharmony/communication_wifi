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

#ifndef OHOS_WIFI_COMMON_UTIL_H
#define OHOS_WIFI_COMMON_UTIL_H

#include <map>
#include <chrono>
#include <string>
#include <vector>
#include "securec.h"
#include "define.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_timer.h"
#endif
#include "wifi_errcode.h"
#include "wifi_msg.h"

#ifndef WIFI_MAC_LEN
#define WIFI_MAC_LEN 6
#endif

namespace OHOS {
namespace Wifi {

#ifndef NO_SANITIZE
#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define NO_SANITIZE(type) __attribute__((no_sanitize(type)))
#endif
#endif
#endif

#ifndef NO_SANITIZE
#define NO_SANITIZE(type)
#endif

constexpr int INVALID_FREQ_OR_CHANNEL = -1;
constexpr int SECOND_TO_MICROSECOND = 1000 * 1000;
const uint32_t DECIMAL_NOTATION = 10;
inline const uint8_t WIFI_SYSTEM_ID = 202;
inline const uint8_t P2P_SUB_SYSTEM_ID = 2;
inline const int SYSTEM_OFFSET = 21;
inline const int SUB_SYSTEM_OFFSET = 16;
inline const int SIGNAL_RECORD_12S = 12;
inline const int SIGNAL_RECORD_5S = 5;
inline const int BEACON_LENGTH_RSSI = 10;
inline const int8_t BEACON_LOST_RSSI0 = -128;
inline const int8_t BEACON_LOST_RSSI1 = 127;
inline const int SIGNAL_LEVEL_TWO = 2;
inline const int BEACON_ABNORMAL = 2;

enum BeaconLostType : int32_t {
    SIGNAL_LEVEL_LOW = 0,
    SIGNAL_LEVEL_HIGH = 1
};

struct BeaconLostInfo {
    int64_t time;
    int cnt;
    std::string bssid;
    int rssi;
    unsigned int rxBytes;
};

struct BeaconAbnormalInfo {
    int64_t time;
    int cnt;
    std::string bssid;
    std::vector<uint8_t> rssiArr;
};

/* StaCallBackNameEventIdMap */
static std::map<std::string, int> g_staCallBackNameEventIdMap = {
    { EVENT_STA_POWER_STATE_CHANGE, WIFI_CBK_MSG_STATE_CHANGE },
    { EVENT_STA_CONN_STATE_CHANGE, WIFI_CBK_MSG_CONNECTION_CHANGE },
    { EVENT_STA_RSSI_STATE_CHANGE, WIFI_CBK_MSG_RSSI_CHANGE },
    { EVENT_STA_WPS_STATE_CHANGE, WIFI_CBK_MSG_WPS_STATE_CHANGE },
    { EVENT_STREAM_CHANGE, WIFI_CBK_MSG_STREAM_DIRECTION },
    { EVENT_STA_DEVICE_CONFIG_CHANGE, WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE },
    { EVENT_STA_SCAN_STATE_CHANGE, WIFI_CBK_MSG_SCAN_STATE_CHANGE },
    { EVENT_STA_CANDIDATE_CONNECT_CHANGE, WIFI_CBK_MSG_CANDIDATE_CONNECT_CHANGE },
};

/* ApCallBackNameEventIdMap */
static std::map<std::string, int> g_apCallBackNameEventIdMap = {
    { EVENT_HOTSPOT_STATE_CHANGE, WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE },
    { EVENT_HOTSPOT_STA_JOIN, WIFI_CBK_MSG_HOTSPOT_STATE_JOIN },
    { EVENT_HOTSPOT_STA_LEAVE, WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE },
};

/* P2PCallBackNameEventIdMap */
static std::map<std::string, int> g_p2pCallBackNameEventIdMap = {
    { EVENT_P2P_STATE_CHANGE, WIFI_CBK_MSG_P2P_STATE_CHANGE },
    { EVENT_P2P_PERSISTENT_GROUP_CHANGE, WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE },
    { EVENT_P2P_DEVICE_STATE_CHANGE, WIFI_CBK_MSG_THIS_DEVICE_CHANGE },
    { EVENT_P2P_PEER_DEVICE_CHANGE, WIFI_CBK_MSG_PEER_CHANGE },
    { EVENT_P2P_SERVICES_CHANGE, WIFI_CBK_MSG_SERVICE_CHANGE },
    { EVENT_P2P_CONN_STATE_CHANGE, WIFI_CBK_MSG_CONNECT_CHANGE },
    { EVENT_P2P_DISCOVERY_CHANGE, WIFI_CBK_MSG_DISCOVERY_CHANGE },
    { EVENT_P2P_ACTION_RESULT, WIFI_CBK_MSG_P2P_ACTION_RESULT },
    { EVENT_P2P_CONFIG_CHANGE, WIFI_CBK_MSG_CFG_CHANGE },
    { EVENT_P2P_GC_JOIN_GROUP, WIFI_CBK_MSG_P2P_GC_JOIN_GROUP},
    { EVENT_P2P_GC_LEAVE_GROUP, WIFI_CBK_MSG_P2P_GC_LEAVE_GROUP},
    { EVENT_P2P_PRIVATE_PEER_DEVICE_CHANGE, WIFI_CBK_MSG_PRIVATE_PEER_CHANGE},
    { EVENT_P2P_CHR_ERRCODE_REPORT, WIFI_CBK_MSG_P2P_CHR_ERRCODE_REPORT},
};

/**
 * @Description MAC address anonymization
 *
 * <p> eg: a2:7c:b0:98:e3:92 -> a2:7c:**:**:**:92
 *
 * @param str - Input MAC address
 * @return std::string - Processed MAC
 */
std::string MacAnonymize(const std::string str);

/**
 * @Description MAC address anonymization
 *
 * <p> eg: 192.168.0.1 -> 192.***.*.1
 *
 * @param str - Input MAC address
 * @return std::string - Processed MAC
 */
std::string IpAnonymize(const std::string str);

/**
 * @Description Ssid anonymization
 *
 * <p> a) Length less than or equal to 2, all bits are hidden;
 * b) Length less than or equal to 4, hiding the middle bit;
 * c) Length less than or equal to 8, hiding 3 bits from the second bit;
 * d) Length greater than or equal to 9, showing the first and last three bits, the middle bits are hidden
 * <p> eg:
 * 1 -> *
 * 12 -> **
 * 123 -> 1*3
 * 1234 -> 1**4
 * 12345 -> 1***5
 * 123456 -> 1***56
 * 1234567 -> 1***567
 * 12345678 -> 1***5678
 * 123456789 -> 123***789
 * 12345678910 -> 123*****910
 *
 * @param str - Input ssid
 * @return std::string - Processed ssid
 */
std::string SsidAnonymize(const std::string str);

/**
 * @Description Password anonymization
 *
 * Length greater than or equal to 8
 * <p> eg: 12345678 -> 12****78
 *
 * @param str - Input Password
 * @return std::string - Processed Password
 */
std::string PassWordAnonymize(const std::string str);

/**
 * @Description Converting string MAC to a C-style MAC address
 *
 * @param strMac - Input MAC address
 * @param mac - conversion result
 * @return errno_t - EOK for success, failure for other values.
 */
errno_t MacStrToArray(const std::string& strMac, unsigned char mac[WIFI_MAC_LEN]);

/**
 * @Description Converting C-style MAC to a string MAC
 *
 * @param mac - Input MAC address
 * @return string - conversion result.
 */
std::string MacArrayToStr(const unsigned char mac[WIFI_MAC_LEN]);

/**
 * @Description Check whether the array of MAC address is empty
 *
 * @param mac - Input MAC address
 * @return bool - true: empty, false: not empty
 */
bool IsMacArrayEmpty(const unsigned char mac[WIFI_MAC_LEN]);

/**
 * @Description Converting a string IP Address to an integer IP address
 *
 * @param strIp - Input string IP address
 * @return unsigned int - integer IP address
 */
unsigned int Ip2Number(const std::string& strIp);

/**
 * @Description Converting an integer IP address to a string IP Address
 *
 * @param intIp - Input integer IP address
 * @return string - string IP address
 */
std::string Number2Ip(unsigned int intIp);

/**
 * @Description Splitting strings by delimiter
 *
 * @param str - Input string
 * @param delim - Split delimiter
 * @return std::vector<std::string> - Split result
 */
std::vector<std::string> StrSplit(const std::string& str, const std::string& delim);

/**
  * @brief Returns the time, in seconds, since 1970-01-01 00:00:00 GMT
  *
  * @return Returns the time, in seconds
  */
int64_t GetCurrentTimeSeconds();

/**
 * @Description GetCurrentTimeSeconds since 1970-01-01 00:00:00 GMT
 *
 * @return Returns the time, in milliseconds
 */
int64_t GetCurrentTimeMilliSeconds();
/**
 * @Description GetElapsedMicrosecondsSinceBoot
 *
 * @return microseconds;
 */
int64_t GetElapsedMicrosecondsSinceBoot();

#ifndef OHOS_ARCH_LITE
/**
 * @Description get bundle name, it can only be obtained at the interfaces layer.
 *
 * @return bool - bundle name
 */
std::string GetBundleName();

std::string GetBundleAppIdByBundleName(const int callingUid, const std::string &bundleName);

/**
 * @Description whether the bundle is installed.
 *
 * @param std::string - bundle name
 * @return bool - true: installed
 */
bool IsBundleInstalled(const std::string &bundleName);

/**
 * @Description get bundle name by uid
 *
 * @param int - uid
 * @param std::string - bundle name
 * @return ErrCode - operation result
 */
ErrCode GetBundleNameByUid(const int uid, std::string &bundleName);

/**
 * @Description get bundle name by uid
 *
 * @param std::vector<std::string> - bundle name list
 * @return ErrCode - operation result
 */
ErrCode GetAllBundleName(std::vector<std::string> &bundleNameList);

/**
 * @Description get calling pid
 *
 * @return int - calling pid
 */
int GetCallingPid();

/**
 * @Description get calling uid
 *
 * @return int - calling uid
 */
int GetCallingUid();

/**
 * @Description get calling token id
 *
 * @return int - calling token id
 */
int GetCallingTokenId();

/**
 * @Description by Process uid ,the app is a wifi broker process
 *
 * @param uid - Input uid
 * @param pid - Input pid
 * @return string - Returns processname
 */
std::string GetBrokerProcessNameByPid(const int uid, const int pid);

/**
 * @Description set Process pid and processname
 *
 * @param pid - Input pid
 * @param processName - Input processName
 * @return void
 */
void SetWifiBrokerProcess(int pid, std::string processName);

/**
 * @Description Time consuming statistics
 *
 */
class TimeStats final {
public:
    TimeStats(const std::string desc);
    TimeStats() = delete;
    ~TimeStats();

private:
    std::string m_desc;
    std::chrono::steady_clock::time_point m_startTime;
};
#endif

/**
 * @Description Convert frequency to channel
 *
 * @return int - channel
 */
int FrequencyToChannel(int freq);

/**
 * @Description Convert channel to frequency
 *
 * @return int - frequency
 */
int ChannelToFrequency(int channel);
bool IsOtherVapConnect();
bool IsBeaconLost(std::string bssid, WifiSignalPollInfo checkInfo);
bool IsBeaconAbnormal(std::string bssid, WifiSignalPollInfo checkInfo);
int HexString2Byte(const char *hex, uint8_t *buf, size_t len);
void Byte2HexString(const uint8_t* byte, uint8_t bytesLen, char* hexstr, uint8_t hexstrLen);
bool DecodeBase64(const std::string &input, std::vector<uint8_t> &output);
std::string EncodeBase64(const std::vector<uint8_t> &input);
std::vector<std::string> GetSplitInfo(const std::string &input, const std::string &delimiter);
std::string HexToString(const std::string &str);
std::string StringToHex(const std::string &data);
int CheckDataLegal(std::string &data, int base = DECIMAL_NOTATION);
int CheckDataLegalBin(const std::string &data);
int CheckDataLegalHex(const std::string &data);
unsigned int CheckDataToUint(std::string &data, int base = DECIMAL_NOTATION);
long long CheckDataTolonglong(std::string &data, int base = DECIMAL_NOTATION);
uint32_t GenerateStandardErrCode(uint8_t subSystem, uint16_t errCode);
unsigned long StringToUlong(const std::string &word);
float StringToFloat(const std::string &word);
double StringToDouble(const std::string &word);
/**
 * @Description Internal HiLinkNetwork Type To Bool
 *
 * @return bool - isHiLinkNetwork
 */
bool InternalHiLinkNetworkToBool(int isHiLinkNetwork);

std::string Ipv4IntAnonymize(uint32_t ipInt);

std::string Ipv6Anonymize(std::string str);
}  // namespace Wifi
}  // namespace OHOS
#endif