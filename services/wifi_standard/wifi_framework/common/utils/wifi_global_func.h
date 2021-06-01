/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_scan_msg.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
constexpr int MAC_STRING_SIZE = 17;
constexpr int MIN_SSID_LEN = 1;
constexpr int MAX_SSID_LEN = 32;
constexpr int MIN_PSK_LEN = 8;
constexpr int MAX_PSK_LEN = 63;
constexpr int HEX_TYPE_LEN = 3; /* 3 hex type: 0 a A */
constexpr int MAX_AP_CONN = 32;

/**
 * @Description Check valid ssid config
 *
 * @param cfg - HotspotConfig
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode CfgCheckSsid(const HotspotConfig &cfg);

/**
 * @Description Check valid psk config
 *
 * @param cfg - HotspotConfig
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode CfgCheckPsk(const HotspotConfig &cfg);

/**
 * @Description Check valid band config
 *
 * @param cfg - HotspotConfig
 * @param bandsFromCenter - vector of BandType
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode CfgCheckBand(const HotspotConfig &cfg, std::vector<BandType> &bandsFromCenter);

/**
 * @Description Check valid channel config
 *
 * @param cfg - HotspotConfig
 * @param channInfoFromCenter - ChannelsTable object
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode CfgCheckChannel(const HotspotConfig &cfg, ChannelsTable &channInfoFromCenter);

/**
 * @Description Check valid connect number config
 *
 * @param cfg - HotspotConfig
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode CfgCheckMaxconnum(const HotspotConfig &cfg);

/**
 * @Description Check valid hotspot config
 *
 * @param cfg - HotspotConfig
 * @param cfgFromCenter - Get HotspotConfig from config center
 * @param bandsFromCenter - vector of BandType
 * @param channInfoFromCenter - ChannelsTable object
 * @return ErrCode - WIFI_OPT_SUCCESS or others
 */
ErrCode IsValidHotspotConfig(const HotspotConfig &cfg, const HotspotConfig &cfgFromCenter,
    std::vector<BandType> &bandsFromCenter, ChannelsTable &channInfoFromCenter);

/**
 * @Description Get a random string
 *
 * @param len - Random string length
 * @return std::string - Random String
 */
std::string GetRandomStr(int len);

/**
 * @Description If allowed scan always according the scan control policy
 *
 * @param info - ScanControlInfo object
 * @return true - allowed
 * @return false - not allowed
 */
bool IsAllowScanAnyTime(const ScanControlInfo &info);

/**
 * @Description Internal transition from OperateResState struct to ConnectionState
 *
 * @param resState - OperateResState state
 * @return ConnectionState - convert output connection state
 */
ConnectionState ConvertConnStateInternal(OperateResState resState);

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
}  // namespace Wifi
}  // namespace OHOS
#endif