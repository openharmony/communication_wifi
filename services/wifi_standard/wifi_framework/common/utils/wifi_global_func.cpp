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
#include "wifi_global_func.h"
#include <algorithm>
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_COMMON_GLOBAL_FUNC"

namespace OHOS {
namespace Wifi {
ErrCode CfgCheckSsid(const HotspotConfig &cfg)
{
    if (cfg.GetSsid().length() < MIN_SSID_LEN || cfg.GetSsid().length() > MAX_SSID_LEN) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode CfgCheckPsk(const HotspotConfig &cfg)
{
    if (cfg.GetPreSharedKey().length() < MIN_PSK_LEN || cfg.GetPreSharedKey().length() > MAX_PSK_LEN) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode CfgCheckBand(const HotspotConfig &cfg, std::vector<BandType> &bandsFromCenter)
{
    for (auto it = bandsFromCenter.begin(); it != bandsFromCenter.end(); ++it) {
        if (cfg.GetBand() == *it) {
            return ErrCode::WIFI_OPT_SUCCESS;
        }
    }
    return ErrCode::WIFI_OPT_INVALID_PARAM;
}

ErrCode CfgCheckChannel(const HotspotConfig &cfg, ChannelsTable &channInfoFromCenter)
{
    std::vector<int32_t> channels = channInfoFromCenter[static_cast<BandType>(cfg.GetBand())];
    auto it = find(channels.begin(), channels.end(), cfg.GetChannel());
    return ((it == channels.end()) ? ErrCode::WIFI_OPT_INVALID_PARAM : ErrCode::WIFI_OPT_SUCCESS);
}

ErrCode CfgCheckMaxconnum(const HotspotConfig &cfg)
{
    if (cfg.GetMaxConn() < 1 || cfg.GetMaxConn() > MAX_AP_CONN) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode IsValidHotspotConfig(const HotspotConfig &cfg, const HotspotConfig &cfgFromCenter,
    std::vector<BandType> &bandsFromCenter, ChannelsTable &channInfoFromCenter)
{
    if (CfgCheckSsid(cfg) == ErrCode::WIFI_OPT_INVALID_PARAM) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    if (cfg.GetSecurityType() == KeyMgmt::NONE) {
        if (cfg.GetPreSharedKey().length() > 0) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    } else if (cfg.GetSecurityType() == KeyMgmt::WPA_PSK || cfg.GetSecurityType() == KeyMgmt::WPA2_PSK) {
        if (CfgCheckPsk(cfg) == ErrCode::WIFI_OPT_INVALID_PARAM) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    } else {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    if (cfg.GetBand() != cfgFromCenter.GetBand()) {
        if (CfgCheckBand(cfg, bandsFromCenter) == ErrCode::WIFI_OPT_INVALID_PARAM) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    }

    if (cfg.GetChannel() != cfgFromCenter.GetChannel()) {
        if (CfgCheckChannel(cfg, channInfoFromCenter) == ErrCode::WIFI_OPT_INVALID_PARAM) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    }

    if (CfgCheckMaxconnum(cfg) == ErrCode::WIFI_OPT_INVALID_PARAM) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

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

bool IsAllowScanAnyTime(const ScanControlInfo &info)
{
    auto forbidIter = info.scanForbidMap.find(SCAN_SCENE_ALL);
    for (; forbidIter != info.scanForbidMap.end(); forbidIter++) {
        for (auto iter = forbidIter->second.begin(); iter != forbidIter->second.end(); iter++) {
            if (iter->scanMode == ScanMode::ANYTIME_SCAN) {
                return false;
            }
        }
    }
    return true;
}

ConnectionState ConvertConnStateInternal(OperateResState resState)
{
    switch (resState) {
        case OperateResState::CONNECT_CONNECTING:
            return ConnectionState::CONNECT_CONNECTING;
        case OperateResState::CONNECT_AP_CONNECTED:
            return ConnectionState::CONNECT_AP_CONNECTED;
        case OperateResState::CONNECT_CHECK_PORTAL:
            return ConnectionState::CONNECT_CHECK_PORTAL;
        case OperateResState::CONNECT_NETWORK_ENABLED:
            return ConnectionState::CONNECT_NETWORK_ENABLED;
        case OperateResState::CONNECT_NETWORK_DISABLED:
            return ConnectionState::CONNECT_NETWORK_DISABLED;
        case OperateResState::DISCONNECT_DISCONNECTING:
            return ConnectionState::DISCONNECT_DISCONNECTING;
        case OperateResState::DISCONNECT_DISCONNECT_FAILED:
            return ConnectionState::DISCONNECT_DISCONNECT_FAILED;
        case OperateResState::DISCONNECT_DISCONNECTED:
            return ConnectionState::DISCONNECT_DISCONNECTED;
        case OperateResState::CONNECT_PASSWORD_WRONG:
            return ConnectionState::CONNECT_PASSWORD_WRONG;
        case OperateResState::CONNECT_CONNECTING_TIMEOUT:
            return ConnectionState::CONNECT_CONNECTING_TIMEOUT;
        default:
            return ConnectionState::UNKNOWN;
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
}  // namespace Wifi
}  // namespace OHOS
