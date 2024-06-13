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

#ifndef OHOS_WIFI_AP_MSG_H
#define OHOS_WIFI_AP_MSG_H
#include <cstdint>
#include <set>
#include <string>
#include "wifi_common_msg.h"

namespace OHOS {
namespace Wifi {
#define AP_CHANNEL_INVALID (-1)
#define AP_CHANNEL_DEFAULT 6
#define AP_CHANNEL_5G_DEFAULT 149
#define AP_CHANNEL_5G_NOT_RECOMMEND (165)  // cannot group bandwidth of 40M or above
#define WIFI_BSSID_LENGTH 18
#define DHCP_LEASE_TIME_MIN 60
#define DHCP_LEASE_TIME 21600
#define WIFI_SSID_MAX_LEN 32
#define WIFI_IP_MAX_LEN 15
#define AP_BANDWIDTH_DEFAULT 0
#define AP_BANDWIDTH_160 8
#define AP_BANDWIDTH_5G_160M_DEFAULT 36
#define AP_BANDWIDTH_5G_160M_SET_BEGIN 36
#define AP_BANDWIDTH_5G_160M_SET_END 48
enum class ApState {
    AP_STATE_NONE = 0,
    AP_STATE_IDLE,
    AP_STATE_STARTING,
    AP_STATE_STARTED,
    AP_STATE_CLOSING,
    AP_STATE_CLOSED,
};

/* Encryption Mode */
enum class KeyMgmt {
    NONE = 0,
    WPA_PSK = 1,
    WPA_EAP = 2,
    IEEE8021X = 3,
    WPA2_PSK = 4,
    OSEN = 5,
    FT_PSK = 6,
    FT_EAP = 7
};

enum class BandType {
    BAND_NONE = 0, /* unknown */
    BAND_2GHZ = 1, /* 2.4GHz */
    BAND_5GHZ = 2, /* 5GHz */
    BAND_6GHZ = 3, /* 6GHz */
    BAND_60GHZ = 4, /* 60GHz */
    BAND_ANY = 5, /* Dual-mode frequency band */
};

enum class PowerModel {
    SLEEPING = 0, /* Sleeping model. */
    GENERAL = 1, /* General model. */
    THROUGH_WALL = 2, /* Through wall model. */
};

struct HotspotConfig {
    HotspotConfig()
    {
        securityType = KeyMgmt::WPA2_PSK;
        band = BandType::BAND_2GHZ;
        channel = AP_CHANNEL_DEFAULT;
        maxConn = -1;
        leaseTime = DHCP_LEASE_TIME;
        apBandWidth = AP_BANDWIDTH_DEFAULT;
    }

    inline void SetSsid(const std::string &newSsid)
    {
        ssid = newSsid;
    }
    inline const std::string &GetSsid() const
    {
        return ssid;
    }

    inline void SetPreSharedKey(const std::string &newKey)
    {
        preSharedKey = newKey;
    }
    inline const std::string &GetPreSharedKey() const
    {
        return preSharedKey;
    }

    inline void SetSecurityType(KeyMgmt type)
    {
        securityType = type;
    }
    inline KeyMgmt GetSecurityType() const
    {
        return securityType;
    }

    inline void SetBand(BandType newBand)
    {
        band = newBand;
    }
    inline BandType GetBand() const
    {
        return band;
    }

    inline void SetBandWidth(int32_t bandWidth)
    {
        apBandWidth = bandWidth;
    }
    inline int32_t GetBandWidth() const
    {
        return apBandWidth;
    }
    inline void SetChannel(int32_t newchannel)
    {
        channel = newchannel;
    }
    inline int32_t GetChannel() const
    {
        return channel;
    }

    inline void SetMaxConn(int32_t newMaxConn)
    {
        maxConn = newMaxConn;
    }
    inline int32_t GetMaxConn() const
    {
        return maxConn;
    }

    inline void SetIpAddress(const std::string &newIpAddress)
    {
        ipAddress = newIpAddress;
    }

    inline const std::string &GetIpAddress() const
    {
        return ipAddress;
    }

    inline void SetLeaseTime(int32_t newLeaseTime)
    {
        leaseTime = newLeaseTime;
    }

    inline int32_t GetLeaseTime() const
    {
        return leaseTime;
    }
private:
    std::string ssid;         /* Hotspot name, The string length range is 1~32 */
    std::string preSharedKey; /* Hotspot password ,The string length range is 8~63 */
    KeyMgmt securityType;     /* Hotspot Encryption type, Optional NONE/WPA_PSK/WPA2_PSK */
    BandType band;
    int32_t channel;
    int32_t maxConn;
    std::string ipAddress;    /* Hotspot IP address of the dhcp server */
    int32_t leaseTime;
    int32_t apBandWidth;
};

struct StationInfo {
    std::string deviceName; /* Device name */
    std::string bssid;      /* Device Mac */
    int bssidType; /* bssid type */
    std::string ipAddr;     /* Device IP address */
};
}  // namespace Wifi
}  // namespace OHOS
#endif