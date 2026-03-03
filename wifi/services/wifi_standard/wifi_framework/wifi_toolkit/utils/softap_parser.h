/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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
#ifndef SOFTAP_PARSER
#define SOFTAP_PARSER
#include "xml_parser.h"
#include <unordered_map>
#include "wifi_ap_msg.h"

inline constexpr auto XML_TAG_HEADER_SOFTAP = "SoftAp";
inline constexpr auto XML_TAG_SOFTAP_SSID = "SSID";
inline constexpr auto XML_SECURITY_TYPE = "SecurityType";
inline constexpr auto XML_PASSPHRASE = "Passphrase";
inline constexpr auto XML_BAND_CHANNEL_MAP = "BandChannelMap";
inline constexpr auto XML_BAND_CHANNEL = "BandChannel";
inline constexpr auto XML_BAND = "Band";
inline constexpr auto XML_CHANNEL = "Channel";

enum class HotspotConfigType {
    SOFTAP_SSID = 0,
    SECURITYTYPE,
    PASSPHRASE,
    UNUSED,
};

inline const std::unordered_map<std::string, HotspotConfigType> g_hotspotConfigMap = {
    {XML_TAG_SOFTAP_SSID, HotspotConfigType::SOFTAP_SSID},
    {XML_SECURITY_TYPE, HotspotConfigType::SECURITYTYPE},
    {XML_PASSPHRASE, HotspotConfigType::PASSPHRASE},
};

namespace OHOS {
namespace Wifi {
class SoftapXmlParser : public XmlParser {
public:
    SoftapXmlParser() = default;
    ~SoftapXmlParser() override;

    /**
     * @Description get softap configs
     *
     * @return std::vector<HotspotConfig> - softap configs
    */
    std::vector<HotspotConfig> GetSoftapConfigs();
private:
    HotspotConfig hotspotConfig{};

    bool ParseInternal(xmlNodePtr node) override;
    HotspotConfigType GetConfigNameAsInt(xmlNodePtr node);
    xmlNodePtr GotoSoftApNode(xmlNodePtr innode);
    void GetBandInfo(xmlNodePtr innode);
    void TransBandinfo(xmlNodePtr innode);
    void ParseSoftap(xmlNodePtr innode);
};
}
}
#endif