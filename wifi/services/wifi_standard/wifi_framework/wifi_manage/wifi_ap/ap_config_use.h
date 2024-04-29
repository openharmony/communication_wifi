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

#ifndef OHOS_AP_CONFIG_UTIL_H
#define OHOS_AP_CONFIG_UTIL_H

#include <vector>
#include <map>
#include "ap_define.h"
#include "ap_macro.h"
#include "wifi_ap_msg.h"
#include "xml_parser.h"

namespace OHOS {
namespace Wifi {
class ApConfigUse {
    FRIEND_GTEST(ApIdleState);
public:
    /**
     * @Description  construction method
     *
     * @param None
     * @return None
     */
    explicit ApConfigUse(int id = 0);

    /**
     * @Description  destructor method
     *
     * @param None
     * @return None
     */
    virtual ~ApConfigUse() = default;

    /**
     * @Description update ap channel config
     *
     * @param apConfig - ap configuration input
     */
    void UpdateApChannelConfig(HotspotConfig &apConfig) const;
private:
    static constexpr int DEFAULT_STA_INSTANCE_ID = 0;

    class SoftapChannelPolicyParser : public XmlParser {
    public:
        enum class SoftapChannelsPolicyType {
            UNVALID,
            COUNTRY_CODE,
            INDOOR_CHANNELS
        };
        static constexpr const char* SOFTAP_CHANNELS_POLICY_FILE_PATH = "/system/etc/wifi/softap_channels_policy.xml";
        static constexpr const char* XML_TAG_SOFTAP_CHANNELS_POLICY = "SoftapChannelsPolicy";
        static constexpr const char* XML_TAG_CHANNELS_POLICY = "CountryPolicy";
        static constexpr const char* XML_TAG_POLICY_ITEM = "PolicyItem";
        static constexpr const char* XML_TAG_COUNTRY_CODE = "CountryCode";
        static constexpr const char* XML_TAG_INDOOR_CHANNELS = "IndoorChannels";
        static constexpr const char* XML_TAG_SOFTAP_SUPPORT_CHANNELS = "SoftapSupportChannels";
        static constexpr const char* XML_TAG_CHANNEL_2G_LIST = "Channel2gList";
        static constexpr const char* XML_TAG_CHANNEL_5G_LIST = "Channel5gList";
        static constexpr const char* XML_TAG_CHANNEL_6G_LIST = "Channel6gList";
        static constexpr const char* XML_TAG_CHANNEL_60G_LIST = "Channel60gList";

        SoftapChannelPolicyParser();
        ~SoftapChannelPolicyParser();
        std::map<std::string, std::set<int>> GetAllIndoorChannels() const;
        std::map<BandType, std::vector<int>> GetAllPreferredChannels() const;
    private:
        std::map<std::string, std::set<int>> m_indoorChannels;
        std::map<BandType, std::vector<int>> m_preferredChannels;
        std::unordered_map<std::string, SoftapChannelPolicyParser::SoftapChannelsPolicyType> g_softapChannelsPolicyMap;
        std::unordered_map<std::string, BandType> g_bandTypeMap;

        bool InitParser();
        bool ParseInternal(xmlNodePtr node) override;
        void ParseCountryPolicyList(xmlNodePtr innode);
        void ParsePreferredChannelsList(xmlNodePtr innode);
        std::set<int> ParseChannels(xmlNodePtr innode);
        xmlNodePtr GotoCountryPolicy(xmlNodePtr innode) const;
        ApConfigUse::SoftapChannelPolicyParser::SoftapChannelsPolicyType GetPolicyItem(xmlNodePtr node);
        xmlNodePtr GotoSoftapSupportChannels(xmlNodePtr innode) const;
        BandType GetSupportChannelsItem(xmlNodePtr node);
        std::vector<int> ParseSupportChannels(xmlNodePtr innode, const char* const &bandXml);
    };
    int m_id;
    std::unique_ptr<SoftapChannelPolicyParser> m_softapChannelPolicyPtr;
    std::map<std::string, std::set<int>> m_softapIndoorChannels;
    std::map<BandType, std::vector<int>> m_softapPreferredChannels;
    DISALLOW_COPY_AND_ASSIGN(ApConfigUse)

    int GetBestChannelFor2G() const;
    int GetBestChannelFor5G(HotspotConfig &apConfig) const;
    std::vector<int> GetChannelFromDrvOrXmlByBand(const BandType &bandType) const;
    void FilterIndoorChannel(std::vector<int> &channels) const;
    void Filter165Channel(std::vector<int> &channels) const;
    void JudgeDbacWithP2p(HotspotConfig &apConfig) const;
    std::set<int> GetIndoorChanByCountryCode(const std::string &countryCode) const;
    std::vector<int> GetPreferredChannelByBand(const BandType &bandType) const;
};
}  // namespace Wifi
}  // namespace OHOS
#endif