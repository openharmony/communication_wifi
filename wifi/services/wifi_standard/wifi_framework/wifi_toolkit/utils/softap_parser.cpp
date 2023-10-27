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

#include "softap_parser.h"
#include "wifi_logger.h"
#include "wifi_global_func.h"

DEFINE_WIFILOG_LABEL("SoftapParser");
namespace OHOS {
namespace Wifi {
SoftapXmlParser::~SoftapXmlParser()
{
}

bool SoftapXmlParser::ParseInternal(xmlNodePtr node)
{
    if (IsDocValid(node) != true) {
        WIFI_LOGI("ParseInternal error");
        return false;
    }
    xmlNodePtr softapNode = GotoSoftApNode(node);
    ParseSoftap(softapNode);
    return true;
}

xmlNodePtr SoftapXmlParser::GotoSoftApNode(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetNodeValue(node) == XML_TAG_HEADER_SOFTAP) {
            return node;
        }
    }
    return nullptr;
}

void SoftapXmlParser::ParseSoftap(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case HotspotConfigType::SOFTAP_SSID: {
                hotspotConfig.SetSsid(GetStringValue(node));
                break;
            }
            case HotspotConfigType::SECURITYTYPE: {
                if (GetPrimValue<int>(node, PrimType::INT) == 1) {
                    hotspotConfig.SetSecurityType(KeyMgmt::WPA2_PSK);
                } else {
                    hotspotConfig.SetSecurityType(KeyMgmt::NONE);
                }
                break;
            }
            case HotspotConfigType::PASSPHRASE: {
                hotspotConfig.SetPreSharedKey(GetStringValue(node));
                break;
            }
            default: {
                break;
            }
        }
        GetBandInfo(node);
    }
}

HotspotConfigType SoftapXmlParser::GetConfigNameAsInt(xmlNodePtr node)
{
    std::string tagName = GetNameValue(node);
    if (g_hotspotConfigMap.find(tagName) != g_hotspotConfigMap.end()) {
        return g_hotspotConfigMap.at(tagName);
    }
    return HotspotConfigType::UNUSED;
}

void SoftapXmlParser::TransBandinfo(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetNameValue(node) == XML_BAND) {
            int band = GetPrimValue<int>(node, PrimType::INT);
            if (band == 1) {
                hotspotConfig.SetBand(BandType::BAND_2GHZ);
            } else {
                hotspotConfig.SetBand(BandType::BAND_5GHZ);
            }
        }
    }
}

void SoftapXmlParser::GetBandInfo(xmlNodePtr innode)
{
    if (innode == nullptr || GetNodeValue(innode) != XML_BAND_CHANNEL_MAP) {
        return;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetNodeValue(node) == XML_BAND_CHANNEL) {
            TransBandinfo(node);
        }
    }
}

std::vector<HotspotConfig> SoftapXmlParser::GetSoftapConfigs()
{
    std::vector<HotspotConfig> hotspotConfigs{};
    hotspotConfigs.push_back(hotspotConfig);
    return hotspotConfigs;
}
}
}