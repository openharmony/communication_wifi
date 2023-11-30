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

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("SoftapParser");
const int BAND_2GHZ = 1 << 0;
const int SECURITY_TYPE_WPA2_PSK = 1;

SoftapXmlParser::~SoftapXmlParser()
{
}

bool SoftapXmlParser::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseInternal node null");
        return false;
    }
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
    if (innode == nullptr) {
        WIFI_LOGE("GotoSoftApNode node null");
        return nullptr;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetNodeValue(node) == XML_TAG_HEADER_SOFTAP) {
            return node;
        }
    }
    return nullptr;
}

void SoftapXmlParser::ParseSoftap(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("ParseSoftap node null");
        return;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case HotspotConfigType::SOFTAP_SSID: {
                hotspotConfig.SetSsid(GetStringValue(node));
                break;
            }
            case HotspotConfigType::SECURITYTYPE: {
                if (GetPrimValue<int>(node, PrimType::INT) == SECURITY_TYPE_WPA2_PSK) {
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
    hotspotConfig.SetMaxConn(MAX_AP_CONN);
}

HotspotConfigType SoftapXmlParser::GetConfigNameAsInt(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("GetConfigNameAsInt node null");
        return HotspotConfigType::UNUSED;
    }
    std::string tagName = GetNameValue(node);
    if (g_hotspotConfigMap.find(tagName) != g_hotspotConfigMap.end()) {
        return g_hotspotConfigMap.at(tagName);
    }
    return HotspotConfigType::UNUSED;
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

void SoftapXmlParser::TransBandinfo(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("TransBandinfo node null");
        return;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetNameValue(node) == XML_BAND) {
            int band = GetPrimValue<int>(node, PrimType::INT);
            if (band == BAND_2GHZ) {
                hotspotConfig.SetBand(BandType::BAND_2GHZ);
            } else {
                hotspotConfig.SetBand(BandType::BAND_5GHZ);
            }
        }
    }
}

std::vector<HotspotConfig> SoftapXmlParser::GetSoftapConfigs()
{
    std::vector<HotspotConfig> hotspotConfigs{};
    if (hotspotConfig.GetSecurityType() == KeyMgmt::NONE) {
        return hotspotConfigs;
    }
    hotspotConfigs.push_back(hotspotConfig);
    return hotspotConfigs;
}
}
}