/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "wifi_app_parser.h"
#include <unordered_map>
#include "wifi_common_def.h"
#include "wifi_config_file_impl.h"
#include <algorithm>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiAppXmlParser");

constexpr auto WIFI_MONITOR_APP_FILE_PATH = "/system/etc/wifi/wifi_monitor_apps.xml";
constexpr auto XML_TAG_SECTION_HEADER_MONITOR_APP = "MonitorAPP";
constexpr auto XML_TAG_SECTION_HEADER_GAME_INFO = "GameInfo";
constexpr auto XML_TAG_SECTION_HEADER_APP_WHITE_LIST = "AppWhiteList";
constexpr auto XML_TAG_SECTION_HEADER_APP_BLACK_LIST = "AppBlackList";
constexpr auto XML_TAG_SECTION_HEADER_CHARIOT_APP = "ChariotApp";
constexpr auto XML_TAG_SECTION_HEADER_HIGH_TEMP_LIMIT_SPEED_APP = "HighTempLimitSpeedApp";

constexpr auto XML_TAG_SECTION_KEY_GAME_NAME = "gameName";
constexpr auto XML_TAG_SECTION_KEY_PACKAGE_NAME = "packageName";

const std::unordered_map<std::string, AppType> appTypeMap = {
    { XML_TAG_SECTION_HEADER_GAME_INFO, AppType::LOW_LATENCY_APP },
    { XML_TAG_SECTION_HEADER_APP_WHITE_LIST, AppType::WHITE_LIST_APP },
    { XML_TAG_SECTION_HEADER_APP_BLACK_LIST, AppType::BLACK_LIST_APP },
    { XML_TAG_SECTION_HEADER_CHARIOT_APP, AppType::CHARIOT_APP },
    {XML_TAG_SECTION_HEADER_HIGH_TEMP_LIMIT_SPEED_APP, AppType::HIGH_TEMP_LIMIT_SPEED_APP},
};

AppParser::AppParser()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
    if (InitAppParser(WIFI_MONITOR_APP_FILE_PATH)) {
        WIFI_LOGD("%{public}s InitAppParser successful", __FUNCTION__);
    } else {
        WIFI_LOGE("%{public}s InitAppParser fail", __FUNCTION__);
    };
}

AppParser::~AppParser()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

AppParser &AppParser::GetInstance()
{
    static AppParser instance;
    return instance;
}

bool AppParser::IsLowLatencyApp(const std::string &bundleName) const
{
    return std::any_of(m_lowLatencyAppVec.begin(), m_lowLatencyAppVec.end(),
        [bundleName](const LowLatencyAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsWhiteListApp(const std::string &bundleName) const
{
    return std::any_of(m_whiteAppVec.begin(), m_whiteAppVec.end(),
        [bundleName](const WhiteListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsBlackListApp(const std::string &bundleName) const
{
    return std::any_of(m_blackAppVec.begin(), m_blackAppVec.end(),
        [bundleName](const BlackListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsChariotApp(const std::string &bundleName) const
{
    return std::any_of(m_chariotAppVec.begin(), m_chariotAppVec.end(),
        [bundleName](const ChariotAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsHighTempLimitSpeedApp(const std::string &bundleName) const
{
    return std::any_of(m_highTempLimitSpeedAppVec.begin(), m_highTempLimitSpeedAppVec.end(),
        [bundleName](const HighTempLimitSpeedAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::InitAppParser(const char *appXmlFilePath)
{
    if (appXmlFilePath == nullptr) {
        WIFI_LOGE("%{public}s appXmlFilePath is null", __FUNCTION__);
        return false;
    }
    if (!std::filesystem::exists(appXmlFilePath)) {
        WIFI_LOGE("%{public}s %{public}s not exists", __FUNCTION__, appXmlFilePath);
        return false;
    }
    bool ret = LoadConfiguration(appXmlFilePath);
    if (!ret) {
        WIFI_LOGE("%{public}s load failed", __FUNCTION__);
        return ret;
    }
    ret = Parse();
    if (!ret) {
        WIFI_LOGE("%{public}s parse failed", __FUNCTION__);
        return ret;
    }
    WIFI_LOGD("%{public}s, wifi monitor app xml parsed successfully", __FUNCTION__);
    return ret;
}

bool AppParser::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("%{public}s node is null", __FUNCTION__);
        return false;
    }
    ParseAppList(node);
    return true;
}

void AppParser::ParseAppList(const xmlNodePtr &innode)
{
    if (xmlStrcmp(innode->name, BAD_CAST(XML_TAG_SECTION_HEADER_MONITOR_APP)) != 0) {
        WIFI_LOGE("innode name=%{public}s not equal MonitorAPP", innode->name);
        return;
    }
    m_lowLatencyAppVec.clear();
    m_whiteAppVec.clear();
    m_blackAppVec.clear();
    m_chariotAppVec.clear();
    m_highTempLimitSpeedAppVec.clear();
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetAppTypeAsInt(node)) {
            case AppType::LOW_LATENCY_APP:
                m_lowLatencyAppVec.push_back(ParseLowLatencyAppInfo(node));
                break;
            case AppType::WHITE_LIST_APP:
                m_whiteAppVec.push_back(ParseWhiteAppInfo(node));
                break;
            case AppType::BLACK_LIST_APP:
                m_blackAppVec.push_back(ParseBlackAppInfo(node));
                break;
            case AppType::CHARIOT_APP:
                m_chariotAppVec.push_back(ParseChariotAppInfo(node));
                break;
            case AppType::HIGH_TEMP_LIMIT_SPEED_APP:
                m_highTempLimitSpeedAppVec.push_back(ParseHighTempLimitSpeedAppInfo(node));
                break;
            default:
                WIFI_LOGD("app type: %{public}s is not monitored", GetNodeValue(node).c_str());
                break;
        }
    }
}

LowLatencyAppInfo AppParser::ParseLowLatencyAppInfo(const xmlNodePtr &innode)
{
    LowLatencyAppInfo appInfo;
    std::string gameName =
        std::string(reinterpret_cast<char *>(xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_GAME_NAME))));
    appInfo.packageName = gameName;
    return appInfo;
}

WhiteListAppInfo AppParser::ParseWhiteAppInfo(const xmlNodePtr &innode)
{
    WhiteListAppInfo appInfo;
    appInfo.packageName =
        std::string(reinterpret_cast<char *>(xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME))));
    return appInfo;
}

BlackListAppInfo AppParser::ParseBlackAppInfo(const xmlNodePtr &innode)
{
    BlackListAppInfo appInfo;
    appInfo.packageName =
        std::string(reinterpret_cast<char *>(xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME))));
    return appInfo;
}

ChariotAppInfo AppParser::ParseChariotAppInfo(const xmlNodePtr &innode)
{
    ChariotAppInfo appInfo;
    appInfo.packageName =
        std::string(reinterpret_cast<char *>(xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME))));
    return appInfo;
}

HighTempLimitSpeedAppInfo AppParser::ParseHighTempLimitSpeedAppInfo(const xmlNodePtr &innode)
{
    HighTempLimitSpeedAppInfo appInfo;
    appInfo.packageName =
        std::string(reinterpret_cast<char *>(xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME))));
    return appInfo;
}

AppType AppParser::GetAppTypeAsInt(const xmlNodePtr &innode)
{
    std::string tagName = GetNodeValue(innode);
    if (appTypeMap.find(tagName) != appTypeMap.end()) {
        return appTypeMap.at(tagName);
    }
    WIFI_LOGD("%{public}s not find targName:%{public}s in appTypeMap", __FUNCTION__, tagName.c_str());
    return AppType::OTHER_APP;
}


} // namespace Wifi
} // namespace OHOS