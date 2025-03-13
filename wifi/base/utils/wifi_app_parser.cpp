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
#include "wifi_app_parser.h"
#include <unordered_map>
#include "wifi_common_def.h"
#include "wifi_config_file_impl.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiAppXmlParser");

constexpr auto WIFI_MONITOR_APP_FILE_PATH = "/system/etc/wifi/wifi_monitor_apps.xml";
constexpr auto WIFI_NETWORK_CONTROL_APP_FILE_PATH = "/system/etc/wifi/wifi_network_control_apps.xml";
constexpr auto XML_TAG_SECTION_HEADER_MONITOR_APP = "MonitorAPP";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK_CONTROL_APP = "NetworkControlAPP";
constexpr auto XML_TAG_SECTION_HEADER_GAME_INFO = "GameInfo";
constexpr auto XML_TAG_SECTION_HEADER_APP_WHITE_LIST = "AppWhiteList";
constexpr auto XML_TAG_SECTION_HEADER_APP_BLACK_LIST = "AppBlackList";
constexpr auto XML_TAG_SECTION_HEADER_MULTILINK_BLACK_LIST = "MultiLinkBlackList";
constexpr auto XML_TAG_SECTION_HEADER_CHARIOT_APP = "ChariotApp";
constexpr auto XML_TAG_SECTION_HEADER_HIGH_TEMP_LIMIT_SPEED_APP = "HighTempLimitSpeedApp";
constexpr auto XML_TAG_SECTION_HEADER_APP_KEY_FOREGROUND_LIST = "KeyAppForegroundList";
constexpr auto XML_TAG_SECTION_HEADER_APP_KEY_BACKGROUND_LIMIT_LIST = "KeyBackgroundLimitListApp";
constexpr auto XML_TAG_SECTION_HEADER_APP_LIVE_STREAM_LIST = "AppLiveStream";
constexpr auto XML_TAG_SECTION_HEADER_APP_GAME_BACKGROUND_LIMIT_LIST = "GameBackgroundLimitListApp";
constexpr auto XML_TAG_SECTION_HEADER_ASYNC_DELAY_TIME = "AsyncDelayTime";
constexpr auto XML_TAG_SECTION_KEY_GAME_RTT = "mGameRtt";
constexpr auto XML_TAG_SECTION_KEY_GAME_NAME = "gameName";
constexpr auto XML_TAG_SECTION_KEY_PACKAGE_NAME = "packageName";
constexpr auto XML_TAG_SECTION_KEY_DELAY_TIME = "delayTime";
constexpr auto XML_VERSION_NODE_NAME = "HighTempLimitSpeedAppVersionInfo";

const std::unordered_map<std::string, AppType> appTypeMap = {
    { XML_TAG_SECTION_HEADER_GAME_INFO, AppType::LOW_LATENCY_APP },
    { XML_TAG_SECTION_HEADER_APP_WHITE_LIST, AppType::WHITE_LIST_APP },
    { XML_TAG_SECTION_HEADER_APP_BLACK_LIST, AppType::BLACK_LIST_APP },
    { XML_TAG_SECTION_HEADER_MULTILINK_BLACK_LIST, AppType::MULTILINK_BLACK_LIST_APP },
    { XML_TAG_SECTION_HEADER_CHARIOT_APP, AppType::CHARIOT_APP },
    {XML_TAG_SECTION_HEADER_HIGH_TEMP_LIMIT_SPEED_APP, AppType::HIGH_TEMP_LIMIT_SPEED_APP},
    { XML_TAG_SECTION_HEADER_APP_KEY_FOREGROUND_LIST, AppType::KEY_FOREGROUND_LIST_APP},
    { XML_TAG_SECTION_HEADER_APP_KEY_BACKGROUND_LIMIT_LIST, AppType::KEY_BACKGROUND_LIMIT_LIST_APP},
    { XML_TAG_SECTION_HEADER_ASYNC_DELAY_TIME, AppType::ASYNC_DELAY_TIME},
    { XML_TAG_SECTION_HEADER_APP_LIVE_STREAM_LIST, AppType::LIVE_STREAM_APP},
    { XML_TAG_SECTION_HEADER_APP_GAME_BACKGROUND_LIMIT_LIST, AppType::GAME_BACKGROUND_LIMIT_LIST_APP},
    { XML_TAG_SECTION_KEY_GAME_RTT, AppType::GAME_RTT},
};

AppParserInner::AppParserInner()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

AppParserInner::~AppParserInner()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

bool AppParserInner::Init(AppParserResult &result, std::vector<const char*> appFileList)
{
    if (!initFlag_) {
        bool parserRet = true;
        for (auto filePath: appFileList) {
            bool ret = InitAppParser(filePath);
            WIFI_LOGI("%{public}s InitAppParser result %{public}s : %{public}d",
                __FUNCTION__, filePath, static_cast<int>(ret));
            parserRet &= ret;
        }
        if (parserRet) {
            initFlag_ = true;
            result = result_;
            WIFI_LOGD("%{public}s InitAppParser successful", __FUNCTION__);
        } else {
            WIFI_LOGE("%{public}s InitAppParser fail", __FUNCTION__);
        };
    }
    return initFlag_;
}


bool AppParserInner::InitAppParser(const char *appXmlFilePath)
{
    if (appXmlFilePath == nullptr) {
        WIFI_LOGE("%{public}s appXmlFilePath is null", __FUNCTION__);
        return false;
    }
    std::string xmlPath(appXmlFilePath);
    std::filesystem::path pathName = xmlPath;
    std::error_code code;
    if (!std::filesystem::exists(pathName, code)) {
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

bool AppParserInner::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("%{public}s node is null", __FUNCTION__);
        return false;
    }
    ParseAppList(node);
    ParseNetworkControlAppList(node);
    return true;
}

void AppParserInner::ParseAppList(const xmlNodePtr &innode)
{
    if (innode == nullptr) {
        return;
    }
    if (innode->name == nullptr || xmlStrcmp(innode->name, BAD_CAST(XML_TAG_SECTION_HEADER_MONITOR_APP)) != 0) {
        WIFI_LOGE("innode name=%{public}s not equal MonitorAPP", innode->name);
        return;
    }
    result_.m_lowLatencyAppVec.clear();
    result_.m_whiteAppVec.clear();
    result_.m_multilinkAppVec.clear();
    result_.m_chariotAppVec.clear();
    result_.m_blackAppVec.clear();
    result_.m_highTempLimitSpeedAppVec.clear();
    xmlNodePtr nodeVersion = innode->children;
    if (nodeVersion != nullptr) {
        GetLocalFileVersion(nodeVersion);
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetAppTypeAsInt(node)) {
            case AppType::LOW_LATENCY_APP:
                result_.m_lowLatencyAppVec.push_back(ParseLowLatencyAppInfo(node));
                break;
            case AppType::WHITE_LIST_APP:
                result_.m_whiteAppVec.push_back(ParseWhiteAppInfo(node));
                break;
            case AppType::MULTILINK_BLACK_LIST_APP:
                result_.m_multilinkAppVec.push_back(ParseMultiLinkAppInfo(node));
                break;
            case AppType::BLACK_LIST_APP:
                result_.m_blackAppVec.push_back(ParseBlackAppInfo(node));
                break;
            case AppType::CHARIOT_APP:
                result_.m_chariotAppVec.push_back(ParseChariotAppInfo(node));
                break;
            case AppType::HIGH_TEMP_LIMIT_SPEED_APP:
                result_.m_highTempLimitSpeedAppVec.push_back(ParseHighTempLimitSpeedAppInfo(node));
                break;
            default:
                WIFI_LOGD("app type: %{public}s is not monitored", GetNodeValue(node).c_str());
                break;
        }
    }
    WIFI_LOGI("%{public}s out,result_.m_highTempLimitSpeedAppVec count:%{public}d!",
        __FUNCTION__, (int)result_.m_highTempLimitSpeedAppVec.size());
    WIFI_LOGI("%{public}s out,result_.m_multilinkAppVec count:%{public}d!",
        __FUNCTION__, (int)result_.m_multilinkAppVec.size());
}

void AppParserInner::ParseNetworkControlAppList(const xmlNodePtr &innode)
{
    if (innode == nullptr || innode->name == nullptr) {
        return;
    }
    if (xmlStrcmp(innode->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK_CONTROL_APP)) != 0) {
        WIFI_LOGE("innode name=%{public}s not equal NetworkControlAPP", innode->name);
        return;
    }
    result_.m_keyForegroundListAppVec.clear();
    result_.m_keyBackgroundLimitListAppVec.clear();
    result_.m_liveStreamAppVec.clear();
    result_.m_gameBackgroundLimitListAppVec.clear();

    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetAppTypeAsInt(node)) {
            case AppType::KEY_FOREGROUND_LIST_APP:
                result_.m_keyForegroundListAppVec.push_back(ParseKeyForegroundListAppInfo(node));
                break;
            case AppType::KEY_BACKGROUND_LIMIT_LIST_APP:
                result_.m_keyBackgroundLimitListAppVec.push_back(ParseKeyBackgroundLimitListAppInfo(node));
                break;
            case AppType::GAME_BACKGROUND_LIMIT_LIST_APP:
                result_.m_gameBackgroundLimitListAppVec.push_back(ParseGameBackgroundLimitListAppInfo(node));
                break;
            case AppType::LIVE_STREAM_APP:
                result_.m_liveStreamAppVec.push_back(ParseLiveStreamAppInfo(node));
                break;
            case AppType::ASYNC_DELAY_TIME:
                ParseAsyncLimitSpeedDelayTime(node);
                break;
            default:
                WIFI_LOGD("app type: %{public}s is not limited", GetNodeValue(node).c_str());
                break;
        }
    }
    WIFI_LOGI("%{public}s out,result_.m_keyForegroundListAppVec count:%{public}d!",
        __FUNCTION__, (int)result_.m_keyForegroundListAppVec.size());
    WIFI_LOGI("%{public}s out,result_.m_keyBackgroundLimitListAppVec count:%{public}d!",
        __FUNCTION__, (int)result_.m_keyBackgroundLimitListAppVec.size());
}

LowLatencyAppInfo AppParserInner::ParseLowLatencyAppInfo(const xmlNodePtr &innode)
{
    LowLatencyAppInfo appInfo{};
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_GAME_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser low latency app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string gameName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = gameName;
    xmlFree(value);
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetAppTypeAsInt(node) == AppType::GAME_RTT) {
            xmlChar *rttValue = xmlNodeGetContent(node);
            if (rttValue == NULL) {
                WIFI_LOGE("%{public}s xml parser game rtt info error.", __FUNCTION__);
                break;
            }
            std::string rtt = std::string(reinterpret_cast<char *>(rttValue));
            result_.m_gameRtt[gameName] = CheckDataLegal(rtt);
            xmlFree(rttValue);
        }
    }
    return appInfo;
}

WhiteListAppInfo AppParserInner::ParseWhiteAppInfo(const xmlNodePtr &innode)
{
    WhiteListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

BlackListAppInfo AppParserInner::ParseBlackAppInfo(const xmlNodePtr &innode)
{
    BlackListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

MultiLinkAppInfo AppParserInner::ParseMultiLinkAppInfo(const xmlNodePtr &innode)
{
    MultiLinkAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    WIFI_LOGD("%{public}s packageName:%{public}s", __FUNCTION__, packageName.c_str());
    xmlFree(value);
    return appInfo;
}

ChariotAppInfo AppParserInner::ParseChariotAppInfo(const xmlNodePtr &innode)
{
    ChariotAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

HighTempLimitSpeedAppInfo AppParserInner::ParseHighTempLimitSpeedAppInfo(const xmlNodePtr &innode)
{
    HighTempLimitSpeedAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

KeyForegroundListAppInfo AppParserInner::ParseKeyForegroundListAppInfo(const xmlNodePtr &innode)
{
    KeyForegroundListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

KeyBackgroundLimitListAppInfo AppParserInner::ParseKeyBackgroundLimitListAppInfo(const xmlNodePtr &innode)
{
    KeyBackgroundLimitListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser  app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

LiveStreamAppInfo AppParserInner::ParseLiveStreamAppInfo(const xmlNodePtr &innode)
{
    LiveStreamAppInfo appInfo{};
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser live stream app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

GameBackgroundLimitListAppInfo AppParserInner::ParseGameBackgroundLimitListAppInfo(const xmlNodePtr &innode)
{
    GameBackgroundLimitListAppInfo appInfo{};
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser game background limit app info error.", __FUNCTION__);
        return appInfo;
    }
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

void AppParserInner::ParseAsyncLimitSpeedDelayTime(const xmlNodePtr &innode)
{
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_DELAY_TIME));
    if (value == NULL) {
        WIFI_LOGE("%{public}s xml parser info error.", __FUNCTION__);
        return;
    }
    result_.m_delayTime = std::string(reinterpret_cast<char *>(value));
    if (result_.m_delayTime.empty()) {
        WIFI_LOGE("%{public}s delay time is null, will set 0.", __FUNCTION__);
        result_.m_delayTime = "0";
    }
}

AppType AppParserInner::GetAppTypeAsInt(const xmlNodePtr &innode)
{
    std::string tagName = GetNodeValue(innode);
    if (appTypeMap.find(tagName) != appTypeMap.end()) {
        return appTypeMap.at(tagName);
    }
    WIFI_LOGD("%{public}s not find targName:%{public}s in appTypeMap", __FUNCTION__, tagName.c_str());
    return AppType::OTHER_APP;
}

std::string AppParserInner::GetLocalFileVersion(const xmlNodePtr &innode)
{
    if (innode == nullptr || innode->name == nullptr) {
        return "";
    }
    if (xmlStrcmp(innode->name, BAD_CAST(XML_VERSION_NODE_NAME)) != 0) {
        WIFI_LOGE("innode name=%{public}s not equal version", innode->name);
        return "";
    }
    std::string fileVersion = GetStringValue(innode);
    WIFI_LOGI("%{public}s name=%{public}s", __FUNCTION__, fileVersion.c_str());
    return fileVersion;
}

/* below: AppParser is used for judge whether application in certain list*/

AppParser::AppParser()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
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

bool AppParser::Init()
{
    std::unique_lock<std::shared_mutex> lock(appParserMutex_);
    if (!initFlag_) {
        appParserInner_ = std::make_unique<AppParserInner>();
        std::vector<const char*> appFileList = {WIFI_MONITOR_APP_FILE_PATH, WIFI_NETWORK_CONTROL_APP_FILE_PATH};
        initFlag_ = appParserInner_->Init(result_, appFileList);
        appParserInner_ = nullptr; // release memory after use
    }
    return initFlag_;
}

bool AppParser::IsLowLatencyApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_lowLatencyAppVec.begin(), result_.m_lowLatencyAppVec.end(),
        [bundleName](const LowLatencyAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsWhiteListApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_whiteAppVec.begin(), result_.m_whiteAppVec.end(),
        [bundleName](const WhiteListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsBlackListApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_blackAppVec.begin(), result_.m_blackAppVec.end(),
        [bundleName](const BlackListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsMultiLinkApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_multilinkAppVec.begin(), result_.m_multilinkAppVec.end(),
        [bundleName](const MultiLinkAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsChariotApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_chariotAppVec.begin(), result_.m_chariotAppVec.end(),
        [bundleName](const ChariotAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsHighTempLimitSpeedApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_highTempLimitSpeedAppVec.begin(), result_.m_highTempLimitSpeedAppVec.end(),
        [bundleName](const HighTempLimitSpeedAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsKeyForegroundApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_keyForegroundListAppVec.begin(), result_.m_keyForegroundListAppVec.end(),
        [bundleName](const KeyForegroundListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsKeyBackgroundLimitApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_keyBackgroundLimitListAppVec.begin(), result_.m_keyBackgroundLimitListAppVec.end(),
        [bundleName](const KeyBackgroundLimitListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsLiveStreamApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_liveStreamAppVec.begin(), result_.m_liveStreamAppVec.end(),
        [bundleName](const LiveStreamAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsGameBackgroundLimitApp(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return std::any_of(result_.m_gameBackgroundLimitListAppVec.begin(), result_.m_gameBackgroundLimitListAppVec.end(),
        [bundleName](const GameBackgroundLimitListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsOverGameRtt(const std::string &bundleName, const int gameRtt) const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    if (result_.m_gameRtt.find(bundleName) == result_.m_gameRtt.end()) {
        return false;
    }
    return result_.m_gameRtt.at(bundleName) <= gameRtt;
}

std::string AppParser::GetAsyncLimitSpeedDelayTime() const
{
    std::shared_lock<std::shared_mutex> lock(appParserMutex_);
    return result_.m_delayTime;
}
} // namespace Wifi
} // namespace OHOS