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
#include "wifi_logger.h"
#include "json/json.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiAppXmlParser");

constexpr auto WIFI_MONITOR_APP_FILE_PATH = "/system/etc/wifi/wifi_monitor_apps.xml";
constexpr auto WIFI_NETWORK_CONTROL_APP_FILE_PATH = "/system/etc/wifi/wifi_network_control_apps.xml";
constexpr auto WIFI_MONITOR_CLOUD_PUSH_INSTALL_PATH = "/data/service/el1/public/update/param_service/install/system/";
constexpr auto WIFI_MONITOR_CLOUD_PUSH_FILE_PATH = "etc/WifiHighTemSpeedLimit/";
constexpr auto WIFI_MONITOR_CLOUD_PUSH_VERIOSN_FILE_NAME = "version.txt";
constexpr auto WIFI_MONITOR_CLOUD_PUSH_FILE_NAME = "HighTemperatureSpeedLimit.json";
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
constexpr auto VERSION_FILE_MAX_LINE = 50;
constexpr auto VERSION_FILE_KEY_WORD = "version=";
const char* XML_VERSION_NODE_NAME = "HighTempLimitSpeedAppVersionInfo";

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
    if (!initFlag_) {
        if (IsReadCloudConfig()) {
            ReadPackageCloudFilterConfig();
        }
        if (InitAppParser(WIFI_MONITOR_APP_FILE_PATH) && InitAppParser(WIFI_NETWORK_CONTROL_APP_FILE_PATH)) {
            initFlag_ = true;
            WIFI_LOGD("%{public}s InitAppParser successful", __FUNCTION__);
        } else {
            WIFI_LOGE("%{public}s InitAppParser fail", __FUNCTION__);
        };
    }
    return initFlag_;
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

bool AppParser::IsMultiLinkApp(const std::string &bundleName) const
{
    return std::any_of(m_multilinkAppVec.begin(), m_multilinkAppVec.end(),
        [bundleName](const MultiLinkAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsChariotApp(const std::string &bundleName) const
{
    return std::any_of(m_chariotAppVec.begin(), m_chariotAppVec.end(),
        [bundleName](const ChariotAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsHighTempLimitSpeedApp(const std::string &bundleName) const
{
    if (mIshighTempLimitSpeedReadCloudPush) {
        return std::any_of(m_highTempLimitSpeedAppVecCloudPush.begin(), m_highTempLimitSpeedAppVecCloudPush.end(),
            [bundleName](const HighTempLimitSpeedAppInfo &app) { return app.packageName == bundleName; });
    } else {
        return std::any_of(m_highTempLimitSpeedAppVec.begin(), m_highTempLimitSpeedAppVec.end(),
            [bundleName](const HighTempLimitSpeedAppInfo &app) { return app.packageName == bundleName; });
    }
}

bool AppParser::IsKeyForegroundApp(const std::string &bundleName) const
{
    return std::any_of(m_keyForegroundListAppVec.begin(), m_keyForegroundListAppVec.end(),
        [bundleName](const KeyForegroundListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsKeyBackgroundLimitApp(const std::string &bundleName) const
{
    return std::any_of(m_keyBackgroundLimitListAppVec.begin(), m_keyBackgroundLimitListAppVec.end(),
        [bundleName](const KeyBackgroundLimitListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsLiveStreamApp(const std::string &bundleName) const
{
    return std::any_of(m_liveStreamAppVec.begin(), m_liveStreamAppVec.end(),
        [bundleName](const LiveStreamAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsGameBackgroundLimitApp(const std::string &bundleName) const
{
    return std::any_of(m_gameBackgroundLimitListAppVec.begin(), m_gameBackgroundLimitListAppVec.end(),
        [bundleName](const GameBackgroundLimitListAppInfo &app) { return app.packageName == bundleName; });
}

bool AppParser::IsOverGameRtt(const std::string &bundleName, const int gameRtt) const
{
    if (m_gameRtt.find(bundleName) == m_gameRtt.end()) {
        return false;
    }
    return m_gameRtt.at(bundleName) <= gameRtt;
}

std::string AppParser::GetAsyncLimitSpeedDelayTime() const
{
    return m_delayTime;
}

bool AppParser::InitAppParser(const char *appXmlFilePath)
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

bool AppParser::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("%{public}s node is null", __FUNCTION__);
        return false;
    }
    ParseAppList(node);
    ParseNetworkControlAppList(node);
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
    m_multilinkAppVec.clear();
    m_chariotAppVec.clear();
    m_blackAppVec.clear();
    m_highTempLimitSpeedAppVec.clear();

    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetAppTypeAsInt(node)) {
            case AppType::LOW_LATENCY_APP:
                m_lowLatencyAppVec.push_back(ParseLowLatencyAppInfo(node));
                break;
            case AppType::WHITE_LIST_APP:
                m_whiteAppVec.push_back(ParseWhiteAppInfo(node));
                break;
            case AppType::MULTILINK_BLACK_LIST_APP:
                m_multilinkAppVec.push_back(ParseMultiLinkAppInfo(node));
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
    WIFI_LOGI("%{public}s out,m_highTempLimitSpeedAppVec count:%{public}d!",
        __FUNCTION__, (int)m_highTempLimitSpeedAppVec.size());
    WIFI_LOGI("%{public}s out,m_multilinkAppVec count:%{public}d!",
        __FUNCTION__, (int)m_multilinkAppVec.size());
}

void AppParser::ParseNetworkControlAppList(const xmlNodePtr &innode)
{
    if (xmlStrcmp(innode->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK_CONTROL_APP)) != 0) {
        WIFI_LOGE("innode name=%{public}s not equal NetworkControlAPP", innode->name);
        return;
    }
    m_keyForegroundListAppVec.clear();
    m_keyBackgroundLimitListAppVec.clear();
    m_liveStreamAppVec.clear();
    m_gameBackgroundLimitListAppVec.clear();

    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetAppTypeAsInt(node)) {
            case AppType::KEY_FOREGROUND_LIST_APP:
                m_keyForegroundListAppVec.push_back(ParseKeyForegroundListAppInfo(node));
                break;
            case AppType::KEY_BACKGROUND_LIMIT_LIST_APP:
                m_keyBackgroundLimitListAppVec.push_back(ParseKeyBackgroundLimitListAppInfo(node));
                break;
            case AppType::GAME_BACKGROUND_LIMIT_LIST_APP:
                m_gameBackgroundLimitListAppVec.push_back(ParseGameBackgroundLimitListAppInfo(node));
                break;
            case AppType::LIVE_STREAM_APP:
                m_liveStreamAppVec.push_back(ParseLiveStreamAppInfo(node));
                break;
            case AppType::ASYNC_DELAY_TIME:
                ParseAsyncLimitSpeedDelayTime(node);
                break;
            default:
                WIFI_LOGD("app type: %{public}s is not limited", GetNodeValue(node).c_str());
                break;
        }
    }
    WIFI_LOGI("%{public}s out,m_keyForegroundListAppVec count:%{public}d!",
        __FUNCTION__, (int)m_keyForegroundListAppVec.size());
    WIFI_LOGI("%{public}s out,m_keyBackgroundLimitListAppVec count:%{public}d!",
        __FUNCTION__, (int)m_keyBackgroundLimitListAppVec.size());
}

LowLatencyAppInfo AppParser::ParseLowLatencyAppInfo(const xmlNodePtr &innode)
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
            m_gameRtt[gameName] = CheckDataLegal(rtt);
            xmlFree(rttValue);
        }
    }
    return appInfo;
}

WhiteListAppInfo AppParser::ParseWhiteAppInfo(const xmlNodePtr &innode)
{
    WhiteListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

BlackListAppInfo AppParser::ParseBlackAppInfo(const xmlNodePtr &innode)
{
    BlackListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

MultiLinkAppInfo AppParser::ParseMultiLinkAppInfo(const xmlNodePtr &innode)
{
    MultiLinkAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    WIFI_LOGD("%{public}s packageName:%{public}s", __FUNCTION__, packageName.c_str());
    xmlFree(value);
    return appInfo;
}

ChariotAppInfo AppParser::ParseChariotAppInfo(const xmlNodePtr &innode)
{
    ChariotAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

HighTempLimitSpeedAppInfo AppParser::ParseHighTempLimitSpeedAppInfo(const xmlNodePtr &innode)
{
    HighTempLimitSpeedAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

KeyForegroundListAppInfo AppParser::ParseKeyForegroundListAppInfo(const xmlNodePtr &innode)
{
    KeyForegroundListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

KeyBackgroundLimitListAppInfo AppParser::ParseKeyBackgroundLimitListAppInfo(const xmlNodePtr &innode)
{
    KeyBackgroundLimitListAppInfo appInfo;
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_PACKAGE_NAME));
    std::string packageName = std::string(reinterpret_cast<char *>(value));
    appInfo.packageName = packageName;
    xmlFree(value);
    return appInfo;
}

LiveStreamAppInfo AppParser::ParseLiveStreamAppInfo(const xmlNodePtr &innode)
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

GameBackgroundLimitListAppInfo AppParser::ParseGameBackgroundLimitListAppInfo(const xmlNodePtr &innode)
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

void AppParser::ParseAsyncLimitSpeedDelayTime(const xmlNodePtr &innode)
{
    xmlChar *value = xmlGetProp(innode, BAD_CAST(XML_TAG_SECTION_KEY_DELAY_TIME));
    m_delayTime = std::string(reinterpret_cast<char *>(value));
    if (m_delayTime.empty()) {
        WIFI_LOGE("%{public}s delay time is null, will set 0.", __FUNCTION__);
        m_delayTime = "0";
    }
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

bool AppParser::ReadPackageCloudFilterConfig()
{
    WIFI_LOGI("%{public}s enter!", __FUNCTION__);
    std::ifstream ifs;
    ifs.open(GetCloudPushJsonFilePath().c_str());
    if (!ifs.is_open()) {
        WIFI_LOGE("%{public}s json file not exist,%{public}s!", __FUNCTION__, GetCloudPushJsonFilePath().c_str());
        return false;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string jsonString = buffer.str();
    Json::Value root;
    Json::Reader reader;
    ifs.close();
    bool success = reader.parse(jsonString, root);
    if (!success) {
        WIFI_LOGE("%{public}s Failed to parse JSON data!", __FUNCTION__);
        return false;
    }
    if (!root.isMember("HighTemperatureSpeedLimit")) {
        WIFI_LOGE("%{public}s Failed to parse JSON data,no member HighTemperatureSpeedLimit!", __FUNCTION__);
        return false;
    }
    int nSize = 0;
    m_highTempLimitSpeedAppVecCloudPush.clear();
    Json::Value packageName = root["HighTemperatureSpeedLimit"];
    if (packageName.isArray()) {
        m_highTempLimitSpeedAppVecCloudPush.clear();
        HighTempLimitSpeedAppInfo appInfo;
        nSize = (int)packageName.size();
        for (int i = 0; i < nSize; ++i) {
            appInfo.packageName = packageName[i].asString();
            m_highTempLimitSpeedAppVecCloudPush.push_back(appInfo);
        }
    } else {
        WIFI_LOGE("%{public}s Failed , JSON data Not ARRAY!", __FUNCTION__);
        return false;
    }
    WIFI_LOGI("%{public}s out,count:%{public}d!", __FUNCTION__, nSize);
    return true;
}

bool AppParser::IsReadCloudConfig()
{
    std::string strLocal = GetLocalFileVersion(WIFI_MONITOR_APP_FILE_PATH);
    std::string strCloud = GetCloudPushFileVersion(GetCloudPushVersionFilePath().c_str());
    bool isReadCloudConfig = (strCloud > strLocal) || (strCloud.empty() && strLocal.empty());
    WIFI_LOGI("%{public}s out,IsReadCloudConfig:%{public}d,strLocal=%{public}s,strCloud =%{public}s !", __FUNCTION__,
        isReadCloudConfig, strLocal.c_str(), strCloud.c_str());
    mIshighTempLimitSpeedReadCloudPush = isReadCloudConfig;
    return isReadCloudConfig;
}

std::string AppParser::GetCloudPushFileVersion(const char *appVersionFilePath)
{
    if (appVersionFilePath == nullptr) {
        return "";
    }
    std::string strFileVersion = "";
    std::ifstream ifs;
    ifs.open(appVersionFilePath);
    bool isVersionFileExist = ifs.is_open();
    if (!isVersionFileExist) {
        WIFI_LOGE("%{public}s %{public}s not exists", __FUNCTION__, appVersionFilePath);
        return strFileVersion;
    }
    int nLineCount = 0;
    std::string strTemp = "";
    while (getline(ifs, strTemp)) {
        if (nLineCount > VERSION_FILE_MAX_LINE) {
            WIFI_LOGE("%{public}s %{public}s Failed to parse local version data!", __FUNCTION__, appVersionFilePath);
            break;
        }
        nLineCount++;
        int nPos = strTemp.find(VERSION_FILE_KEY_WORD);
        if (nPos != -1) {
            strFileVersion = strTemp.substr(nPos + strlen(VERSION_FILE_KEY_WORD),
                strTemp.length() - nPos - strlen(VERSION_FILE_KEY_WORD));
            break;
        }
    }
    ifs.close();
    return strFileVersion;
}

std::string AppParser::GetLocalFileVersion(const char *appXmlVersionFilePath)
{
    WIFI_LOGI("%{public}s enter!", __FUNCTION__);
    std::string strFileVersion = "";
    if (appXmlVersionFilePath == nullptr) {
        WIFI_LOGE("%{public}s appXmlVersionFilePath null!", __FUNCTION__);
        return strFileVersion;
    }
    std::string xmlPath(appXmlVersionFilePath);
    std::filesystem::path pathName = xmlPath;
    std::error_code code;
    if (!std::filesystem::exists(xmlPath, code)) {
        WIFI_LOGE("%{public}s %{public}s not exists", __FUNCTION__, appXmlVersionFilePath);
        return strFileVersion;
    }
    xmlDoc *xmlObj = xmlReadFile(appXmlVersionFilePath, nullptr, XML_PARSE_NOBLANKS);
    if (xmlObj == nullptr) {
        WIFI_LOGE("%{public}s xmlReadFile failed", __FUNCTION__);
        return strFileVersion;
    }
    do {
        xmlNodePtr root = xmlDocGetRootElement(xmlObj);
        if (root == nullptr) {
            WIFI_LOGE("%{public}s Parse root null!", __FUNCTION__);
            break;
        }
        xmlNodePtr cur = root;
        xmlNodePtr pNode = nullptr;
        cur = cur->xmlChildrenNode;
        while (cur != NULL) {
            if ((xmlStrcmp(cur->name, (const xmlChar *)XML_VERSION_NODE_NAME)==0)) {
                pNode = cur;
                break;
            }
            cur = cur->next;
        }
        if (pNode == nullptr) {
            WIFI_LOGE("%{public}s VersionInfo not find", __FUNCTION__);
            break;
        }
        strFileVersion = GetStringValue(pNode);
    } while (0);

    if (xmlObj != nullptr) {
        xmlFreeDoc(xmlObj);
        xmlCleanupParser();
        xmlObj = nullptr;
    }
    return strFileVersion;
}

std::string AppParser::GetCloudPushVersionFilePath()
{
    std::string path = WIFI_MONITOR_CLOUD_PUSH_INSTALL_PATH;
    path += WIFI_MONITOR_CLOUD_PUSH_FILE_PATH;
    return path + WIFI_MONITOR_CLOUD_PUSH_VERIOSN_FILE_NAME;
}

std::string AppParser::GetCloudPushJsonFilePath()
{
    std::string path = WIFI_MONITOR_CLOUD_PUSH_INSTALL_PATH;
    path += WIFI_MONITOR_CLOUD_PUSH_FILE_PATH;
    return path + WIFI_MONITOR_CLOUD_PUSH_FILE_NAME;
}
} // namespace Wifi
} // namespace OHOS