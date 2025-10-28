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

#ifndef OHOS_WIFI_APP_PARSE_H
#define OHOS_WIFI_APP_PARSE_H

#include "xml_parser.h"
#include <vector>
#include <string>
#include <shared_mutex>

namespace OHOS {
namespace Wifi {
enum class AppType {
    LOW_LATENCY_APP = 0,
    WHITE_LIST_APP,
    BLACK_LIST_APP,
    MULTILINK_BLACK_LIST_APP,
    CHARIOT_APP,
    HIGH_TEMP_LIMIT_SPEED_APP,
    KEY_FOREGROUND_LIST_APP,
    KEY_BACKGROUND_LIMIT_LIST_APP,
    ASYNC_DELAY_TIME,
    GAME_RTT,
    LIVE_STREAM_APP,
    GAME_BACKGROUND_LIMIT_LIST_APP,
    RSS_GAME_LIST_APP,
    OTHER_APP
};

struct CommonAppInfo {
    std::string packageName;
};

struct LowLatencyAppInfo : CommonAppInfo {};
struct WhiteListAppInfo : CommonAppInfo {};
struct BlackListAppInfo : CommonAppInfo {};
struct MultiLinkAppInfo : CommonAppInfo {};
struct ChariotAppInfo : CommonAppInfo {};
struct HighTempLimitSpeedAppInfo : CommonAppInfo {};
struct KeyForegroundListAppInfo : CommonAppInfo {};
struct KeyBackgroundLimitListAppInfo : CommonAppInfo {};
struct GameBackgroundLimitListAppInfo : CommonAppInfo {};
struct LiveStreamAppInfo : CommonAppInfo {};
struct RssGameListAppInfo : CommonAppInfo {};

struct AppParserResult {
    std::vector<LowLatencyAppInfo> m_lowLatencyAppVec {};
    std::vector<WhiteListAppInfo> m_whiteAppVec {};
    std::vector<BlackListAppInfo> m_blackAppVec {};
    std::vector<MultiLinkAppInfo> m_multilinkAppVec {};
    std::vector<ChariotAppInfo> m_chariotAppVec {};
    std::vector<HighTempLimitSpeedAppInfo> m_highTempLimitSpeedAppVec {};
    std::vector<KeyForegroundListAppInfo> m_keyForegroundListAppVec {};
    std::vector<KeyBackgroundLimitListAppInfo> m_keyBackgroundLimitListAppVec {};
    std::vector<LiveStreamAppInfo> m_liveStreamAppVec {};
    std::vector<GameBackgroundLimitListAppInfo> m_gameBackgroundLimitListAppVec {};
    std::vector<RssGameListAppInfo> m_rssGameListAppVec {};
    std::unordered_map<std::string, int> m_gameRtt {};
    std::string m_delayTime = "";
};

class AppParserInner : public XmlParser {
public:
    AppParserInner();
    ~AppParserInner() override;
    bool Init(AppParserResult &result, std::vector<const char*> appFileList = {});
private:
    bool InitAppParser(const char *appXmlFilePath);
    bool ParseInternal(xmlNodePtr node) override;
    void ParseAppList(const xmlNodePtr &innode);
    void ParseNetworkControlAppList(const xmlNodePtr &innode);
    LowLatencyAppInfo ParseLowLatencyAppInfo(const xmlNodePtr &innode);
    WhiteListAppInfo ParseWhiteAppInfo(const xmlNodePtr &innode);
    BlackListAppInfo ParseBlackAppInfo(const xmlNodePtr &innode);
    MultiLinkAppInfo ParseMultiLinkAppInfo(const xmlNodePtr &innode);
    ChariotAppInfo ParseChariotAppInfo(const xmlNodePtr &innode);
    HighTempLimitSpeedAppInfo ParseHighTempLimitSpeedAppInfo(const xmlNodePtr &innode);
    KeyForegroundListAppInfo ParseKeyForegroundListAppInfo(const xmlNodePtr &innode);
    KeyBackgroundLimitListAppInfo ParseKeyBackgroundLimitListAppInfo(const xmlNodePtr &innode);
    LiveStreamAppInfo ParseLiveStreamAppInfo(const xmlNodePtr &innode);
    GameBackgroundLimitListAppInfo ParseGameBackgroundLimitListAppInfo(const xmlNodePtr &innode);
    RssGameListAppInfo ParseRssGameListAppInfo(const xmlNodePtr &innode);
    void ParseAsyncLimitSpeedDelayTime(const xmlNodePtr &innode);
    AppType GetAppTypeAsInt(const xmlNodePtr &innode);
    std::string GetLocalFileVersion(const xmlNodePtr &innode);
private:
    AppParserResult result_;
    std::atomic<bool> initFlag_ {false};
};

class AppParser {
public:
    static AppParser &GetInstance();
    bool Init();
    bool IsLowLatencyApp(const std::string &bundleName) const;
    bool IsWhiteListApp(const std::string &bundleName) const;
    bool IsBlackListApp(const std::string &bundleName) const;
    bool IsMultiLinkApp(const std::string &bundleName) const;
    bool IsChariotApp(const std::string &bundleName) const;
    bool IsHighTempLimitSpeedApp(const std::string &bundleName) const;
    bool IsKeyForegroundApp(const std::string &bundleName) const;
    bool IsKeyBackgroundLimitApp(const std::string &bundleName) const;
    std::string GetAsyncLimitSpeedDelayTime() const;
    bool IsLiveStreamApp(const std::string &bundleName) const;
    bool IsGameBackgroundLimitApp(const std::string &bundleName) const;
    bool IsRssGameApp(const std::string &bundleName) const;
    bool IsOverGameRtt(const std::string &bundleName, const int gameRtt) const;
private:
    AppParser();
    ~AppParser();
private:
    mutable std::shared_mutex appParserMutex_;
    std::unique_ptr<AppParserInner> appParserInner_;
    AppParserResult result_;
    std::atomic<bool> initFlag_ {false};
};
} // namespace Wifi
} // namespace OHOS

#endif