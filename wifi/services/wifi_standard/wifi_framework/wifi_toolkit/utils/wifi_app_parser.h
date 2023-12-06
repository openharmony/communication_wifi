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

#ifndef OHOS_WIFI_APP_PARSE_H
#define OHOS_WIFI_APP_PARSE_H

#include "xml_parser.h"
#include <vector>
#include <string>

namespace OHOS {
namespace Wifi {
enum class AppType {
    GAME_APP = 0,
    WHITE_LIST_APP,
    BLACK_LIST_APP,
    CHARIOT_APP,
    OTHER_APP
};

enum class GameAppInfoType {
    GAME_ID = 0,
    SCENE_ID,
    GAME_KQI,
    GAME_RTT,
    GAME_ACTION,
    GAME_SPACIAL_INFO_SOURCES,
    INVALID
};

struct CommonAppInfo {
    std::string packageName;
};

struct WhiteListAppInfo : CommonAppInfo {};
struct BlackListAppInfo : CommonAppInfo {};
struct ChariotAppInfo : CommonAppInfo {};

struct GameAppInfo {
    std::string gameName;
    std::string mGameId;
    std::string mSceneId;
    std::string mGameKQI;
    std::string mGameRtt;
    std::string mGameAction;
    std::string mGameSpacialInfoSources;
};

class AppParser : public XmlParser {
public:
    AppParser();
    ~AppParser() override;
    static AppParser &GetInstance();
    bool IsGameApp(const std::string &bundleName) const;
    bool IsWhiteListApp(const std::string &bundleName) const;
    bool IsBlackListApp(const std::string &bundleName) const;
    bool IsChariotApp(const std::string &bundleName) const;

private:
    void InitAppParser();
    bool ParseInternal(xmlNodePtr node) override;
    void ParserAppList(const xmlNodePtr &innode);
    GameAppInfo ParseGameAppInfo(const xmlNodePtr &innode);
    WhiteListAppInfo ParseWhiteAppInfo(const xmlNodePtr &innode);
    BlackListAppInfo ParseBlackAppInfo(const xmlNodePtr &innode);
    ChariotAppInfo ParseChariotAppInfo(const xmlNodePtr &innode);
    GameAppInfoType GetGameAppInfoNameAsInt(const xmlNodePtr &innode);
    AppType GetAppTypeAsInt(const xmlNodePtr &innode);

private:
    std::vector<GameAppInfo> m_gameAppVec {};
    std::vector<WhiteListAppInfo> m_whiteAppVec {};
    std::vector<BlackListAppInfo> m_blackAppVec {};
    std::vector<ChariotAppInfo> m_chariotAppVec {};
};
} // namespace Wifi
} // namespace OHOS

#endif