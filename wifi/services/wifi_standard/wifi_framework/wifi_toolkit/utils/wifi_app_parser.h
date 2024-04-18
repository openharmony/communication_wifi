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
    LOW_LATENCY_APP = 0,
    WHITE_LIST_APP,
    BLACK_LIST_APP,
    CHARIOT_APP,
    HIGH_TEMP_LIMIT_SPEED_APP,
    OTHER_APP
};

struct CommonAppInfo {
    std::string packageName;
};

struct LowLatencyAppInfo : CommonAppInfo {};
struct WhiteListAppInfo : CommonAppInfo {};
struct BlackListAppInfo : CommonAppInfo {};
struct ChariotAppInfo : CommonAppInfo {};
struct HighTempLimitSpeedAppInfo : CommonAppInfo {};

class AppParser : public XmlParser {
public:
    AppParser();
    ~AppParser() override;
    static AppParser &GetInstance();
    bool IsLowLatencyApp(const std::string &bundleName) const;
    bool IsWhiteListApp(const std::string &bundleName) const;
    bool IsBlackListApp(const std::string &bundleName) const;
    bool IsChariotApp(const std::string &bundleName) const;
    bool IsHighTempLimitSpeedApp(const std::string &bundleName) const;

private:
    bool InitAppParser(const char *appXmlFilePath);
    bool ParseInternal(xmlNodePtr node) override;
    void ParseAppList(const xmlNodePtr &innode);
    LowLatencyAppInfo ParseLowLatencyAppInfo(const xmlNodePtr &innode);
    WhiteListAppInfo ParseWhiteAppInfo(const xmlNodePtr &innode);
    BlackListAppInfo ParseBlackAppInfo(const xmlNodePtr &innode);
    ChariotAppInfo ParseChariotAppInfo(const xmlNodePtr &innode);
    HighTempLimitSpeedAppInfo ParseHighTempLimitSpeedAppInfo(const xmlNodePtr &innode);
    AppType GetAppTypeAsInt(const xmlNodePtr &innode);
    bool ReadPackageCloudFilterConfig();
    bool IsReadCloudConfig();
    std::string GetLocalFileVersion(const char *appXmlVersionFilePath);
    std::string GetCloudPushFileVersion(const char *appVersionFilePath);
    std::string GetCloudPushVersionFilePath();
    std::string GetCloudPushJsonFilePath();
private:
    std::vector<LowLatencyAppInfo> m_lowLatencyAppVec {};
    std::vector<WhiteListAppInfo> m_whiteAppVec {};
    std::vector<BlackListAppInfo> m_blackAppVec {};
    std::vector<ChariotAppInfo> m_chariotAppVec {};
    std::vector<HighTempLimitSpeedAppInfo> m_highTempLimitSpeedAppVec {};
    std::vector<HighTempLimitSpeedAppInfo> m_highTempLimitSpeedAppVecCloudPush {};
    bool mIshighTempLimitSpeedReadCloudPush = false;
};
} // namespace Wifi
} // namespace OHOS

#endif