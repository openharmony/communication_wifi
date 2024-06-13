/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_WIFI_APP_PARSER_H
#define OHOS_MOCK_WIFI_APP_PARSER_H

#include <gmock/gmock.h>
#include <vector>
#include <string>

namespace OHOS {
namespace Wifi {
class MockWifiAppParser {
public:
    virtual bool IsLowLatencyApp(const std::string &bundleName);
    virtual bool IsWhiteListApp(const std::string &bundleName);
    virtual bool IsBlackListApp(const std::string &bundleName);
    virtual bool IsChariotApp(const std::string &bundleName);
    virtual bool IsHighTempLimitSpeedApp(const std::string &bundleName);
};

class AppParser : public MockWifiAppParser {
public:
    static AppParser &GetInstance(void);
    MOCK_METHOD1(IsLowLatencyApp, bool(const std::string &bundleName));
    MOCK_METHOD1(IsWhiteListApp, bool(const std::string &bundleName));
    MOCK_METHOD1(IsBlackListApp, bool(const std::string &bundleName));
    MOCK_METHOD1(IsChariotApp, bool(const std::string &bundleName));
    MOCK_METHOD1(IsHighTempLimitSpeedApp, bool(const std::string &bundleName));
};
} /* namespace Wifi */
} /* namespace OHOS */
#endif