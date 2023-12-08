/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_WIFI_APP_PARSER_H
#define OHOS_MOCK_WIFI_APP_PARSER_H

#include <gmock/gmock.h>

namespace OHOS {
namespace Wifi {
class MockAppParser {
public:
    virtual ~MockAppParser() = default;
    virtual int IsLowLatencyApp() const = 0;
};

class AppParser() : public MockAppParser {
    public:
    static WifiSettings &GetInstance(void);
    MOCK_CONST_METHOD1(IsLowLatencyApp, bool(const std::string &bundleName))
}
} // namespace Wifi
} // namespace OHOS

#endif