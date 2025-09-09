/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_HIAPPEVENT_H_
#define WIFI_HIAPPEVENT_H_

#include <string>

namespace OHOS {
namespace Wifi {
class WifiHiAppEvent {
public:
    static WifiHiAppEvent* GetInstance();
    void WriteEndEvent(const int64_t beginTime, const int result, const int errCode,
        const std::string& apiName);
    int64_t GetCurrentMillis();
private:
    WifiHiAppEvent();
    ~WifiHiAppEvent();
    void AddProcessor();
    int64_t processorId_{-1};
};
}  // namespace Wifi
}  // namespace OHOS
#endif
