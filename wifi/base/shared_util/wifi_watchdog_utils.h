/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_STATE_H
#define OHOS_STATE_H
#include <memory>
#include <string>
namespace OHOS {
namespace Wifi {
class WifiWatchDogUtils {
public:
    explicit WifiWatchDogUtils();
    static std::shared_ptr<WifiWatchDogUtils> GetInstance();
    ~WifiWatchDogUtils();

public:
    bool ResetProcess(bool usingHiviewDfx, const std::string &threadName, bool notResetProcess = false);
    int StartWatchDogForFunc(const std::string &funcName);
    bool StopWatchDogForFunc(const std::string &funcName, int id);
private:
    void StartAllWatchDog();
    bool ReportResetEvent(const std::string &threadName);
    static void FfrtCallback(uint64_t taskId, const char *taskInfo, uint32_t delayedTaskCount);
};
}  // namespace Wifi
}  // namespace OHOS
#endif