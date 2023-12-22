/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_SYSTEM_TIMER_H
#define WIFI_SYSTEM_TIMER_H

#ifndef OHOS_ARCH_LITE
#include <cstdint>
#include <functional>
#include <string>
#include <sys/time.h>
#include <vector>
#include "time_service_client.h"
#include "itimer_info.h"
#include "timer.h"

namespace OHOS {
namespace Wifi {
class WifiSysTimer : public MiscServices::ITimerInfo {
public:
    WifiSysTimer();
    WifiSysTimer(bool repeat, uint64_t interval, bool isExact, bool isIdle = false);
    virtual ~WifiSysTimer();
    void OnTrigger() override;
    void SetType(const int &type) override;
    void SetRepeat(bool repeat) override;
    void SetInterval(const uint64_t &interval) override;
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent) override;
    void SetCallbackInfo(const std::function<void()> &callBack);
private:
    std::function<void()> callBack_ = nullptr;
};

class WifiTimer {
public:
    using TimerCallback = std::function<void()>;
    static constexpr uint32_t DEFAULT_TIMEROUT = 10000;
    static WifiTimer *GetInstance(void);

    WifiTimer();
    ~WifiTimer();

    bool Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT,
        bool once = true);
    void UnRegister(uint32_t timerId);

private:
    std::unique_ptr<Utils::Timer> timer_{nullptr};
};
} // namespace Wifi
} // namespace OHOS
#endif
#endif // WIFI_SYSTEM_TIMER_H