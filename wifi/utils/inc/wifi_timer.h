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

#ifndef OHOS_WIFI_TIMER_H
#define OHOS_WIFI_TIMER_H

#ifndef OHOS_ARCH_LITE
#ifndef WIFI_FFRT_ENABLE
#include "timer.h"
#else
#include "wifi_event_handler.h"
#endif
#include "wifi_errcode.h"
namespace OHOS {
namespace Wifi {
#ifdef WIFI_FFRT_ENABLE
class WifiTimer {
public:
    using TimerCallback = std::function<void()>;
    static constexpr uint32_t DEFAULT_TIMEROUT = 10000;
    static WifiTimer *GetInstance(void);

    WifiTimer();
    ~WifiTimer();

    ErrCode Register(
        const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT, bool once = true);
    void UnRegister(uint32_t timerId);

private:
    std::unique_ptr<WifiEventHandler> timer_{nullptr};
    int32_t timerIdInit = 0;
};
#else
class WifiTimer {
public:
    using TimerCallback = std::function<void()>;
    static constexpr uint32_t DEFAULT_TIMEROUT = 10000;
    static WifiTimer *GetInstance(void);

    WifiTimer();
    ~WifiTimer();

    ErrCode Register(
        const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT, bool once = true);
    void UnRegister(uint32_t timerId);

private:
    std::unique_ptr<Utils::Timer> timer_{nullptr};
};
#endif
}
}
#endif
#endif
