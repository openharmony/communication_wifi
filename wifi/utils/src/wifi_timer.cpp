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

#include "wifi_timer.h"
#include "wifi_logger.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonUtil");
WifiTimer *WifiTimer::GetInstance()
{
    static WifiTimer instance;
    return &instance;
}
#ifdef WIFI_FFRT_ENABLE
WifiTimer::WifiTimer() : timer_(std::make_unique<WifiEventHandler>("WifiManagerTimer"))
{
    timerIdInit = 0;
}

WifiTimer::~WifiTimer()
{
    if (timer_) {
        timer_.reset();
    }
}

ErrCode WifiTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return WIFI_OPT_FAILED;
    }
    timerIdInit++;
    bool ret = timer_->PostAsyncTask(callback, std::to_string(timerIdInit), interval);
    if (!ret) {
        WIFI_LOGE("Register timer failed");
        timerIdInit--;
        return WIFI_OPT_FAILED;
    }

    outTimerId = timerIdInit;
    return WIFI_OPT_SUCCESS;
}

void WifiTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        WIFI_LOGE("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return;
    }

    timer_->RemoveAsyncTask(std::to_string(timerId));
    return;
}
#else
WifiTimer::WifiTimer() : timer_(std::make_unique<Utils::Timer>("WifiManagerTimer"))
{
    timer_->Setup();
}

WifiTimer::~WifiTimer()
{
    if (timer_) {
        timer_->Shutdown(true);
    }
}

ErrCode WifiTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return WIFI_OPT_FAILED;
    }

    uint32_t ret = timer_->Register(callback, interval, once);
    if (ret == Utils::TIMER_ERR_DEAL_FAILED) {
        WIFI_LOGE("Register timer failed");
        return WIFI_OPT_FAILED;
    }

    outTimerId = ret;
    return WIFI_OPT_SUCCESS;
}

void WifiTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        WIFI_LOGE("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return;
    }

    timer_->Unregister(timerId);
    return;
}
#endif
}
}