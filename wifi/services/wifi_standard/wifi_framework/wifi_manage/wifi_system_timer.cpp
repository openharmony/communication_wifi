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

#ifndef OHOS_ARCH_LITE
#include "wifi_system_timer.h"
#include "wifi_logger.h"
#include "common_timer_errors.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiTimer");

WifiSysTimer::WifiSysTimer()
{}

WifiSysTimer::~WifiSysTimer()
{}

WifiSysTimer::WifiSysTimer(bool repeat, uint64_t interval, bool isExact, bool isIdle)
{
    this->repeat = repeat;
    this->interval = interval;
    this->type = TIMER_TYPE_WAKEUP;
    if (isExact) {
        this->type = TIMER_TYPE_WAKEUP + TIMER_TYPE_EXACT;
    }
    if (isIdle) {
        this->type = TIMER_TYPE_IDLE;
    }
}

void WifiSysTimer::OnTrigger()
{
    if (callBack_ != nullptr) {
        callBack_();
    }
}

void WifiSysTimer::SetCallbackInfo(const std::function<void()> &callBack)
{
    this->callBack_ = callBack;
}

void WifiSysTimer::SetType(const int &type)
{
    this->type = type;
}

void WifiSysTimer::SetRepeat(bool repeat)
{
    this->repeat = repeat;
}

void WifiSysTimer::SetInterval(const uint64_t &interval)
{
    this->interval = interval;
}

void WifiSysTimer::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    this->wantAgent = wantAgent;
}

WifiTimer *WifiTimer::GetInstance()
{
    static WifiTimer instance;
    return &instance;
}

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

bool WifiTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return false;
    }

    uint32_t ret = timer_->Register(callback, interval, once);
    if (ret == Utils::TIMER_ERR_DEAL_FAILED) {
        WIFI_LOGE("Register timer failed");
        return false;
    }

    outTimerId = ret;
    return true;
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
} // namespace Wifi
} // namespace OHOS
#endif