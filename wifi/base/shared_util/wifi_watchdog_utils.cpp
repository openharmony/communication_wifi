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

#include <csignal>
#include <fcntl.h>
#include "securec.h"
#include <unistd.h>
#ifndef OHOS_ARCH_LITE
#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif
#include "wifi_watchdog_utils.h"
#include "wifi_logger.h"
#undef LOG_TAG

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiWatchDogUtils");
constexpr int RESET_NOW = 1; //1s
constexpr int TIME_OUT_WATCHDOG = 10; // 10s
std::shared_ptr<WifiWatchDogUtils> WifiWatchDogUtils::GetInstance()
{
    static std::shared_ptr<WifiWatchDogUtils> instance = nullptr;
    if (instance == nullptr) {
        instance = std::make_shared<WifiWatchDogUtils>();
    }
    return instance;
}
WifiWatchDogUtils::WifiWatchDogUtils()
{}

WifiWatchDogUtils::~WifiWatchDogUtils()
{}

bool WifiWatchDogUtils::ResetProcess(bool usingHiviewDfx, const std::string &threadName, bool notResetProcess)
{
#ifndef OHOS_ARCH_LITE
    ReportResetEvent(threadName);
    if (notResetProcess) {
        WIFI_LOGI("ResetProcess enter, but should not reset process");
        HiviewDFX::XCollie::GetInstance().SetTimer("WifiResetTimer", TIME_OUT_WATCHDOG,
            nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG|HiviewDFX::XCOLLIE_FLAG_RECOVERY);
        return false;
    }
    if (usingHiviewDfx) {
        WIFI_LOGI("ResetProcess through HiviewDfx");
        //generate sysfreeze file in faultlogger, report to hiview
        HiviewDFX::XCollie::GetInstance().SetTimer("WifiResetTimer", RESET_NOW,
            nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG|HiviewDFX::XCOLLIE_FLAG_RECOVERY);
    } else {
        WIFI_LOGI("ResetProcess enter, please check crash.cpp for more information");
        //generate crash file in faultlogger, report to hiview
        kill(getpid(), SIGSEGV);
    }
#endif
    return true;
}

int WifiWatchDogUtils::StartWatchDogForFunc(const std::string &funcName)
{
    #ifndef OHOS_ARCH_LITE
    WIFI_LOGI("StartWatchDogForFunc enter for funcName:%{public}s", funcName.c_str());
    // this will generate a watchdog file in faultlogger but will not reset process
    return HiviewDFX::XCollie::GetInstance().SetTimer(funcName, TIME_OUT_WATCHDOG,
        nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    #endif
    return -1;
}

bool WifiWatchDogUtils::StopWatchDogForFunc(const std::string &funcName, int id)
{
    #ifndef OHOS_ARCH_LITE
    WIFI_LOGI("StopWatchDogForFunc enter for funcName:%{public}s", funcName.c_str());
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
    #endif
    return true;
}

void WifiWatchDogUtils::StartAllWatchDog()
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("StartAllWatchDog enter");
    //unsupported for process other than foundation
#endif
}

bool WifiWatchDogUtils::ReportResetEvent(const std::string &threadName)
{
    WIFI_LOGI("ReportResetEvent enter for threadName:%{public}s", threadName.c_str());
    return true;
}
}  // namespace Wifi
}  // namespace OHOSs