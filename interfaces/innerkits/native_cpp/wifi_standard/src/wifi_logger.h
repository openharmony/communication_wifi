/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_LOG_CPLUS_H
#define OHOS_WIFI_LOG_CPLUS_H

#include "hilog/log_c.h"
#include "hilog/log_cpp.h"

namespace OHOS {
namespace Wifi {
#define DEFINE_WIFILOG_LABEL(name) static constexpr OHOS::HiviewDFX::HiLogLabel WIFI_LOG_LABEL = {LOG_CORE, 0, name};

#define WIFI_LOGF(...) (void)OHOS::HiviewDFX::HiLog::Fatal(WIFI_LOG_LABEL, ##__VA_ARGS__)
#define WIFI_LOGE(...) (void)OHOS::HiviewDFX::HiLog::Error(WIFI_LOG_LABEL, ##__VA_ARGS__)
#define WIFI_LOGW(...) (void)OHOS::HiviewDFX::HiLog::Warn(WIFI_LOG_LABEL, ##__VA_ARGS__)
#define WIFI_LOGI(...) (void)OHOS::HiviewDFX::HiLog::Info(WIFI_LOG_LABEL, ##__VA_ARGS__)
#define WIFI_LOGD(...) (void)OHOS::HiviewDFX::HiLog::Debug(WIFI_LOG_LABEL, ##__VA_ARGS__)
}  // namespace Wifi
}  // namespace OHOS
#endif