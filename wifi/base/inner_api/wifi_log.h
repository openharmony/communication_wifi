/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_LOG_H
#define OHOS_WIFI_LOG_H

#ifdef OHOS_ARCH_LITE
#include "hilog/log.h"
#else
#include "hilog/log_c.h"
#endif

#undef LOG_TAG
#define LOG_TAG "WifiFrameWork"

#undef LOG_DOMAIN
#define  LOG_DOMAIN    0xD001560

#define LOGD(...) HILOG_DEBUG(LOG_CORE, ##__VA_ARGS__)
#define LOGI(...) HILOG_INFO(LOG_CORE, ##__VA_ARGS__)
#define LOGW(...) HILOG_WARN(LOG_CORE, ##__VA_ARGS__)
#define LOGE(...) HILOG_ERROR(LOG_CORE, ##__VA_ARGS__)
#define LOGF(...) HILOG_FATAL(LOG_CORE, ##__VA_ARGS__)

#ifndef CHECK_NULL_AND_RETURN
#define CHECK_NULL_AND_RETURN(ptr, retValue) \
if (!(ptr)) { \
    LOGI("Pointer %{public}s in %{public}s is NULL!", #ptr, __func__); \
    return retValue; \
}
#endif
#endif