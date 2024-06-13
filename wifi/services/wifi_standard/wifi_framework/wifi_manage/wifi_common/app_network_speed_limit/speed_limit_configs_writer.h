/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_SPEED_LIMIT_CONFIGS_WRITER_H
#define OHOS_WIFI_SPEED_LIMIT_CONFIGS_WRITER_H

#include <vector>
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {

typedef enum {
    SET_BG_UID = 0,
    SET_BG_PID,
    SET_FG_UID,
} BgLimitType;

/**
 * @Description set background limit speed mode
 *
 * @param mode - limit mode
 * @return ErrCode
 */
ErrCode SetBgLimitMode(int mode);

/**
 * @Description set background limit speed uid&pid list
 *
 * @param idList - foreground and background app list
 * @param type - enable/disable dpi mark
 * @return void
 */
void SetBgLimitIdList(std::vector<int> idList, int type);

/**
 * @Description write background limit uid&pid data to file
 *
 * @param filePath - target file path
 * @param idArray - uid&pid array
 * @param size - idArray size
 * @return NONE
 */
void SetUidPids(const char *filePath, const int *idArray, int size);

} // namespace Wifi
} // namespace OHOS

#endif