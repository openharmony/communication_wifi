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

#ifndef OHOS_WIFI_HAL_COMMON_FUNC_H
#define OHOS_WIFI_HAL_COMMON_FUNC_H

/**
 * @Description copy max len - 1 characters to destination
 *
 * @param dst - copy to
 * @param len - dst's size
 * @param src - copy from
 */
void MySafeCopy(char *dst, unsigned len, const char *src);

#endif