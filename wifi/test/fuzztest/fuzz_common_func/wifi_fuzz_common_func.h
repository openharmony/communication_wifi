/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef WIFI_FUZZ_COMMON_FUNC_H_
#define WIFI_FUZZ_COMMON_FUNC_H_

#include <cstdint>

namespace OHOS {
namespace Wifi {
inline uint16_t U16_AT(const uint8_t* data)
{
    return (data[0] << 8) | data[1];
}

inline uint32_t U32_AT(const uint8_t* data)
{
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}
}  // namespace Wifi
}  // namespace OHOS
#endif

