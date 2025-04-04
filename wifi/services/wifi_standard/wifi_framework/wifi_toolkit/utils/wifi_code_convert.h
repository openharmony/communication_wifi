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

#ifndef OHOS_WIFI_CONVERT_UTILS_H
#define OHOS_WIFI_CONVERT_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace Wifi {
class WifiCodeConvertUtil {
public:
    WifiCodeConvertUtil() = default;
    ~WifiCodeConvertUtil() = default;

    static bool IsUtf8(const std::string &stf);
    static std::string GbkToUtf8(const std::string &strGbk);
    static std::string Utf8ToGbk(const std::string &strUtf8);
private:
    static std::string Convert(const std::string &str, const std::string &fromCharset,
    const std::string &toCharset);
    static bool Utf8Check(const char *str, size_t length);
    static bool IsUtf8Char(unsigned char chr, int32_t &nBytes);
};
} // namespace Wifi
} // namespace OHOS
#endif // OHOS_WIFI_CONVERT_UTILS_H