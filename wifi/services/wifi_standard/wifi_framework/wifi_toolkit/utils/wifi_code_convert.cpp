/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_ARCH_LITE
#include <unicode/ucnv.h>
#endif // OHOS_ARCH_LITE
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <securec.h>
#include "wifi_code_convert.h"

namespace OHOS {
namespace Wifi {
bool WifiCodeConvertUtil::IsUtf8(const std::string &stf)
{
    return Utf8Check(stf.c_str(), stf.length());
}

bool WifiCodeConvertUtil::Utf8Check(const char *str, size_t length)
{
    size_t i = 0;
    int32_t nBytes = 0;
    unsigned char chr = 0;
    while (i < length) {
        chr = *(str + i);
        if (!IsUtf8Char(chr, nBytes)) {
            return false;
        }
        i++;
    }
    return (nBytes == 0);
}

const unsigned char MASK_80 = 0x80;
const unsigned char MASK_C0 = 0xC0;
const int MIN_BYTES = 2;
const int MAX_BYTES = 6;
bool WifiCodeConvertUtil::IsUtf8Char(unsigned char chr, int32_t &nBytes)
{
    if (nBytes == 0) {
        if ((chr & MASK_80) == 0) {
            return true;
        }
        while ((chr & MASK_80) == MASK_80) {
            chr <<= 1;
            nBytes++;
        }

        if (nBytes < MIN_BYTES || nBytes > MAX_BYTES) {
            return false;
        }
        nBytes--;
    } else {
        if ((chr & MASK_C0) != MASK_80) {
            return false;
        }
        nBytes--;
    }
    return true;
}

std::string WifiCodeConvertUtil::GbkToUtf8(const std::string &strGbk)
{
#ifdef OHOS_ARCH_LITE
    return strGbk;
#else
    if (strGbk.length() == 0 || IsUtf8(strGbk)) {
        return strGbk;
    }
    std::string result = Convert(strGbk, "gb2312", "utf8");
    if (result.length() == 0) {
        return strGbk;
    }
    return result;
#endif // OHOS_ARCH_LITE
}

std::string WifiCodeConvertUtil::Utf8ToGbk(const std::string &strUtf8)
{
#ifdef OHOS_ARCH_LITE
    return strUtf8;
#else
    if (strUtf8.length() == 0 || !IsUtf8(strUtf8)) {
        return strUtf8;
    }
    std::string result = Convert(strUtf8, "utf8", "gb2312");
    if (result.length() == 0) {
        return strUtf8;
    }
    return result;
#endif // OHOS_ARCH_LITE
}

std::string WifiCodeConvertUtil::Convert(const std::string &str, const std::string &fromCharset,
    const std::string &toCharset)
{
#ifdef OHOS_ARCH_LITE
    return str;
#else
    UErrorCode status = U_ZERO_ERROR;
    int32_t resultlen  = ucnv_convert(toCharset.c_str(), fromCharset.c_str(), nullptr, 0, str.c_str(),
        str.length(), &status);
    std::unique_ptr<char[]> result = std::make_unique<char[]>(resultlen + 1);
    memset_s(result.get(), resultlen + 1, 0, resultlen + 1);
    status = U_ZERO_ERROR;
    ucnv_convert(toCharset.c_str(), fromCharset.c_str(), result.get(), resultlen + 1,
        str.c_str(), str.length(), &status);
    if (U_FAILURE(status)) {
        return str;
    }
    return std::string(result.get());
#endif // OHOS_ARCH_LITE
}
} // namespace Wifi
} // namespace OHOS
