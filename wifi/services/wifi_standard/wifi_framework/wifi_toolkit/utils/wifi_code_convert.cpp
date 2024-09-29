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
#include <iconv.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
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
    return true;
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
    if (strGbk.length() == 0 || IsUtf8(strGbk)) {
        return strGbk;
    }
    std::string result = Convert(strGbk, "gb2312", "utf-8");
    if (result.length() == 0) {
        return strGbk;
    }
    return result;
}

std::string WifiCodeConvertUtil::Convert(const std::string &str, const std::string &fromCharset,
    const std::string &toCharset)
{
    iconv_t cd = iconv_open(toCharset.c_str(), fromCharset.c_str());
    if (cd == reinterpret_cast<iconv_t>(static_cast<uintptr_t>(-1))) {
        return "";
    }

    size_t inlen = str.length();
    size_t outlen = inlen * 4;
    char *inbuf = const_cast<char *>(str.c_str());
    char *outbuf = new char[outlen];
    if (outbuf == nullptr) {
        iconv_close(cd);
        return "";
    }

    char *outbufbak = outbuf;
    if (iconv(cd, &inbuf, &inlen, &outbuf, &outlen) == static_cast<size_t>(-1)) {
        delete[] outbufbak;
        outbufbak = nullptr;
        iconv_close(cd);
        return "";
    }

    std::string strOut(outbufbak, outbuf - outbufbak);
    delete[] outbufbak;
    outbufbak = nullptr;
    iconv_close(cd);
    return strOut;
}
} // namespace Wifi
} // namespace OHOS
