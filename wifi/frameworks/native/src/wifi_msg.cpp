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

#include "wifi_msg.h"
#include <string>

namespace OHOS {
namespace Wifi {
static const std::string PREFIX_AUTH = "auth=";
static const std::string PREFIX_AUTHEAP = "autheap=";
static const std::string METHOD_STRS[] = { "NONE", "PAP", "MSCHAP", "MSCHAPV2", "GTC", "SIM", "AKA", "AKA'" };

std::string WifiEapConfig::Phase2MethodToStr(const std::string& eap, const int& method)
{
    if (method < 0 || method >= static_cast<int>(sizeof(METHOD_STRS) / sizeof(METHOD_STRS[0]))) {
        return "auth=NONE";
    }
    std::string prefix = (eap == EAP_METHOD_TTLS && method == static_cast<int>(Phase2Method::GTC)) ?
        PREFIX_AUTHEAP : PREFIX_AUTH;
    return prefix + METHOD_STRS[method];
}

Phase2Method WifiEapConfig::Phase2MethodFromStr(const std::string& str)
{
    std::string methodStr;
    if (str.find(PREFIX_AUTH) == 0) {
        methodStr = str.substr(PREFIX_AUTH.length());
    } else if (str.find(PREFIX_AUTHEAP) == 0) {
        methodStr = str.substr(PREFIX_AUTHEAP.length());
    } else {
        return Phase2Method::NONE;
    }
    int len = sizeof(METHOD_STRS) / sizeof(METHOD_STRS[0]);
    for (int i = 0; i < len; i++) {
        if (METHOD_STRS[i] == methodStr) {
            return Phase2Method(i);
        }
    }
    return Phase2Method::NONE;
}
} // namespace Wifi
} // namespace OHOS
