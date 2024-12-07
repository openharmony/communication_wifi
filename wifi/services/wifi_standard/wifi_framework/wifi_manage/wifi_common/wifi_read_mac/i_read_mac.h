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

#ifndef I_READ_MAC_H
#define I_READ_MAC_H

#include <dlfcn.h>
#include <string>

namespace OHOS {
namespace Wifi {

class IReadMac
{
public:
    IReadMac() = default;
    virtual ~IReadMac() = default;
    virtual int GetConstantMac(std::string &constantMac) = 0;
};
} //Wifi
} //OHOS

#endif // I_READ_MAC_H