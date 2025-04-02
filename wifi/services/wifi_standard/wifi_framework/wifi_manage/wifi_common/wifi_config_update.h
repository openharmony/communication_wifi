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

#ifndef SERVICE_CORE_PROXY_H
#define SERVICE_CORE_PROXY_H

#include <string>

namespace OHOS {
namespace Wifi {

class LibraryUtils {
public:
    LibraryUtils(const std::string& libName, void*& handle, bool isDlclose);
    virtual ~LibraryUtils();
    void* GetFunc(const std::string& funcName);

protected:
    const std::string libName_;
    bool isDlclose_;
    void*& handle_;
};

class WifiConfigUpdate {
public:
    WifiConfigUpdate() : libUtils("libwifi_config_update.z.so", handle_, false) {}
    ~WifiConfigUpdate() {}

    void SaveWifiConfig(const char* ssid, const char* keyMgmt, const char* preSharedKey);

private:
    static void* handle_;
    LibraryUtils libUtils;
};
} // namespace Wifi
} // namespace OHOS
#endif // SERVICE_CORE_PROXY_H
