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

#ifndef OHOS_WIFIEVENTCALLBACK_H
#define OHOS_WIFIEVENTCALLBACK_H

namespace OHOS {
namespace Wifi {
struct WifiEventCallback {
    void *pInstance;
    void (*onConnectChanged)(int status, int networkId, char *bssid, void *pInstance);
    void (*onWpaStateChanged)(int status, void *pInstance);
    void (*onWpaSsidWrongKey)(int status, void *pInstance);
    void (*onWpsOverlap)(int status, void *pInstance);
    void (*onWpsTimeOut)(int status, void *pInstance);
    WifiEventCallback()
    {
        pInstance = nullptr;
        onConnectChanged = nullptr;
        onWpaStateChanged = nullptr;
        onWpaSsidWrongKey = nullptr;
        onWpsOverlap = nullptr;
        onWpsTimeOut = nullptr;
    }
};
}  // namespace Wifi
}  // namespace OHOS

#endif