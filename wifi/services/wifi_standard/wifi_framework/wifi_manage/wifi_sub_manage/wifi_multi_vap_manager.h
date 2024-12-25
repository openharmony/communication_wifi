/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_MULTI_VAP_MANAGER_H
#define OHOS_WIFI_MULTI_VAP_MANAGER_H

#ifndef OHOS_ARCH_LITE

namespace OHOS {
namespace Wifi {
class WifiMultiVapManager {
public:
    WifiMultiVapManager() = default;
    ~WifiMultiVapManager() = default;

    bool CheckCanConnectDevice();
    bool CheckCanUseP2p();
    bool CheckCanUseSoftAp();
    void VapConflictReport();
private:
    bool CheckStaConnected();
    bool CheckP2pConnected();
    bool CheckSoftApStarted();
    bool CheckEnhanceWifiConnected();
    void ForceStopSoftAp();
    void ShowToast();
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_MULTI_VAP_MANAGER_H