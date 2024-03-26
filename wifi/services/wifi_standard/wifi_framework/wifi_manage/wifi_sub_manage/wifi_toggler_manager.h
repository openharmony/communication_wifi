/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_TOGGLRT_MANAGER_H
#define OHOS_WIFI_TOGGLRT_MANAGER_H

#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"
#include "wifi_controller_state_machine.h"

namespace OHOS {
namespace Wifi {
class WifiTogglerManager {
public:
    WifiTogglerManager();
    ~WifiTogglerManager() = default;

    ConcreteModeCallback& GetConcreteCallback(void);
    SoftApModeCallback& GetSoftApCallback(void);
    ErrCode WifiToggled(int isOpen, int id = 0);
    ErrCode SoftapToggled(int isOpen, int id = 0);
    ErrCode ScanOnlyToggled(int isOpen);
    ErrCode AirplaneToggled(int isOpen);
    bool HasAnyApRuning();
    std::unique_ptr<WifiControllerMachine>& GetControllerMachine();

private:
    void InitConcreteCallback(void);
    void InitSoftapCallback(void);
    void DealConcreateStop(int id = 0);
    void DealConcreateStartFailure(int id = 0);
    void DealSoftapStop(int id = 0);
    void DealSoftapStartFailure(int id = 0);
    void DealClientRemoved(int id = 0);

private:
    ConcreteModeCallback mConcreteModeCb;
    SoftApModeCallback mSoftApModeCb;
    std::unique_ptr<WifiControllerMachine> pWifiControllerMachine = nullptr;
};

}  // namespace Wifi
}  // namespace OHOS
#endif // OHOS_WIFI_TOGGLRT_MANAGER_H