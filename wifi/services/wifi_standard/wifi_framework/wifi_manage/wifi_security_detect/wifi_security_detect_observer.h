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

#ifndef WIFI_SECURITY_DETECT_OBSERVER_H
#define WIFI_SECURITY_DETECT_OBSERVER_H

#include "data_ability_observer_stub.h"

namespace OHOS {
namespace Wifi {
class SecurityDetectObserver : public AAFwk::DataAbilityObserverStub {
public:
    SecurityDetectObserver() = default;

    ~SecurityDetectObserver() = default;

    void OnChange() override;

private:
    std::shared_ptr<SecurityDetectObserver> SecurityDetectObserver_;
};

} // namespace Wifi
} // namespace OHOS
#endif