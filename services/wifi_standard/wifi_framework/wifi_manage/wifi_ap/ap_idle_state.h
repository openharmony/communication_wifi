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
#ifndef OHOS_AP_IDLE_STATE_H
#define OHOS_AP_IDLE_STATE_H

#include "ap_define.h"
#include "ap_macro.h"
#include "state.h"

namespace OHOS {
namespace Wifi {
class ApIdleState : public State {
public:
    /**
     * @Description  construction method
     * @param None
     * @return None
     */
    ApIdleState();
    /**
     * @Description  destructor method
     * @param None
     * @return None
     */
    virtual ~ApIdleState();

public:
    /**
     * @Description  realize pure base class method: called when enter state.
     * @param None
     * @return None
     */
    virtual void Enter() override;
    /**
     * @Description  realize pure base class method: called when exit state.
     * @param None
     * @return None
     */
    virtual void Exit() override;
    /**
     * @Description  realize pure base class method: process event in idle state.
     * @param msg - message to be processed
     * @return HANDLED：Processed successfully    NOT_HANDLED: Processed failed
     */
    virtual bool ProcessMessage(InternalMessage *msg) override;
};
}  // namespace Wifi
}  // namespace OHOS

#endif