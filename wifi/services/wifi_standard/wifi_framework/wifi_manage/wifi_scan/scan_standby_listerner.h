/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_SCAN_STANDBY_LISTERNER_H
#define OHOS_WIFI_SCAN_STANDBY_LISTERNER_H

#ifndef OHOS_ARCH_LITE
#include <string>
#include <functional>
#include "common_event_manager.h"
#include "common_event_data.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace Wifi {

class StandBySubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit StandBySubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
        std::function<void(bool, bool)> callBack) : CommonEventSubscriber(subscriberInfo)
    {
        onStandbyChangedEvent = callBack;
    }
    virtual ~StandBySubscriber() {};
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event) override;
private:
    std::function<void(bool, bool)> onStandbyChangedEvent;
};

class StandByListerner {
public:
    StandByListerner();
    virtual ~StandByListerner();
    /**
     * @Description  Initializing the StandByListerner.
     *
     * @return success: true, failed: false
     */
    bool Init();
    /**
     * @Description Unit the StandByListerner.
     *
     */
    void Unit();

    /**
     * @Description check can scan on standystatus
     *
     * @param scanSerivceCallbacks callback function
     */
    bool AllowScan();

    /**
     * @Description standystatus changed event
     *
     * @param scanSerivceCallbacks napped sleeping
     */
    static void OnStandbyStateChanged(bool napped, bool sleeping);

private:
    static bool allowScan;
    std::shared_ptr<StandBySubscriber> standbySubscriber = nullptr;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif
