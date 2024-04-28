/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SELF_CURE_SERVICE_H
#define OHOS_WIFI_SELF_CURE_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "self_cure_service_callback.h"
#include "ip2p_service_callbacks.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
class ISelfCureService {
public:
    virtual ~ISelfCureService() = default;
    /**
    * @Description  Register self cure callback function.
    *
    * @param callbacks - Callback function pointer storage structure
    * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
    */
    virtual ErrCode RegisterSelfCureServiceCallback(const SelfCureServiceCallback &callbacks) = 0;
    /**
     * @Description  self cure service initialization function.
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode InitSelfCureService() = 0;

    /**
     * @Description Get register sta callback
     *
     * @return StaServiceCallback - sta callback
     */
    virtual StaServiceCallback GetStaCallback();
};
}  // namespace Wifi
}  // namespace OHOS
#endif
