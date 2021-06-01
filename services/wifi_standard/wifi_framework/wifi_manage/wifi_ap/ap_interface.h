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
#ifndef OHOS_AP_INTERFACE_H
#define OHOS_AP_INTERFACE_H

#include "ap_define.h"
#include "base_service.h"

namespace OHOS {
namespace Wifi {
class ApInterface : public BaseService {
public:
    /**
     * @Description  construction method
     * @param None
     * @return None
     */
    ApInterface();
    /**
     * @Description  destructor method
     * @param None
     * @return None
     */
    ~ApInterface();

    /**
     * @Description  This command is invoked after the AP dynamic library file is loaded.
     * @param mqUp - MO message
     * @return success: 0    failed: -1
     */
    virtual int Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp);
    /**
     * @Description  This interface is invoked when an MO message is sent to the AP.
     * @param msg - delivered message
     * @return success: 0    failed: -1
     */
    virtual int PushMsg(WifiRequestMsgInfo *msg);
    /**
     * @Description  This command is invoked before the AP dynamic library file is uninstalled.
     * @param None
     * @return None
     */
    virtual int UnInit(void);
}; /* ApInterface */
}  // namespace Wifi
}  // namespace OHOS

#endif
