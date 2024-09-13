/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_RPT_INTERFACE_H
#define OHOS_RPT_INTERFACE_H

#include <string>
#include "wifi_errcode.h"
#include "wifi_ap_msg.h"
#include "wifi_p2p_msg.h"

namespace OHOS::Wifi {
class RptInterface {
public:
    RptInterface() {};
    virtual ~RptInterface() {};
    virtual bool IsRptRunning() = 0;
    virtual ErrCode GetStationList(std::vector<StationInfo> &result) = 0;
    virtual std::string GetRptIfaceName() = 0;
    virtual void AddBlock(const std::string &mac) = 0;
    virtual void DelBlock(const std::string &mac) = 0;

    virtual void OnP2pActionResult(P2pActionCallback action, ErrCode code) = 0;
    virtual void OnP2pConnectionChanged(P2pConnectedState p2pConnState) = 0;
    virtual void OnStationJoin(std::string mac) = 0;
    virtual void OnStationLeave(std::string mac) = 0;
};
} // namespace OHOS::Wifi
#endif