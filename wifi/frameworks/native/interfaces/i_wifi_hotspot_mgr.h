/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_I_WIFI_HOTSPOT_MGR_H
#define OHOS_I_WIFI_HOTSPOT_MGR_H

#include "iremote_broker.h"

namespace OHOS {
namespace Wifi {
class IWifiHotspotMgr : public IRemoteBroker {
public:
    IWifiHotspotMgr() {}
    virtual ~IWifiHotspotMgr() {}
    /**
     * @Description get remote ap obj.
     *
     * @param id - obj id
     * @return IRemoteObject - ap obj
     */
    virtual sptr<IRemoteObject> GetWifiRemote(int id) = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IWifiHotspotMgr");
    enum Code {
        WIFI_MGR_GET_HOTSPOT_SERVICE = 0,
    };
};
}  // namespace Wifi
}  // namespace OHOS
#endif