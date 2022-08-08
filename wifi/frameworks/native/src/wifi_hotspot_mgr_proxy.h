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

#ifndef OHOS_WIFI_HOTSPOT_MGR_PROXY_H
#define OHOS_WIFI_HOTSPOT_MGR_PROXY_H

#include "i_wifi_hotspot_mgr.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "refbase.h"

namespace OHOS {
namespace Wifi {
class WifiHotspotMgrProxy : public IRemoteProxy<IWifiHotspotMgr> {
public:
    explicit WifiHotspotMgrProxy(const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IWifiHotspotMgr>(remote)
    {}
    virtual ~WifiHotspotMgrProxy()
    {}
    sptr<IRemoteObject> GetWifiRemote(int id) override;
private:
    static BrokerDelegator<WifiHotspotMgrProxy> g_delegator;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
