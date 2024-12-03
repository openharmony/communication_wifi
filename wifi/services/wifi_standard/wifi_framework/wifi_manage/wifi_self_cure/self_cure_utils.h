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
 
#ifndef OHOS_SELF_CURE_UTILS_H
#define OHOS_SELF_CURE_UTILS_H

#include "singleton.h"
#include "netsys_dns_report_callback.h"

namespace OHOS {
namespace Wifi {
class SelfCureUtils {
public:
    SelfCureUtils();
    ~SelfCureUtils();
    static SelfCureUtils& GetInstance();
    void RegisterDnsResultCallback();
    void UnRegisterDnsResultCallback();
    int32_t GetCurrentDnsFailedCounter();
    void ClearDnsFailedCounter();
    int32_t GetSelfCureType(int32_t currentCureLevel);
private:
    class SelfCureDnsResultCallback : public NetManagerStandard::NetsysDnsReportCallback {
    public:
        SelfCureDnsResultCallback() {};
        ~SelfCureDnsResultCallback() {};
        int32_t OnDnsResultReport(uint32_t size, const std::list<NetsysNative::NetDnsResultReport> reports);
    private:
        int32_t GetWifiNetId();
        int32_t GetDefaultNetId();
    public:
        int32_t dnsFailedCounter_ = 0;
    };

private:
    sptr<SelfCureDnsResultCallback> dnsResultCallback_{nullptr};
};
} // namespace Wifi
} // namespace OHOS
#endif // OHOS_SELF_CURE_UTILS_H