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

#include "dhcp_service_api.h"
#include <memory>
#include "dhcp_service.h"
#include "i_dhcp_service.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpServiceApi");

namespace OHOS {
namespace Wifi {
std::unique_ptr<IDhcpService> DhcpServiceApi::GetInstance()
{
    std::unique_ptr<IDhcpService> service = std::make_unique<DhcpService>();
    if (service == nullptr) {
        WIFI_LOGI("DhcpApi GetInstance is null");
    }
    return service;
}

}  // namespace Wifi
}  // namespace OHOS
