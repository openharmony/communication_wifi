/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_WIFI_POWER_CMD_CLIENT_H
#define OHOS_WIFI_POWER_CMD_CLIENT_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Wifi {
const int CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH = 125;

struct WifiPrivCmd {
    uint8_t *buf;
    uint32_t size;
    uint32_t len;
};

class WifiPowerCmdClient {
public:
    static WifiPowerCmdClient &GetInstance();
    int SendCmdToDriver(const std::string &ifName, int commandId, const std::string &param) const;

private:
    int SendCommandToDriverByInterfaceName(const std::string &ifName, const std::string &cmdParm) const;
    int SetRxListen(const std::string &ifName, const std::string &param) const;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_WIFI_POWER_CMD_CLIENT_H */