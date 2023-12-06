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

#include <unistd.h>

namespace OHOS {
namespace Wifi {

const auto WiFI_IFNAME = "wlan0";
const int CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH = 125;

typedef struct {
    unit8_t *buf;
    unint32_t size;
    unint32_t len;
} WifiPrivCmd;

class WifiPowerCmdClient {
public:
    static WifiPowerCmdClient &GetInstance();
    int SendCmdToDriver(const char *iface, int commandId, const char *paramBuf, unsigned int paramSize) const;

private:
    int SendCommandToDriverByInterfaceName(char *cmdBuf, int cmdSize, const char *interfaceName) const;
    int SetRxListen(const char *paramBuf) const;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_WIFI_POWER_CMD_CLIENT_H */