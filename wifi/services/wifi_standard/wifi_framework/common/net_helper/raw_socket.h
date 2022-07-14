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

#ifndef OHOS_WIFI_RAW_SOCKET_H
#define OHOS_WIFI_RAW_SOCKET_H
#include <cstdint>

namespace OHOS {
namespace Wifi {
class RawSocket {
public:
    RawSocket();
    ~RawSocket();
    int CreateSocket(const char *iface, uint16_t protocol);
    int Send(uint8_t *buff, int count, uint8_t *destHwaddr);
    int Recv(uint8_t *buff, int count, int timeoutMillis);
    int Close(void);
private:
    bool SetNonBlock(int fd);
    int socketFd_;
    uint16_t ifaceIndex_;
    uint16_t protocol_;
};
}
}

#endif
