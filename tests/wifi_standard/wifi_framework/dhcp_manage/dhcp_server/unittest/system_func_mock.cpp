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

#include "system_func_mock.h"
#include <stdint.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include "dhcp_logger.h"
#include "dhcp_message_sim.h"

using namespace OHOS::Wifi;

#undef LOG_TAG
#define LOG_TAG "DhcpServerSystemFuncMock"

#define TIME_SEC_TO_USEC (1000 * 1000)
#define DHCP_SEL_WAIT_TIMEOUTS 1500

static bool g_mockTag = false;

SystemFuncMock &SystemFuncMock::GetInstance()
{
    static SystemFuncMock gSystemFuncMock;
    return gSystemFuncMock;
};

SystemFuncMock::SystemFuncMock()
{}

SystemFuncMock::~SystemFuncMock()
{}

void SystemFuncMock::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool SystemFuncMock::GetMockFlag(void)
{
    return g_mockTag;
}

extern "C" {
int __real_socket(int __domain, int __type, int __protocol);
int __wrap_socket(int __domain, int __type, int __protocol)
{
    LOGD("==>socket.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().socket(__domain, __type, __protocol);
    }
    return __real_socket(__domain, __type, __protocol);
}

int __real_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen);
int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    LOGD("==>setsockopt.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().setsockopt(__fd, __level, __optname, __optval, __optlen);
    }
    return __real_setsockopt(__fd, __level, __optname, __optval, __optlen);
}
int __real_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds, struct timeval *__timeout);
int __wrap_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds, struct timeval *__timeout)
{
    LOGD("==>select.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        LOGD("message queue total: %d.", DhcpMsgManager::GetInstance().SendTotal());
        if (DhcpMsgManager::GetInstance().SendTotal() > 0) {
            FD_CLR(__nfds, __readfds);
            return 1;
        }
        int retval = SystemFuncMock::GetInstance().select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
        if (retval == 0) {
            if (__timeout) {
                usleep(DHCP_SEL_WAIT_TIMEOUTS * 1000);
                LOGD("select time out.");
            }
        }
        return retval;
    }
    return __real_select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

int __real_bind(int __fd, struct sockaddr * __addr, socklen_t __len);
int __wrap_bind(int __fd, struct sockaddr * __addr, socklen_t __len)
{
    LOGD("==>bind.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().bind(__fd, __addr, __len);
    }
    return __real_bind(__fd, __addr, __len);
}

int __real_close(int _fileno);
int __wrap_close(int _fileno)
{
    LOGD("==>close.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().close(_fileno);
    }
    return __real_close(_fileno);
}

ssize_t __real_sendto(int __fd, const void *__buf, size_t __n, int __flags, struct sockaddr *__addr,
        socklen_t __addr_len);
ssize_t __wrap_sendto(int __fd, const void *__buf, size_t __n, int __flags, struct sockaddr *__addr,
        socklen_t __addr_len)
{
    LOGD("==>sendto.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
    }
    return __real_sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
}

ssize_t __real_recvfrom(int __fd, void *__buf, size_t __n, int __flags, struct sockaddr *__addr,
        socklen_t *__addr_len);

ssize_t __wrap_recvfrom(int __fd, void *__buf, size_t __n, int __flags, struct sockaddr *__addr,
        socklen_t *__addr_len)
{
    LOGD("==>recvfrom.");
    if (g_mockTag) {
        LOGD(" ==>mock enable.");
        if (DhcpMsgManager::GetInstance().SendTotal() > 0) {
            LOGD("== new message received.");
            usleep(150 * 1000);
            DhcpMsgManager::GetInstance().PopSendMsg();
        }
        return SystemFuncMock::GetInstance().recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
    }
    return __real_recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
}
}