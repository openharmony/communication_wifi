/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <signal.h>
#include <string.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include "rpc.h"
#include "serial.h"
#include "common.h"
#include "log.h"
#include "net.h"
#include "wifi_logger.h"
#include "wifi_c_utils.h"
#include "wifi_common_def.h"

DEFINE_WIFILOG_LABEL("RpcClient");

namespace OHOS {
namespace Wifi {
Rpc::~Rpc()
{
    UnInitClient();
}

int Rpc::InitClient(const std::string &sockPath)
{
    client = CreateRpcClient(sockPath);
    if (client == nullptr) {
        WIFI_LOGE("InitClient: init rpc client failed!");
        return -1;
    }
    return 0;
}

void Rpc::UnInitClient()
{
    if (client) {
        ::ReleaseRpcClient(client);
        client = nullptr;
    }
    return;
}

void Rpc::LockClient()
{
    CHECK_PTR_RETURN_VOID(client);
    return ::LockRpcClient(client);
}

void Rpc::UnLockClient()
{
    CHECK_PTR_RETURN_VOID(client);
    return ::UnlockRpcClient(client);
}

int Rpc::RpcClientCall()
{
    CHECK_PTR_RETURN(client, -1);
    return ::RemoteCall(client);
}

void Rpc::ReadClientEnd()
{
    CHECK_PTR_RETURN_VOID(client);
    return ::ReadClientEnd(client);
}

int Rpc::WriteBegin(int type)
{
    CHECK_PTR_RETURN(client, -1);
    return ::WriteBegin(client->context, type);
}

int Rpc::WriteEnd()
{
    CHECK_PTR_RETURN(client, -1);
    return ::WriteEnd(client->context);
}

int Rpc::WriteFunc(const std::string &funcName)
{
    CHECK_PTR_RETURN(client, -1);
    return ::WriteFunc(client->context, funcName.c_str());
}

int Rpc::WriteInt(int i)
{
    CHECK_PTR_RETURN(client, -1);
    return ::WriteInt(client->context, i);
}

int Rpc::WriteString(const std::string &str)
{
    CHECK_PTR_RETURN(client, -1);
    return ::WriteStr(client->context, str.c_str());
}

int Rpc::ReadInt(int *i)
{
    CHECK_PTR_RETURN(client, -1);
    CHECK_PTR_RETURN(i, -1);
    return ::ReadInt(client->context, i);
}

int Rpc::ReadInt(Context *context, int *i)
{
    CHECK_PTR_RETURN(context, -1);
    CHECK_PTR_RETURN(i, -1);
    return ::ReadInt(context, i);
}

int Rpc::ReadString(char *str, int count)
{
    CHECK_PTR_RETURN(client, -1);
    CHECK_PTR_RETURN(str, -1);
    return ::ReadStr(client->context, str, count);
}

int Rpc::ReadString(Context *context, char *str, int count)
{
    CHECK_PTR_RETURN(context, -1);
    CHECK_PTR_RETURN(str, -1);
    return ::ReadStr(context, str, count);
}

void Rpc::RpcClientDealReadMsg(RpcClient *client, char *buff)
{
    if (client == nullptr) {
        if (buff != nullptr) {
            free(buff);
            buff = nullptr;
        }
        return;
    }

    char szTmp[TMP_BUFF_SIZE] = {0};
    if (snprintf_s(szTmp, sizeof(szTmp), sizeof(szTmp) - 1, "N%c", client->context->cSplit) < 0) {
        if (buff != nullptr) {
            free(buff);
            buff = nullptr;
        }
        return;
    }
    if (strncmp(buff, szTmp, strlen(szTmp)) == 0) {
        pthread_mutex_lock(&client->mutex);
        client->waitReply = CLIENT_STATE_DEAL_REPLY;
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        pthread_cond_signal(&client->condW);
        pthread_mutex_unlock(&client->mutex);
    } else {
        pthread_mutex_lock(&client->mutex);
        while (client->waitReply == CLIENT_STATE_DEAL_REPLY) {
            pthread_cond_wait(&client->condW, &client->mutex);
        }
        pthread_mutex_unlock(&client->mutex);
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        OnDealRpcMsg(client->context);
        free(buff);
        buff = nullptr;
    }
    return;
}

char *Rpc::RpcClientReadMsg(RpcClient *client)
{
    if (client == nullptr) {
        return nullptr;
    }

    char *buff = ContextGetReadRecord(client->context);
    while (buff == nullptr && client->threadRunFlag) {
        int ret = WaitFdEvent(client->context->fd, READ_EVENT, FD_CHECK_TIMEOUT);
        if (ret < 0) {
            WIFI_LOGE("wait server reply message failed!");
            client->threadRunFlag = 0;
            return nullptr;
        } else if (ret == 0) {
            continue;
        }
        ret = ContextReadNet(client->context);
        if (ret < 0) {
            WIFI_LOGE("read server reply message failed!");
            client->threadRunFlag = 0;
            return nullptr;
        }
        buff = ContextGetReadRecord(client->context);
    }
    if (!client->threadRunFlag) {
        if (buff != nullptr) {
            free(buff);
            buff = nullptr;
        }
        return nullptr;
    }
    return buff;
}

void Rpc::RpcClientThreadDeal()
{
    while (client->threadRunFlag) {
        char *buff = RpcClientReadMsg(client);
        if (buff == nullptr) {
            continue;
        }
        RpcClientDealReadMsg(client, buff);
    }
    pthread_mutex_lock(&client->mutex);
    client->waitReply = CLIENT_STATE_EXIT;
    pthread_cond_signal(&client->condW);
    pthread_mutex_unlock(&client->mutex);
    WIFI_LOGI("Client read message thread exiting!");
    return;
}

RpcClient *Rpc::CreateRpcClient(const std::string &path)
{
    int fd = ConnectUnixServer(path.c_str());
    if (fd < 0) {
        return nullptr;
    }
    SetNonBlock(fd, 1);
    RpcClient *client = (RpcClient *)calloc(1, sizeof(RpcClient));
    if (client == nullptr) {
        close(fd);
        return nullptr;
    }
    client->context = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
    if (client->context == nullptr) {
        close(fd);
        free(client);
        client = nullptr;
        return nullptr;
    }
    client->context->fd = fd;
    client->threadRunFlag = 1;
    client->threadId = 0;
    client->waitReply = CLIENT_STATE_IDLE;
    client->callLockFlag = 0;
    pthread_mutex_init(&client->mutex, nullptr);
    pthread_cond_init(&client->condW, nullptr);
    pthread_mutex_init(&client->lockMutex, nullptr);
    pthread_cond_init(&client->lockCond, nullptr);
    rpcClientThread = std::thread(&Rpc::RpcClientThreadDeal, this);
    client->threadId = rpcClientThread.native_handle();
    pthread_setname_np(client->threadId, "RpcClientThread");
    signal(SIGPIPE, SIG_IGN);
    return client;
}
}  // namespace Wifi
}  // namespace OHOS