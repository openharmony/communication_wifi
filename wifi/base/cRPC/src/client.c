/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "client.h"
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <string.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "log.h"
#include "net.h"

#undef LOG_TAG
#define LOG_TAG "WifiRpcClient"

const int FD_CHECK_TIMEOUT = 1000; /* poll wait time, units: ms */
const int CLIENT_STATE_IDLE = 0;
const int CLIENT_STATE_DEAL_REPLY = 1;
const int CLIENT_STATE_EXIT = 2;

#define TMP_BUFF_SIZE 16

static void *RpcClientThreadDeal(void *arg);

static char *RpcClientReadMsg(RpcClient *client)
{
    if (client == NULL) {
        return NULL;
    }

    char *buff = ContextGetReadRecord(client->context);
    while (buff == NULL && client->threadRunFlag) {
        int ret = WaitFdEvent(client->context->fd, READ_EVENT, FD_CHECK_TIMEOUT);
        if (ret < 0) {
            LOGE("wait server reply message failed!");
            client->threadRunFlag = 0;
            return NULL;
        } else if (ret == 0) {
            continue;
        }
        ret = ContextReadNet(client->context);
        if (ret < 0) {
            LOGE("read server reply message failed!");
            client->threadRunFlag = 0;
            return NULL;
        }
        buff = ContextGetReadRecord(client->context);
    }
    if (!client->threadRunFlag) {
        if (buff != NULL) {
            free(buff);
            buff = NULL;
        }
        return NULL;
    }
    return buff;
}

static void RpcClientDealReadMsg(RpcClient *client, char *buff)
{
    if (client == NULL) {
        if (buff != NULL) {
            free(buff);
            buff = NULL;
        }
        return;
    }

    char szTmp[TMP_BUFF_SIZE] = {0};
    if (snprintf_s(szTmp, sizeof(szTmp), sizeof(szTmp) - 1, "N%c", client->context->cSplit) < 0) {
        if (buff != NULL) {
            free(buff);
            buff = NULL;
        }
        return;
    }
    if (strncmp(buff, szTmp, strlen(szTmp)) == 0) { /* deal reply message */
        pthread_mutex_lock(&client->mutex);
        client->waitReply = CLIENT_STATE_DEAL_REPLY;
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        pthread_cond_signal(&client->condW);
        pthread_mutex_unlock(&client->mutex);
    } else { /* deal callback message */
        pthread_mutex_lock(&client->mutex);
        while (client->waitReply == CLIENT_STATE_DEAL_REPLY) {
            pthread_cond_wait(&client->condW, &client->mutex);
        }
        pthread_mutex_unlock(&client->mutex);
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        OnTransact(client->context);
        free(buff);
        buff = NULL;
    }
    return;
}

static void *RpcClientThreadDeal(void *arg)
{
    RpcClient *client = (RpcClient *)arg;
    if (client == NULL) {
        return NULL;
    }

    while (client->threadRunFlag) {
        char *buff = RpcClientReadMsg(client);
        if (buff == NULL) {
            continue;
        }
        RpcClientDealReadMsg(client, buff);
    }
    pthread_mutex_lock(&client->mutex);
    client->waitReply = CLIENT_STATE_EXIT;
    pthread_cond_signal(&client->condW);
    pthread_mutex_unlock(&client->mutex);
    LOGI("Client read message thread exiting!");
    return NULL;
}

RpcClient *CreateRpcClient(const char *path)
{
    int fd = ConnectUnixServer(path);
    if (fd < 0) {
        LOGE("connect server failed.");
        return NULL;
    }
    SetNonBlock(fd, 1);
    RpcClient *client = (RpcClient *)calloc(1, sizeof(RpcClient));
    if (client == NULL) {
        close(fd);
        return NULL;
    }
    client->context = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
    if (client->context == NULL) {
        LOGE("create context failed.");
        close(fd);
        free(client);
        client = NULL;
        return NULL;
    }
    client->context->fd = fd;
    client->threadRunFlag = 1;
    client->threadId = 0;
    client->waitReply = CLIENT_STATE_IDLE;
    client->callLockFlag = 0;
    pthread_mutex_init(&client->mutex, NULL);
    pthread_cond_init(&client->condW, NULL);
    pthread_mutex_init(&client->lockMutex, NULL);
    pthread_cond_init(&client->lockCond, NULL);
    int ret = pthread_create(&client->threadId, NULL, RpcClientThreadDeal, client);
    if (ret) {
        pthread_cond_destroy(&client->condW);
        pthread_mutex_destroy(&client->mutex);
        pthread_cond_destroy(&client->lockCond);
        pthread_mutex_destroy(&client->lockMutex);
        ReleaseContext(client->context);
        close(fd);
        free(client);
        client = NULL;
        return NULL;
    }
    pthread_setname_np(client->threadId, "RpcClientThread");
    signal(SIGPIPE, SIG_IGN);
    return client;
}

void ReleaseRpcClient(RpcClient *client)
{
    if (client != NULL) {
        if (client->threadId != 0) {
            client->threadRunFlag = 0;
            pthread_join(client->threadId, NULL);
        }
        pthread_cond_destroy(&client->condW);
        pthread_mutex_destroy(&client->mutex);
        pthread_cond_destroy(&client->lockCond);
        pthread_mutex_destroy(&client->lockMutex);
        close(client->context->fd);
        ReleaseContext(client->context);
        free(client);
        client = NULL;
    }
    return;
}

int RemoteCall(RpcClient *client)
{
    if (client == NULL) {
        return -1;
    }
    if (client->waitReply == CLIENT_STATE_EXIT) {
        LOGE("remote call, but client exit.");
        return -1;
    }
    int ret = 0;
    Context *context = client->context;
    while (context->wBegin != context->wEnd && ret >= 0) {
        ret = ContextWriteNet(context);
    }
    if (ret < 0) {
        LOGE("context write failed.");
        return ret;
    }
    ret = 0; /* reset ret value */
    pthread_mutex_lock(&client->mutex);
    while (client->waitReply != CLIENT_STATE_DEAL_REPLY && client->waitReply != CLIENT_STATE_EXIT) {
        pthread_cond_wait(&client->condW, &client->mutex);
    }
    if (client->waitReply == CLIENT_STATE_EXIT) {
        LOGE("client exit.");
        ret = -1;
    }
    pthread_mutex_unlock(&client->mutex);
    return ret;
}

void ReadClientEnd(RpcClient *client)
{
    if (client == NULL) {
        return;
    }

    pthread_mutex_lock(&client->mutex);
    free(client->context->oneProcess);
    client->context->oneProcess = NULL;
    if (client->waitReply == CLIENT_STATE_DEAL_REPLY) {
        client->waitReply = CLIENT_STATE_IDLE;
    }
    pthread_cond_signal(&client->condW);
    pthread_mutex_unlock(&client->mutex);
    return;
}

void LockRpcClient(RpcClient *client)
{
    if (client == NULL) {
        return;
    }

    pthread_mutex_lock(&client->lockMutex);
    while (client->callLockFlag != 0) {
        pthread_cond_wait(&client->lockCond, &client->lockMutex);
    }
    client->callLockFlag = 1;
    pthread_mutex_unlock(&client->lockMutex);
    return;
}

void UnlockRpcClient(RpcClient *client)
{
    if (client == NULL) {
        return;
    }

    pthread_mutex_lock(&client->lockMutex);
    client->callLockFlag = 0;
    pthread_cond_signal(&client->lockCond);
    pthread_mutex_unlock(&client->lockMutex);
    return;
}
