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
#include "client.h"
#include <signal.h>
#include <sys/time.h>
#include "log.h"

#undef LOG_TAG
#define LOG_TAG "OHOS_WIFI_RPC_CLIENT"

const int FD_CHECK_TIMEOUT = 1000; /* poll wait time, units: ms */
const int REMOTE_CALL_TIMEOUT = 5; /* remote call timeout, units: second */
const int CLIENT_STATE_IDLE = 0;
const int CLIENT_STATE_DEAL_REPLY = 1;
const int CLIENT_STATE_DEAL_CALLBACK = 2;
const int TMP_BUFF_SIZE = 16;
const int US_1000 = 1000;

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
            client->threadRunFlag = 0;
            return NULL;
        }
        buff = ContextGetReadRecord(client->context);
    }
    if (!client->threadRunFlag) {
        if (buff) {
            free(buff);
        }
        return NULL;
    }
    return buff;
}

static void RpcClientDealReadMsg(RpcClient *client, char *buff)
{
    if (client == NULL) {
        return;
    }

    char szTmp[TMP_BUFF_SIZE] = {0};
    if (snprintf_s(szTmp, sizeof(szTmp), sizeof(szTmp) - 1, "N%c", client->context->cSplit) < 0) {
        return;
    }
    if (strncmp(buff, szTmp, strlen(szTmp)) == 0) { /* deal reply message */
        pthread_mutex_lock(&client->mutex);
        while (client->waitReply) {
            pthread_cond_wait(&client->condW, &client->mutex);
        }
        client->waitReply = CLIENT_STATE_DEAL_REPLY;
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        pthread_cond_signal(&client->condN);
        pthread_mutex_unlock(&client->mutex);
    } else { /* deal callback message */
        pthread_mutex_lock(&client->mutex);
        while (client->waitReply) {
            pthread_cond_wait(&client->condW, &client->mutex);
        }
        client->waitReply = CLIENT_STATE_DEAL_CALLBACK;
        client->context->oneProcess = buff;
        client->context->nPos = strlen(szTmp);
        client->context->nSize = strlen(buff);
        pthread_mutex_unlock(&client->mutex);
        OnTransact(client->context);
        pthread_mutex_lock(&client->mutex);
        free(buff);
        client->waitReply = CLIENT_STATE_IDLE;
        pthread_cond_signal(&client->condW);
        pthread_mutex_unlock(&client->mutex);
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
    return NULL;
}

RpcClient *CreateRpcClient(const char *path)
{
    int fd = ConnectUnixServer(path);
    if (fd < 0) {
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
        close(fd);
        free(client);
        return NULL;
    }
    client->context->fd = fd;
    client->threadRunFlag = 1;
    client->threadId = 0;
    client->waitReply = CLIENT_STATE_IDLE;
    client->callLockFlag = 0;
    pthread_mutex_init(&client->mutex, NULL);
    pthread_cond_init(&client->condN, NULL);
    pthread_cond_init(&client->condW, NULL);
    pthread_mutex_init(&client->lockMutex, NULL);
    pthread_cond_init(&client->lockCond, NULL);
    int ret = pthread_create(&client->threadId, NULL, RpcClientThreadDeal, client);
    if (ret) {
        pthread_cond_destroy(&client->condN);
        pthread_cond_destroy(&client->condW);
        pthread_mutex_destroy(&client->mutex);
        pthread_cond_destroy(&client->lockCond);
        pthread_mutex_destroy(&client->lockMutex);
        ReleaseContext(client->context);
        close(fd);
        free(client);
        return NULL;
    }
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
        pthread_cond_destroy(&client->condN);
        pthread_cond_destroy(&client->condW);
        pthread_mutex_destroy(&client->mutex);
        pthread_cond_destroy(&client->lockCond);
        pthread_mutex_destroy(&client->lockMutex);
        close(client->context->fd);
        ReleaseContext(client->context);
        free(client);
    }
    return;
}

int RemoteCall(RpcClient *client)
{
    if (client == NULL) {
        return -1;
    }

    int ret = 0;
    Context *context = client->context;
    while (context->wBegin != context->wEnd && ret >= 0) {
        ret = ContextWriteNet(context);
    }
    if (ret < 0) {
        return ret;
    }
    ret = 0; /* reset ret value */
    pthread_mutex_lock(&client->mutex);
    struct timeval now;
    struct timespec outtime;
    gettimeofday(&now, NULL);
    outtime.tv_sec = now.tv_sec + REMOTE_CALL_TIMEOUT;
    outtime.tv_nsec = now.tv_usec * US_1000;
    while (client->waitReply != CLIENT_STATE_DEAL_REPLY) {
        ret = pthread_cond_timedwait(&client->condN, &client->mutex, &outtime);
        if (ret != 0) {
            break;
        }
    }
    pthread_mutex_unlock(&client->mutex);
    return ((ret == 0) ? 0 : -1);
}

void ReadClientEnd(RpcClient *client)
{
    if (client == NULL) {
        return;
    }

    pthread_mutex_lock(&client->mutex);
    free(client->context->oneProcess);
    client->context->oneProcess = NULL;
    client->waitReply = CLIENT_STATE_IDLE;
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
