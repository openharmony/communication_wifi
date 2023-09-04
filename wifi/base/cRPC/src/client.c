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
    while (client->waitReply != CLIENT_STATE_DEAL_REPLY && client->waitReply != CLIENT_STATE_EXIT) {
        pthread_cond_wait(&client->condW, &client->mutex);
    }
    if (client->waitReply == CLIENT_STATE_EXIT) {
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
