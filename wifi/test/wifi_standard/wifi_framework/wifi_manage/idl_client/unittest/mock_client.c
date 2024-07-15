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

#include "mock_client.h"
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <string.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "wifi_log.h"
#include "net.h"

#undef LOG_TAG
#define LOG_TAG "WifiRpcClient"

const int FD_CHECK_TIMEOUT = 1000; /* poll wait time, units: ms */
const int CLIENT_STATE_IDLE = 0;
const int CLIENT_STATE_DEAL_REPLY = 1;
const int CLIENT_STATE_EXIT = 2;

#define TMP_BUFF_SIZE 16
RpcClient *CreateRpcClient(const char *path)
{
    RpcClient *client = (RpcClient *)calloc(1, sizeof(RpcClient));
    if (client == NULL) {
        return NULL;
    }
    client->context = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
    return client;
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
    return 0;
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