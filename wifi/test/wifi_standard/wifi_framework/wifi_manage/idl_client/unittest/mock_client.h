/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#ifndef CRPC_CLIENT_H
#define CRPC_CLIENT_H

#include <pthread.h>
#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RpcClient RpcClient;

/*
 * RPC CLIENT
 * RPC client sends a request and wait for a response from the server,
 * and process the callback function initiated by the server.
 * so we start a thread to get the server's reply message, judge message type,
 * and to deal reply or callback.
 * the client may process like this:
 * 1. thread: poll read ---> server reply msg ---> notify RemoteCall
 *    client: request functions --->RemoteCall ---> Wait Reply ---> Get Return
 * 2. thread: poll read ---> server callback msg ---> OnTransact
 *    client: OnTransact ---> deal event callback functions
 */

struct RpcClient {
    Context *context;
    int threadRunFlag;
    pthread_t threadId;
    int waitReply;
    pthread_mutex_t mutex;
    pthread_cond_t condW;
    int callLockFlag;
    pthread_mutex_t lockMutex;
    pthread_cond_t lockCond;
};

RpcClient *CreateRpcClient(const char *path);
void LockRpcClient(RpcClient *client);
void UnlockRpcClient(RpcClient *client);
void ReleaseRpcClient(RpcClient *client);
int RemoteCall(RpcClient *client);
void ReadClientEnd(RpcClient *client);
#ifdef __cplusplus
}
#endif
#endif