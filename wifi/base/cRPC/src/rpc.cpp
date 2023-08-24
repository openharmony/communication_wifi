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

#include "rpc.h"

DEFINE_WIFILOG_LABEL("RpcClient");

int OnTransact(Context *context)
{
    if (context == nullptr) {
        WIFI_LOGE("OnTransact: context is NULL!");
        return -1;
    }
    using namespace OHOS::WIFI;
    Rpc::rpcMsgCallback callback = Rpc::GetRpcMsgCallback();
    callback(context);
    return 0;
}

namespace OHOS {
namespace WIFI {
Rpc::rpcMsgCallback Rpc::recvRpcMsgCallback = nullptr;

Rpc::~Rpc()
{
    UnInitClient();
}

int Rpc::InitClient()
{
    recvRpcMsgCallback = std::bind(&Rpc::RecvRpcMsgCallback, this, std::placeholders::_1);
    const std::string sockPath = CONFIG_ROOR_DIR"/unix_sock.sock";
    client = ::CreateRpcClient(sockPath.c_str());
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
    
void Rpc::RecvRpcMsgCallback(Context *context)
{
    if (context == nullptr) {
        WIFI_LOGE("RecvRpcMsgCallback: context is NULL!");
        return;
    }

    int event = 0;
    if (::ReadInt(context, &event) < 0) {
        WIFI_LOGE("RecvRpcMsgCallback: read event failed!");
        return;
    }

    OnDealRpcMsg(context, event);
    return;
}

Rpc::rpcMsgCallback Rpc::GetRpcMsgCallback()
{
    return recvRpcMsgCallback;
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
    return ::ReadInt(client->context, i);
}

int Rpc::ReadString(char *str, int count)
{
    CHECK_PTR_RETURN(client, -1);
    return ::ReadStr(client->context, str, count);
}
}  // namespace Wifi
}  // namespace OHOS