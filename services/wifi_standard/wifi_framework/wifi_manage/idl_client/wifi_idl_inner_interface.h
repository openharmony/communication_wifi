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

#ifndef OHOS_WIFI_IDL_INNER_INTERFACE_H
#define OHOS_WIFI_IDL_INNER_INTERFACE_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description Get the Ap Rpc Client object.
 *
 * @return RpcClient*
 */
RpcClient *GetApRpcClient(void);
/**
 * @Description Get the Chip Rpc Client object.
 *
 * @return RpcClient*
 */
RpcClient *GetChipRpcClient(void);
/**
 * @Description Get the Sta Rpc Client object.
 *
 * @return RpcClient*
 */
RpcClient *GetStaRpcClient(void);
/**
 * @Description Get the Supplicant Rpc Client object.
 *
 * @return RpcClient*
 */
RpcClient *GetSupplicantRpcClient(void);

#ifdef __cplusplus
}
#endif
#endif