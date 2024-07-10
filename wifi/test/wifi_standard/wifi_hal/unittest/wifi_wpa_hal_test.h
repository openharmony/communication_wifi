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
#ifndef OHOS_WIFI_WPA_HAL_TEST_H
#define OHOS_WIFI_WPA_HAL_TEST_H

#include "wifi_hal_module_manage.h"
#include "wifi_wpa_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wpa_ctrl {
    int s;
};

void DealP2pFindInfo(char *buf);
void DealP2pGoNegRequest(const char *buf);
void DealGroupStartInfo(char *buf);
void DealServiceDiscRespEvent(char *buf);
void DealP2pGroupRemove(const char *buf);
void DealP2pConnectChanged(const char *buf, int type);
void DealDeviceLostEvent(const char *buf);
void DealInvitationReceived(char *buf, int type);
void DealInvitationResultEvent(const char *buf);
void DealP2pGoNegotiationFailure(const char *buf);
void DealP2pConnectFailed(const char *buf);
void DealP2pChannelSwitch(const char *buf);
void DealGroupFormationFailureEvent(const char *buf);
void DealProvDiscPbcReqEvent(const char *buf, unsigned long length);
void DealProDiscPbcRespEvent(const char *buf, unsigned long length);
void DealProDiscEnterPinEvent(const char *buf, unsigned long length);
void DealProvDiscShowPinEvent(const char *buf, unsigned long length);
void DealP2pServDiscReqEvent(char *buf);
void DealP2pInterfaceCreated(const char *buf);
int DealWpaP2pCallBackSubFun(char *p);
int WpaP2pCallBackFunc(char *p);
void ParseAuthReject(const char *p);
void ParseAssocReject(const char *p);
void WpaCallBackFuncTwo(const char *p);
void WpaCallBackFunc(const char *p);
int MyWpaCtrlPending(struct wpa_ctrl *ctrl);
void StopWpaSuppilicant(ModuleInfo *p);
void StopWpaSoftAp(ModuleInfo *p);
void *RecoverWifiProcess(void *arg);
void RecoverWifiThread(void);
void *WpaReceiveCallback(void *arg);
int WpaCliConnect(WifiWpaInterface *p);
void WpaCliClose(WifiWpaInterface *p);
int WpaCliAddIface(WifiWpaInterface *p, const AddInterfaceArgv *argv, bool isWpaAdd);
int WpaCliRemoveIface(WifiWpaInterface *p, const char *name);
int WpaCliWpaTerminate(void);

#ifdef __cplusplus
}
#endif

#endif