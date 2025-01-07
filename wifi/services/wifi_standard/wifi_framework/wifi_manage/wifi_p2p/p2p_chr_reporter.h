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

#ifndef OHOS_P2P_CHR_REPORTER_H
#define OHOS_P2P_CHR_REPORTER_H

#include <cstdint>
#include <string>
#include "p2p_macro.h"

namespace OHOS {
namespace Wifi {

#define P2P_CHR_DEFAULT_REASON_CODE (-1)

enum P2pChrState {
    DEVICE_DISCOVERY = 0,
    PROVISION_DISCOVERY,
    GROUP_OWNER_NEGOTIATION,
    GROUP_FORMATION,
    P2P_INVITATION,
    P2P_INTERFACE_STATE_DISCONNECTED = 5,
    P2P_INTERFACE_STATE_DISABLE,
    P2P_INTERFACE_STATE_INACTIVE,
    P2P_INTERFACE_STATE_SCANNING = 8,
    P2P_INTERFACE_STATE_AUTHENTICATING = 9,
    P2P_INTERFACE_STATE_ASSOCIATING = 10,
    P2P_INTERFACE_STATE_ASSOCIATED = 11,
    P2P_INTERFACE_STATE_4WAY_HANDSHAKE_1,
    P2P_INTERFACE_STATE_4WAY_HANDSHAKE_2,
    P2P_INTERFACE_STATE_4WAY_HANDSHAKE_3,
    P2P_INTERFACE_STATE_GROUP_HANDSHAKE,
    P2P_INTERFACE_STATE_COMPLETED = 16,
    GC_CONNECTED = 17
};

enum P2pEventCode {
    P2P_CHR_EVENT_INTERFACE_STATE_CHANGE = 1,
    P2P_CHR_EVENT_STATE_CHANGE_BEFORE_GROUP_FORMATION_SUCCESS,
};

enum DeviceRole {
    UNKNOWN_ROLE = 0,
    GROUP_OWNER,
    CLIENT,
};

class P2pChrReporter {
    FRIEND_GTEST(P2pChrReporter);
public:
    static constexpr int INDEX_EVENT_TYPE = 0;
    static constexpr int INDEX_STATE = 1;
    static constexpr int INDEX_REASON_CODE = 2;
    static constexpr int INDEX_MINOR_CODE = 3;

    static constexpr int STATE_OFFSET = 11;
    static constexpr int DEVICE_ROLE_OFFSET = 9;
    static constexpr int DISCONNECT_REASON_UNKNOWN = 0;
    static constexpr int DR_TO_SWITCH_MGMT = 259;
    static constexpr int P2P_STATUS_SUCCESS = 0;

    static P2pChrReporter& GetInstance()
    {
        static P2pChrReporter p2pChrReporter;
        return p2pChrReporter;
    }

    void ReportErrCodeBeforeGroupFormationSucc(int state, int errCode, int minorCode);
    void SetWpsSuccess(bool success);
    void SetDeviceRole(DeviceRole role);
    void ResetState();
    void ProcessChrEvent(const std::string &notifyParam);
    void ReportP2pInterfaceStateChange(int state, int errCode, int minorCode);
    void UploadP2pChrErrEvent();

private:
    void UpdateErrorMessage(int state, int errCode, int minorCode);
    void ReportP2pConnectFailed(int state, int errCode, int minorCode);
    void ReportP2pAbnormalDisconnect(int state, int errCode, int minorCode);
    uint16_t GetP2pSpecificError(int state, int errCode);
    bool IsNormalErrCode(int errCode);
    void OnP2pChrErrCodeReport(int errCode);

    bool mWpsSuccess = false;
    DeviceRole mRole = UNKNOWN_ROLE;
    int mLastP2pState = DEVICE_DISCOVERY;
    int mLastErrCode = P2P_CHR_DEFAULT_REASON_CODE;
    int mLastMinorCode = P2P_CHR_DEFAULT_REASON_CODE;
};

} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_P2P_CHR_REPORTER_H */
