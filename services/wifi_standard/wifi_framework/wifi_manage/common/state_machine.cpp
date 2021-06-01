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
#include "state_machine.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STATE_MACHINE"

namespace OHOS {
namespace Wifi {
static const int SM_QUIT_CMD = -1;
static const int SM_INIT_CMD = -2;
StateMachine::StateMachine(const std::string &name) : pSmHandler(nullptr), mStateName(name)
{}

StateMachine::~StateMachine()
{
    LOGD("StateMachine::~StateMachine");
    if (pSmHandler != nullptr) {
        delete pSmHandler;
    }
}

bool StateMachine::InitialStateMachine()
{
    pSmHandler = new (std::nothrow) SmHandler(this);
    if (pSmHandler == nullptr) {
        LOGE("pSmHandler alloc failed.\n");
        return false;
    }

    if (!pSmHandler->InitialSmHandler()) {
        LOGE("InitialSmHandler failed.\n");
        return false;
    }

    return true;
}

void StateMachine::Start()
{
    if (pSmHandler == nullptr) {
        LOGE("Start StateMachine failed, smHandler is nullptr!");
        return;
    }

    pSmHandler->CompleteConstruction();
    return;
}

void StateMachine::SetHandler(SmHandler *smHandler)
{
    pSmHandler = smHandler;
}

void StateMachine::UnhandledMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    LOGD("msg not handled  msg:%{public}d", msg->GetMessageName());
}

void StateMachine::AddState(State *state, State *parent)
{
    pSmHandler->AddState(state, parent);
}

void StateMachine::RemoveState(State *state)
{
    pSmHandler->RemoveState(state);
}

void StateMachine::SetInitialState(State *initialState)
{
    pSmHandler->SetInitialState(initialState);
}
void StateMachine::TransitionTo(State *destState)
{
    pSmHandler->TransitionTo(destState);
}

void StateMachine::DeferMessage(InternalMessage *msg)
{
    pSmHandler->DeferMessage(msg);
}

void StateMachine::StopHandlerThread()
{
    pSmHandler->StopHandlerThread();
}

InternalMessage *StateMachine::ObtainMessage()
{
    return MessageManage::GetInstance().Obtain();
}

InternalMessage *StateMachine::ObtainMessage(InternalMessage *orig)
{
    if (orig == nullptr) {
        return nullptr;
    }
    return MessageManage::GetInstance().Obtain(orig);
}

InternalMessage *StateMachine::ObtainMessage(int what)
{
    return MessageManage::GetInstance().Obtain(what);
}

InternalMessage *StateMachine::ObtainMessage(int what, int arg1)
{
    return MessageManage::GetInstance().Obtain(what, arg1, 0);
}

InternalMessage *StateMachine::ObtainMessage(int what, int arg1, int arg2)
{
    return MessageManage::GetInstance().Obtain(what, arg1, arg2);
}

void StateMachine::SendMessage(int what)
{
    pSmHandler->SendMessage(ObtainMessage(what));
    return;
}

void StateMachine::SendMessage(int what, int arg1)
{
    pSmHandler->SendMessage(ObtainMessage(what, arg1));
    return;
}

void StateMachine::SendMessage(int what, int arg1, int arg2)
{
    pSmHandler->SendMessage(ObtainMessage(what, arg1, arg2));
    return;
}

void StateMachine::SendMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    pSmHandler->SendMessage(msg);
    return;
}

void StateMachine::SendMessageDelayed(int what, long delayMillis)
{
    pSmHandler->SendMessageDelayed(ObtainMessage(what), delayMillis);
    return;
}

void StateMachine::SendMessageDelayed(int what, int arg1, long delayMillis)
{
    pSmHandler->SendMessageDelayed(ObtainMessage(what, arg1), delayMillis);
    return;
}

void StateMachine::SendMessageDelayed(int what, int arg1, int arg2, long delayMillis)
{
    pSmHandler->SendMessageDelayed(ObtainMessage(what, arg1, arg2), delayMillis);
    return;
}

void StateMachine::SendMessageDelayed(InternalMessage *msg, long delayMillis)
{
    pSmHandler->SendMessageDelayed(msg, delayMillis);
    return;
}

void StateMachine::StartTimer(int timerName, long interval)
{
    LOGD("Enter StateMachine::StartTimer, timerName is %{public}d, interval is %ld.", timerName, interval);
    SendMessageDelayed(timerName, interval);
    return;
}

void StateMachine::StopTimer(int timerName)
{
    LOGD("Enter StateMachine::StopTimer, timerName is %{public}d.", timerName);
    pSmHandler->DeleteMessageFromQueue(timerName);
    return;
}

SmHandler::SmHandler(StateMachine *pStateMgr)
{
    mStateInfo.clear();
    mStateList.clear();
    mStateListTopIndex = -1;
    mSequenceStateList.clear();
    mSequenceStateListCount = 0;
    mDeferredMessages.clear();
    pSM = pStateMgr;
    pInitialState = nullptr;
    pDestState = nullptr;
    mHasQuit = false;
    mIsConstructionCompleted = false;
    mTransitionInProgress = false;
    pCurrentMsg = nullptr;
    pQuittingState = nullptr;
    pHaltingState = nullptr;
}

SmHandler::~SmHandler()
{
    LOGD("SmHandler::~SmHandler");
    if (pQuittingState != nullptr) {
        delete pQuittingState;
    }

    if (pHaltingState != nullptr) {
        delete pHaltingState;
    }

    StopHandlerThread();
    ReleaseDeferredMessages();
    CleanupAfterQuitting();

    return;
}

bool SmHandler::InitialSmHandler()
{
    if (!InitialHandler()) {
        return false;
    }

    pQuittingState = new (std::nothrow) QuittingState();
    if (pQuittingState == nullptr) {
        LOGE("Failed to init quitting state!");
        return false;
    }

    pHaltingState = new (std::nothrow) HaltingState();
    if (pHaltingState == nullptr) {
        LOGE("Failed to init halting state!");
        return false;
    }

    return true;
}

StateInfo *SmHandler::AddState(State *state, State *parent)
{
    LOGD("SmHandler::AddState function.");

    StateInfo *parentStateInfo = nullptr;
    StateInfoMap::iterator it = mStateInfo.begin();
    if (parent != nullptr) {
        it = mStateInfo.find(parent->GetName());
        if (it != mStateInfo.end()) {
            parentStateInfo = it->second;
        }
        if (parentStateInfo == nullptr) {
            LOGD("parentStateInfo is null, add parent first. parent->GetName():%{public}s", parent->GetName().c_str());
            /* Recursively add our parent as it's not been added yet. */
            AddState(parent, nullptr);
        } else {
            LOGD("parentStateInfo is not null, go on.");
        }
    }

    StateInfo *stateInfo = nullptr;
    it = mStateInfo.find(state->GetName());
    if (it != mStateInfo.end()) {
        stateInfo = it->second;
    }
    if (stateInfo == nullptr) {
        stateInfo = new (std::nothrow) StateInfo();
        if (stateInfo == nullptr) {
            LOGE("failed to new StateInfo!");
            return nullptr;
        }
        mStateInfo.insert(StateInfoMap::value_type(state->GetName(), stateInfo));
    }

    /* Validate that we aren't adding the same state in two different hierarchies. */
    if (stateInfo->parentStateInfo != nullptr && stateInfo->parentStateInfo != parentStateInfo) {
        LOGE("The same state cannot be added to two different hierarchies!");
    }

    stateInfo->state = state;
    stateInfo->parentStateInfo = parentStateInfo;
    stateInfo->active = false;

    LOGD("successfully added a new state!");

    return stateInfo;
}

void SmHandler::RemoveState(State *state)
{
    StateInfoMap::iterator it = mStateInfo.find(state->GetName());
    StateInfo *stateInfo = nullptr;
    if (it != mStateInfo.end()) {
        stateInfo = it->second;
    }
    if (stateInfo == nullptr || stateInfo->active) {
        return;
    }

    it = mStateInfo.begin();
    while (it != mStateInfo.end()) {
        if (it->second->parentStateInfo == stateInfo) {
            return;
        }
        ++it;
    }

    it = mStateInfo.find(state->GetName());
    if (it != mStateInfo.end()) {
        delete it->second;
        it->second = nullptr;
        mStateInfo.erase(it);
    }
}

void SmHandler::SetInitialState(State *initialState)
{
    pInitialState = initialState;
}

void SmHandler::CompleteConstruction()
{
    /* Determines the maximum depth of the state hierarchy. */
    int maxDepth = 0;
    StateInfoMap::iterator it = mStateInfo.begin();
    while (it != mStateInfo.end()) {
        int depth = 0;
        StateInfo *tempStateInfo = it->second;
        while (tempStateInfo != nullptr) {
            depth++;
            tempStateInfo = tempStateInfo->parentStateInfo;
        }

        if (maxDepth < depth) {
            maxDepth = depth;
        }

        ++it;
    }

    LOGD("SmHandler::CompleteConstruction, maxDepth:%{public}d", maxDepth);
    mStateList.reserve(maxDepth);
    mSequenceStateList.reserve(maxDepth);

    SetupInitialStateVector();

    SendMessageAtTime(pSM->ObtainMessage(SM_INIT_CMD), 0);

    return;
}

void SmHandler::SetupInitialStateVector()
{
    LOGD("SmHandler::SetupInitialStateVector");

    if (pInitialState == nullptr) {
        LOGE("SmHandler::SetupInitialStateVector  please set initial state first!");
        return;
    }

    StateInfoMap::iterator it = mStateInfo.find(pInitialState->GetName());
    StateInfo *startStateInfo = nullptr;
    if (it != mStateInfo.end()) {
        startStateInfo = it->second;
    }

    for (mSequenceStateListCount = 0; startStateInfo != nullptr; mSequenceStateListCount++) {
        mSequenceStateList[mSequenceStateListCount] = startStateInfo;
        startStateInfo = startStateInfo->parentStateInfo;
    }

    /* Clearing the stateList. */
    mStateListTopIndex = -1;

    MoveSequenceStateListToStateList();
}

StateInfo *SmHandler::SetupTempStateStackWithStatesToEnter(State *destState)
{
    mSequenceStateListCount = 0;
    StateInfoMap::iterator it = mStateInfo.find(destState->GetName());
    StateInfo *curStateInfo = nullptr;
    if (it != mStateInfo.end()) {
        curStateInfo = it->second;
    }

    if (curStateInfo == nullptr) {
        return nullptr;
    }

    do {
        mSequenceStateList[mSequenceStateListCount++] = curStateInfo;
        curStateInfo = curStateInfo->parentStateInfo;
    } while ((curStateInfo != nullptr) && (!curStateInfo->active));

    return curStateInfo;
}

void SmHandler::MoveDeferredMessageAtFrontOfQueue()
{
    LOGD("Enter SmHandler::MoveDeferredMessageAtFrontOfQueue.");

    for (int i = mDeferredMessages.size() - 1; i >= 0; i--) {
        InternalMessage *curMsg = mDeferredMessages[i];
        if (curMsg == nullptr) {
            LOGE("SmHandler::MoveDeferredMessageAtFrontOfQueue: curMsg is null.");
            continue;
        }
        SendMessageAtFrontOfQueue(curMsg);
    }
    mDeferredMessages.clear();

    return;
}

void SmHandler::ReleaseDeferredMessages()
{
    for (int i = mDeferredMessages.size() - 1; i >= 0; i--) {
        InternalMessage *curMsg = mDeferredMessages[i];
        if (curMsg != nullptr) {
            delete curMsg;
        }
    }
    mDeferredMessages.clear();

    return;
}

int SmHandler::MoveSequenceStateListToStateList()
{
    LOGD("SmHandler::MoveSequenceStateListToStateList mSequenceStateListCount:%{public}d", mSequenceStateListCount);

    int newIndex = mStateListTopIndex + 1;
    int i = mSequenceStateListCount - 1;
    int j = newIndex;
    while (i >= 0) {
        mStateList[j] = mSequenceStateList[i];
        j += 1;
        i -= 1;
    }

    mStateListTopIndex = j - 1;

    return newIndex;
}

void SmHandler::TransitionTo(State *destState)
{
    pDestState = static_cast<State *>(destState);
}

void SmHandler::CleanupAfterQuitting()
{
    pSM->SetHandler(nullptr);
    pSM = nullptr;
    pCurrentMsg = nullptr;
    mStateList.clear();
    mSequenceStateList.clear();
    mDeferredMessages.clear();
    pInitialState = nullptr;
    pDestState = nullptr;
    mHasQuit = true;

    StateInfoMap::iterator it = mStateInfo.begin();
    while (it != mStateInfo.end()) {
        delete it->second;
        it->second = nullptr;
        it = mStateInfo.erase(it);
    }
    mStateInfo.clear();
}

void SmHandler::PerformTransitions(State *msgProcessedState, InternalMessage *msg)
{
    if (msgProcessedState == nullptr || msg == nullptr) {
        LOGE("poniter is null.");
    }

    State *destState = pDestState;

    if (destState != nullptr) {
        LOGD("SmHandler::PerformTransitions destState name is: %{public}s", destState->GetName().c_str());
        while (true) {
            StateInfo *commonStateInfo = SetupTempStateStackWithStatesToEnter(destState);
            mTransitionInProgress = true;
            InvokeExitMethods(commonStateInfo);

            int stateListEnteringIndex = MoveSequenceStateListToStateList();
            InvokeEnterMethods(stateListEnteringIndex);

            MoveDeferredMessageAtFrontOfQueue();

            if (destState != pDestState) {
                destState = pDestState;
            } else {
                break;
            }
        }
        pDestState = nullptr;
    }

    if (destState != nullptr) {
        if (destState->GetName() == pQuittingState->GetName()) {
            pSM->OnQuitting();
            CleanupAfterQuitting();
        } else if (destState->GetName() == pHaltingState->GetName()) {
            pSM->OnHalting();
        }
    }

    return;
}

void SmHandler::HandleMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    if (!mHasQuit) {
        if (pSM != nullptr && msg->GetMessageName() != SM_INIT_CMD && msg->GetMessageName() != SM_QUIT_CMD) {
        }

        pCurrentMsg = msg;

        State *msgProcessedState = nullptr;
        if (mIsConstructionCompleted) {
            LOGD("SmHandler::HandleMessage  ProcessMsg!");
            msgProcessedState = ProcessMsg(msg);
        } else if (!mIsConstructionCompleted && msg->GetMessageName() == SM_INIT_CMD) {
            LOGD("SmHandler::HandleMessage  msg: SM_INIT_CMD");
            mIsConstructionCompleted = true;
            InvokeEnterMethods(0);
        } else {
            LOGE("The start method not called!");
        }

        if (pSM != nullptr) {
            PerformTransitions(msgProcessedState, msg);
        } else {
            LOGE("poniter is null.");
        }

        if (pSM != nullptr && msg->GetMessageName() != SM_INIT_CMD && msg->GetMessageName() != SM_QUIT_CMD) {
        }
    }

    return;
}

void SmHandler::DeferMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    LOGD("Enter SmHandler::DeferMessage.");

    InternalMessage *newMsg = pSM->ObtainMessage(msg);
    if (newMsg == nullptr) {
        LOGE("SmHandler::DeferMessage: newMsg is null.");
        return;
    }

    mDeferredMessages.push_back(newMsg);
    return;
}

State *SmHandler::ProcessMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return nullptr;
    }
    LOGD("SmHandler::ProcessMsg mStateListTopIndex:%{public}d", mStateListTopIndex);
    StateInfo *curStateInfo = mStateList[mStateListTopIndex];
    if (curStateInfo == nullptr) {
        LOGE("StateInfo is null.");
        return nullptr;
    }

    if (IsQuit(msg)) {
        TransitionTo(static_cast<State *>(pQuittingState));
    } else {
        while (curStateInfo->state && (!curStateInfo->state->ProcessMessage(msg))) {
            curStateInfo = curStateInfo->parentStateInfo;

            if (curStateInfo == nullptr) {
                pSM->UnhandledMessage(msg);
                break;
            }
        }
    }

    return (curStateInfo != nullptr) ? curStateInfo->state : nullptr;
}

void SmHandler::InvokeExitMethods(StateInfo *commonStateInfo)
{
    while ((mStateListTopIndex >= 0) && (mStateList[mStateListTopIndex] != commonStateInfo)) {
        if (mStateList[mStateListTopIndex] != nullptr) {
            State *curState = mStateList[mStateListTopIndex]->state;
            if (curState != nullptr) {
                curState->Exit();
            }
            mStateList[mStateListTopIndex]->active = false;
        }
        mStateListTopIndex -= 1;
    }
}

void SmHandler::InvokeEnterMethods(int index)
{
    for (int i = index; i <= mStateListTopIndex; i++) {
        if (index == mStateListTopIndex) {
            /* Last enter state for transition. */
            mTransitionInProgress = false;
        }
        LOGD("SmHandler::InvokeEnterMethods  mStateListTopIndex:%{public}d, i: %{public}d", mStateListTopIndex, i);
        if (mStateList[i] != nullptr && mStateList[i]->state != nullptr) {
            mStateList[i]->state->Enter();
            mStateList[i]->active = true;
        }
    }
    /* ensure flag set to false if no methods called. */
    mTransitionInProgress = false;
}

bool SmHandler::IsQuit(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    return (msg->GetMessageName() == SM_QUIT_CMD);
}
}  // namespace Wifi
}  // namespace OHOS