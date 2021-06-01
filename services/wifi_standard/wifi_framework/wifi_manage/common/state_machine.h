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

#ifndef OHOS_STA_MACHINE_H
#define OHOS_STA_MACHINE_H

#include <map>
#include <string>
#include <vector>
#include "handler.h"
#include "message_queue.h"
#include "state.h"

namespace OHOS {
namespace Wifi {
#define CMD_SET_OPERATIONAL_MODE 1
/* Message Processed */
static const bool HANDLED = true;
/* The message is not processed. */
static const bool NOT_HANDLED = false;

class SmHandler;
class StateMachine {
public:
    /**
     * @Description : SmHandler Initialization Function
     *
     * @return true :success, false : failed.
     */
    bool InitialStateMachine();

    /**
     * @Description : Start StateMachine.
     *
     */
    void Start();
    virtual void OnQuitting() = 0;
    virtual void OnHalting() = 0;

    /**
     * @Description : Set Handler.
     *
     * @param smHandler - SmHandler instance.[in]
     */
    void SetHandler(SmHandler *smHandler);

    /**
     * @Description : The Message is not handled.
     *
     * @param msg - Message object.[in]
     */
    void UnhandledMessage(InternalMessage *msg);

    /**
     * @Description Stop Handler Thread.
     *
     */
    void StopHandlerThread();

    /**
     * @Description : Start the timer.
     *
     * @param timerName - Timer Name.[in]
     * @param interval - Timer duration, in milliseconds.[in]
     */
    void StartTimer(int timerName, long interval);

    /**
     * @Description : Stop the timer.
     *
     * @param timerName - Timer Name.[in]
     */
    void StopTimer(int timerName);

    /**
     * @Description : Construct internal messages.
     *
     * @return InternalMessage* : Pointer to the constructed internal message.
     */
    InternalMessage *ObtainMessage();

    /**
     * @Description : Construct an information message based on
     * the original message.
     *
     * @param orig - Original message.[in]
     * @return InternalMessage* : Pointer to the constructed internal message.
     */
    InternalMessage *ObtainMessage(InternalMessage *orig);

    /**
     * @Description : Construct internal messages.
     *
     * @param what - Message Name.[in]
     * @return InternalMessage* : Pointer to the constructed internal message.
     */
    InternalMessage *ObtainMessage(int what);

    /**
     * @Description : Construct internal messages.
     *
     * @param what - Message Name.[in]
     * @param arg1 - Message parameters.[in]
     * @return InternalMessage* : Pointer to the constructed internal message.
     */
    InternalMessage *ObtainMessage(int what, int arg1);

    /**
     * @Description : Construct internal messages.
     *
     * @param what - Message Name.[in]
     * @param arg1 - Message parameters.[in]
     * @param arg2 - Message parameters.[in]
     * @return InternalMessage* : Pointer to the constructed internal message.
     */
    InternalMessage *ObtainMessage(int what, int arg1, int arg2);

    /**
     * @Description : Constructs internal messages and places the
     * messages in the message queue of the state machine.
     *
     * @param what - Message name.[in]
     */
    void SendMessage(int what);

    /**
     * @Description : Constructs internal messages and places the messages
     * in the message queue of the state machine.
     *
     * @param what - Message name.[in]
     * @param arg1 - Message parameter.[in]
     */
    void SendMessage(int what, int arg1);

    /**
     * @Description : Constructs internal messages and places the messages
     * in the message queue of the state machine.
     *
     * @param what - Message name.[in]
     * @param arg1 - Message parameter.[in]
     * @param arg2 - Message parameter.[in]
     */
    void SendMessage(int what, int arg1, int arg2);

    /**
     * @Description : Puts messages into the message queue of the state machine.
     *
     * @param msg - Message to be sent.[in]
     */
    void SendMessage(InternalMessage *msg);

    /**
     * @Description  Constructs internal messages and places them in the
     * message queue of the state machine. The messages are processed
     * after the specified delay time.
     *
     * @param what - Message Name.[in]
     * @param delayMillis - Delay time, in milliseconds.[in]
     */
    void SendMessageDelayed(int what, long delayMillis);

    /**
     * @Description : Constructs internal messages and places them in the
     * message queue of the state machine. The messages are processed
     * after the specified delay time.
     *
     * @param what - Message Name.[in]
     * @param arg1 - Message parameters.[in]
     * @param delayMillis - Delay time, in milliseconds.[in]
     */
    void SendMessageDelayed(int what, int arg1, long delayMillis);

    /**
     * @Description : Constructs internal messages and places them in the
     * message queue of the state machine. The messages are processed
     * after the specified delay time.
     *
     * @param what - Message Name.[in]
     * @param arg1 - Message parameters.[in]
     * @param arg2 - Message parameters.[in]
     * @param delayMillis - Delay time, in milliseconds.[in]
     */
    void SendMessageDelayed(int what, int arg1, int arg2, long delayMillis);

    /**
     * @Description : Constructs internal messages and places them in the
     * message queue of the state machine. The messages are processed
     * after the specified delay time.
     *
     * @param msg - Message to be sent.[in]
     * @param delayMillis - Delay time, in milliseconds.[in]
     */
    void SendMessageDelayed(InternalMessage *msg, long delayMillis);

protected:
    /**
     * @Description : Construct a new State Machine:: State Machine object.
     *
     * @param name - State name.[in]
     */
    explicit StateMachine(const std::string &name);

    /**
     * @Description : Destroy the State Machine:: State Machine object.
     *
     */
    virtual ~StateMachine();

    /**
     * @Description : Add state.
     *
     * @param state - state.[in]
     * @param parent - parent state.[in]
     */
    void AddState(State *state, State *parent);

    /**
     * @Description : Remove state.
     *
     * @param state - state.[in]
     */
    void RemoveState(State *state);

    /**
     * @Description : Set initial state.
     *
     * @param initialState - Initial state.[in]
     */
    void SetInitialState(State *initialState);

    /**
     * @Description : Transition to orther state.
     *
     * @param destState - state.[in]
     */
    void TransitionTo(State *destState);

    /**
     * @Description : Delay Message.
     *
     * @param msg - Message object.[in]
     */
    void DeferMessage(InternalMessage *msg);

private:
    SmHandler *pSmHandler;
    std::string mStateName;
};

typedef struct StateInfo {
    State *state;
    StateInfo *parentStateInfo;
    bool active;
} StateInfo;

class SmHandler : public Handler {
public:
    class QuittingState : public State {
    public:
        QuittingState() : State("QuittingState")
        {}
        ~QuittingState()
        {}
        void Enter()
        {}
        void Exit()
        {}
        bool ProcessMessage(InternalMessage *msg)
        {
            if (msg == nullptr) {
                return NOT_HANDLED;
            }
            return NOT_HANDLED;
        }
    };

    class HaltingState : public State {
    public:
        HaltingState() : State("HaltingState")
        {}
        ~HaltingState()
        {}
        void Enter()
        {}
        void Exit()
        {}
        bool ProcessMessage(InternalMessage *msg)
        {
            if (msg == nullptr) {
                return NOT_HANDLED;
            }
            return HANDLED;
        }
    };

    /**
     * @Description : Construct a new state machine Handler:: StateMachine Handler object.
     *
     * @param pStateMgr - Handler pointer.[in]
     */
    explicit SmHandler(StateMachine *pStateMgr);

    /**
     * @Description : Destroy the StateMachine Handler:: StateMachine Handler object.
     *
     */
    ~SmHandler();

    /**
     * @Description : SmHandler Initialization Function.
     *
     * @return true : success, false : failed.
     */
    bool InitialSmHandler();

    /**
     * @Description : Add a new state.
     *
     * @param state - State to be added.[in]
     * @param parent - parent of state.[in]
     * @return StateInfo*
     */
    StateInfo *AddState(State *state, State *parent);

    /**
     * @Description : Delete a state.
     *
     * @param state - State to be deleted.[in]
     */
    void RemoveState(State *state);

    /**
     * @Description : Sets the Initialization State.
     *
     * @param initialState - Initialization State.[in]
     */
    void SetInitialState(State *initialState);

    /**
     * @Description : State transition function.
     *
     * @param destState - Destination State.[in]
     */
    void TransitionTo(State *destState);

    /**
     * @Description : Delay Message Processing Function.
     *
     * @param msg - Message body pointer.[in]
     */
    void DeferMessage(InternalMessage *msg);

    /**
     * @Description : The state machine is constructed.
     *
     */
    void CompleteConstruction();

private:
    /**
     * @Description : Sets the initial state sequence.
     *
     */
    void SetupInitialStateVector();

    /**
     * @Description : Writes the inactive parent states of destState
     * and destState to the sequenceStateList list.
     *
     * @param destState - Target State Machine.[in]
     * @return StateInfo*
     */
    StateInfo *SetupTempStateStackWithStatesToEnter(State *destState);

    /**
     * @Description : Move Deferred Message At Front Of Queue.
     *
     */
    void MoveDeferredMessageAtFrontOfQueue();

    /**
     * @Description : Release all messages in deferred Messages.
     *
     */
    void ReleaseDeferredMessages();

    /**
     * @Description : Fill the status in the sequential status
     * list in reverse order.
     *
     * @return int
     */
    int MoveSequenceStateListToStateList();

    /**
     * @Description : Invoke the ProcessMessage interface of the current state
     * to process messages sent to the state machine. The entry/exit of the
     * state machine is also called, and the delayed messagei s put back
     * into queue when transitioning to a new state.
     *
     * @param msg - Messages.[in]
     */
    void HandleMessage(InternalMessage *msg);

    /**
     * @Description : Clean up After Quitting.
     *
     */
    void CleanupAfterQuitting();

    /**
     * @Description : Performing Status Transitions.
     *
     * @param msgProcessedState - Message processing status.[in]
     * @param msg - Messages.[in]
     */
    void PerformTransitions(State *msgProcessedState, InternalMessage *msg);

    /**
     * @Description : Process messages. If the current state doesnot process it,
     * the parent state processing is called, and so on. If all parent states
     * are not processed, invoke the UnhandledMessage method of the state machine.
     *
     * @param msg - Message body pointer.[in]
     * @return State*
     */
    State *ProcessMsg(InternalMessage *msg);

    /**
     * @Description : Invoke Exit() for each state from the first
     * state in the list to the public parent state.
     *
     * @param commonStateInfo - common parent state machine.[in]
     */
    void InvokeExitMethods(StateInfo *commonStateInfo);

    /**
     * @Description : Call the Enter method from the start state
     * index to the top of the state stack.
     *
     * @param index - Start state index of the
     *                                 state machine list.
     */
    void InvokeEnterMethods(int index);

    /**
     * @Description : Is Quit or not
     *
     * @param msg - Message body pointer.[in]
     * @return true : success, false: failed.
     */
    bool IsQuit(InternalMessage *msg);

private:
    typedef std::map<std::string, StateInfo *> StateInfoMap;
    typedef std::vector<StateInfo *> StateList;
    typedef std::vector<InternalMessage *> DeferredMessage;

    /* All state mappings of the state machine */
    StateInfoMap mStateInfo;
    /* From child state to parent state list */
    StateList mStateList;
    /* Top index of mStateList */
    int mStateListTopIndex;
    /* From parent state to child state list */
    StateList mSequenceStateList;
    /* Top of mSequenceStateList */
    int mSequenceStateListCount;
    /* Deferred Message Queue */
    DeferredMessage mDeferredMessages;
    /* State machine instance */
    StateMachine *pSM;
    /* Initial state */
    State *pInitialState;
    /* Target Status */
    State *pDestState;
    /* StateMachine exit or not */
    bool mHasQuit;
    /* Whether the state machine has been built */
    bool mIsConstructionCompleted;
    /*
     * All State exit/enter calls are true before the
     * last enter call in the target state.
     */
    bool mTransitionInProgress;
    /* Current Message */
    InternalMessage *pCurrentMsg;
    /* Exit state */
    QuittingState *pQuittingState;
    /* Pauses */
    HaltingState *pHaltingState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif