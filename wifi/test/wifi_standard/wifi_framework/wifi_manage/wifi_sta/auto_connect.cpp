constexpr int UMTS_AUTH_TYPE_TAG = 0xdb;
constexpr int UMTS_AUTS_TYPE_TAG = 0xdc;

void InitRandomMacInfoTest()
    {
        const std::string bssid="";
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_NONE;
        WifiStoreRandomMac randomMacInfo;
        pStaStateMachine->InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);
    }
 
   void OnNetworkHiviewEventTest() 
   {
        const int  wpaCBAssocing= 3;
        const int  wpaCBAssoced= 4;
        pStaStateMachine->OnNetworkHiviewEvent(wpaCBAssocing);
        pStaStateMachine->OnNetworkHiviewEvent(wpaCBAssoced);
   }
 
   void OnNetworkAssocEventTest()
   {
        const int  wpaCBAssocing= 3;
        pStaStateMachine->OnNetworkConnectionEvent(-1, "a2:b1:f5:c7:d1");
   }
   void GetDataSlotIdTest() 
   {
        pStaStateMachine->GetDataSlotId();
   }
   void GetCardTypeTest()
   {
        CardType cardType;
        pStaStateMachine->GetCardType(cardType);
   }
    void GetDefaultIdTest() 
    {
        pStaStateMachine->GetDefaultId(WIFI_INVALID_SIM_ID);
        pStaStateMachine->GetDefaultId(1);
    }
 
    void GetSimCardStateTest()
    {
        pStaStateMachine->GetSimCardState(0);
    }
 
    void IsValidSimIdTest() 
    {
        pStaStateMachine->IsValidSimId(0);
        pStaStateMachine->IsValidSimId(1);
    }
    void IsMultiSimEnabledTest()
    {
        pStaStateMachine->IsMultiSimEnabled();
    }
    void SimAkaAuthTest()
    {
        pStaStateMachine->SimAkaAuth("", SIM_AUTH_EAP_SIM_TYPE);
    }
 
    void GetGsmAuthResponseWithLengthTest()
    {
        EapSimGsmAuthParam param;
        pStaStateMachine->GetGsmAuthResponseWithLength(param);
    }
 
    void GetGsmAuthResponseWithoutLengthTest()
    {
        EapSimGsmAuthParam param;
        pStaStateMachine->GetGsmAuthResponseWithoutLength(param);
    }
 
    void PreWpaEapUmtsAuthEventTest()
    {
        pStaStateMachine->PreWpaEapUmtsAuthEvent();
    }
 
    void FillUmtsAuthReqTest()
    {
        EapSimUmtsAuthParam param;
        pStaStateMachine->FillUmtsAuthReq(param);
    }
    void ParseAndFillUmtsAuthParamTest()
    {
        std::vector<uint8_t> nonce;
        nonce.push_back(UMTS_AUTH_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
        nonce.clear();
        nonce.push_back(UMTS_AUTS_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
    }
 
    void GetUmtsAuthResponseTest()
    {
        EapSimUmtsAuthParam param;
        pStaStateMachine->GetUmtsAuthResponse(param);
    }
 
    void DealWpaEapSimAuthEventTest()
    {
        InternalMessage *msg = nullptr;
        pStaStateMachine->DealWpaEapSimAuthEvent(msg);
        InternalMessage msg1;
        msg1.SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT);
        EapSimGsmAuthParam param;
        msg1.SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(&msg1);
        InternalMessage msg2;
        msg2.SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg2.SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(&msg1);
    }
    void HandlePortalNetworkPorcessTests()
    {
        pStaStateMachine->HandlePortalNetworkPorcess();
    }
 
    void DealWpaEapUmtsAuthEventTest()
    {
        InternalMessage *msg = nullptr;
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg);
        InternalMessage msg1;
        EapSimUmtsAuthParam param;
        msg1.SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg1.SetMessageObj(param);
        pStaStateMachine->DealWpaEapUmtsAuthEvent(&msg1);
        InternalMessage msg2;
        msg2.SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        param.rand = "1111111";
        param.autn = "222222";
        msg2.SetMessageObj(param);
        pStaStateMachine->DealWpaEapUmtsAuthEvent(&msg1);
    }


HWTEST_F(StaStateMachineTest, InitRandomMacInfoTest, TestSize.Level1)
{
    InitRandomMacInfoTest();
}
 
HWTEST_F(StaStateMachineTest, OnNetworkHiviewEventTest, TestSize.Level1)
{
    OnNetworkHiviewEventTest();
}
 
HWTEST_F(StaStateMachineTest, OnNetworkAssocEventTest, TestSize.Level1)
{
    OnNetworkAssocEventTest();
}
 
HWTEST_F(StaStateMachineTest, GetDataSlotIdTest, TestSize.Level1)
{
    GetDataSlotIdTest();
}
 
HWTEST_F(StaStateMachineTest, GetCardTypeTest, TestSize.Level1)
{
    GetCardTypeTest();
}
 
HWTEST_F(StaStateMachineTest, GetDefaultIdTest, TestSize.Level1)
{
    GetDefaultIdTest();
}
 
HWTEST_F(StaStateMachineTest, GetSimCardStateTest, TestSize.Level1)
{
    GetSimCardStateTest();
}
 
HWTEST_F(StaStateMachineTest, IsValidSimIdTest, TestSize.Level1)
{
    IsValidSimIdTest();
}
 
HWTEST_F(StaStateMachineTest, IsMultiSimEnabledTest, TestSize.Level1)
{
    IsMultiSimEnabledTest();
}
 
HWTEST_F(StaStateMachineTest, SimAkaAuthTest, TestSize.Level1)
{
    SimAkaAuthTest();
}
 
HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithLengthTest();
}
 
HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithoutLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithoutLengthTest();
}
 
HWTEST_F(StaStateMachineTest, PreWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    PreWpaEapUmtsAuthEventTest();
}
 
 
HWTEST_F(StaStateMachineTest, FillUmtsAuthReqTest, TestSize.Level1)
{
    FillUmtsAuthReqTest();
}
 
HWTEST_F(StaStateMachineTest, ParseAndFillUmtsAuthParamTest, TestSize.Level1)
{
    ParseAndFillUmtsAuthParamTest();
}
 
HWTEST_F(StaStateMachineTest, GetUmtsAuthResponseTest, TestSize.Level1)
{
    GetUmtsAuthResponseTest();
}
 
HWTEST_F(StaStateMachineTest, DealWpaEapSimAuthEventTest, TestSize.Level1)
{
    DealWpaEapSimAuthEventTest();
}
 
HWTEST_F(StaStateMachineTest, HandlePortalNetworkPorcessTests, TestSize.Level1)
{
    HandlePortalNetworkPorcessTests();
}
 
HWTEST_F(StaStateMachineTest, DealWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    DealWpaEapUmtsAuthEventTest();
}