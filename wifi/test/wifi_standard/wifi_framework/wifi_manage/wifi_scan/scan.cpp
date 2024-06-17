    void GetScanControlInfoTest()
    {
        pScanService->GetScanControlInfo();
    }
 
    void ClearScanTrustSceneIdsTest()
    {
        pScanService->ClearScanTrustSceneIds();
    }
    void SetMovingFreezeScanedTest()
    {
        pScanService->SetMovingFreezeScaned(false);
    }
 
    void ApplyTrustListPolicyTest()
    {
        ScanService::ScanType scanType = ScanService::ScanType::SCAN_TYPE_EXTERN;
        pScanService->ApplyTrustListPolicy(scanType);
    }
 
    void AllowExternScanByPowerIdelStateTest()
    {
        pScanService->AllowExternScanByPowerIdelState();
    }
 
    void AllowExternScanByGnssFixStateTest()
    {
        pScanService->AllowExternScanByGnssFixState();
    }
 
    void AllowExternScanByAbnormalAppTest()
    {
        pScanService->AllowExternScanByAbnormalApp();
    }
    void SetNetworkInterfaceUpDownTest()
    {
        pScanService->SetNetworkInterfaceUpDown(false);
    }
 
    void SystemScanConnectedPolicyTest()
    {
        int interval = 0;
        pScanService->SystemScanConnectedPolicy(interval);
    }
 
    void SystemScanDisconnectedPolicyTest() 
    {
        int interval = 0;
        int count = 0;
        pScanService->SystemScanDisconnectedPolicy(interval, count);
    }
};


HWTEST_F(ScanServiceTest, GetScanControlInfoTest, TestSize.Level1)
{
    GetScanControlInfoTest();
}
 
HWTEST_F(ScanServiceTest, ClearScanTrustSceneIdsTest, TestSize.Level1)
{
    ClearScanTrustSceneIdsTest();
}
 
HWTEST_F(ScanServiceTest, SetMovingFreezeScanedTest, TestSize.Level1)
{
    SetMovingFreezeScanedTest();
}
 
HWTEST_F(ScanServiceTest, ApplyTrustListPolicyTest, TestSize.Level1)
{
    ApplyTrustListPolicyTest();
}
 
HWTEST_F(ScanServiceTest, AllowExternScanByPowerIdelStateTest, TestSize.Level1)
{
    AllowExternScanByPowerIdelStateTest();
}
 
HWTEST_F(ScanServiceTest, AllowExternScanByGnssFixStateTest, TestSize.Level1)
{
    AllowExternScanByGnssFixStateTest();
}
 
HWTEST_F(ScanServiceTest, AllowExternScanByAbnormalAppTest, TestSize.Level1)
{
    AllowExternScanByAbnormalAppTest();
}
 
HWTEST_F(ScanServiceTest, SetNetworkInterfaceUpDownTest, TestSize.Level1)
{
    SetNetworkInterfaceUpDownTest();
}
 
HWTEST_F(ScanServiceTest, SystemScanConnectedPolicyTest, TestSize.Level1)
{
    SystemScanConnectedPolicyTest();
}
 
HWTEST_F(ScanServiceTest, SystemScanDisconnectedPolicyTest, TestSize.Level1)
{
    SystemScanDisconnectedPolicyTest();
}

