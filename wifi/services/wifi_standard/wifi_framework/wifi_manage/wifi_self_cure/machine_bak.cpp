/*
TransVecToIpAddress
DoSlowArpTest
DoArpTest
GetNextIpAddr
IsSameEncryptType
SetSelfCureFailInfo
SetSelfCureConnectFailInfo
IsSoftApSsidSameWithWifi
*/
std::string SelfCureStateMachine::TransVecToIpAddress(const std::vector<uint32_t>& vec)
bool SelfCureStateMachine::DoSlowArpTest(const std::string& testIpAddr)
bool SelfCureStateMachine::DoArpTest(std::string& ipAddress, std::string& gateway)
std::string SelfCureStateMachine::GetNextIpAddr(const std::string& gateway, const std::string& currentAddr,
                                                const std::vector<std::string>& testedAddr)
bool SelfCureStateMachine::IsSameEncryptType(const std::string& scanInfoKeymgmt, const std::string& deviceKeymgmt)
int SelfCureStateMachine::SetSelfCureFailInfo(WifiSelfCureHistoryInfo &info,
                                              std::vector<std::string>& histories, int cnt)
int SelfCureStateMachine::SetSelfCureConnectFailInfo(WifiSelfCureHistoryInfo &info,
                                                     std::vector<std::string>& histories, int cnt)
bool SelfCureStateMachine::IsSoftApSsidSameWithWifi(const HotspotConfig& curApConfig)
