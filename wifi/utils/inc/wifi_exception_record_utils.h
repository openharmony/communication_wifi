#ifndef OHOS_WIFI_EXCEPTION_RECORD_UTILS_H
#define OHOS_WIFI_EXCEPTION_RECORD_UTILS_H

#include <string>
#include <vector>
#include <variant>
#include <cstdint>

namespace OHOS{
namespace Wifi{

enum class ExceptionReason{
    DHCP_CONNECTION_FAIL   = 101,
    DHCP_GET_IP_TIMEOUT    = 102,
    DHCP_IPV4_RESULT_FAIL  = 103,
    DHCP_IP_EXPIRED        = 104,
};

struct DhcpFaultDetail {
    int dhcpStatus; std::string extra;
    bool operator==(const DhcpFaultDetail& o) const { return dhcpStatus == o.dhcpStatus && extra == o.extra; }
};

using FaultDetail = std::variant<DhcpFaultDetail>;

struct WifiExceptionRecord{
    std::string     ssid;
    int64_t         timestamp;
    ExceptionReason reason;
    FaultDetail     detail;
};

struct MergedFault{
    int64_t         timestamp;
    ExceptionReason reason;
    FaultDetail     detail;
};

struct ApGroup{
    std::string              ssid;
    std::vector<MergedFault> faults;
};

class WifiExceptionRecordUtils{
public:
    WifiExceptionRecordUtils() = default;
    ~WifiExceptionRecordUtils() = default;

    int32_t AddException(const WifiExceptionRecord& record);
    int32_t GetAllExceptions(std::vector<ApGroup>& groups);
    int32_t ClearExceptions();
    std::string FormatTime(int64_t ts);
    std::string ReasonToString(ExceptionReason r);
    std::string CategoryToString(ExceptionReason r);


};

}
}

#endif