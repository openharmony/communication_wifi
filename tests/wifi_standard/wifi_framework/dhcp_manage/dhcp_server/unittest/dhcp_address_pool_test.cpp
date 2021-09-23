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

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdbool.h>
#include "string_ex.h"
#include "dhcp_define.h"
#include "dhcp_ipv4.h"
#include "dhcp_message.h"
#include "dhcp_option.h"
#include "dhcp_address_pool.h"
#include "address_utils.h"
#include "common_util.h"

using namespace testing::ext;

class DhcpAddressPoolTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        if (InitAddressPool(&testPool, "lo", NULL)) {
            printf("failed to initialized address pool.\n");
        }
    }
    virtual void TearDown()
    {
        FreeAddressPool(&testPool);
    }

public:
    DhcpAddressPool testPool;

};

HWTEST_F(DhcpAddressPoolTest, AddBindingTest, TestSize.Level1)
{
    AddressBinding bind = {0};
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.1");
    uint32_t testIp2 = ParseIpAddr("192.168.100.2");
    bind.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddBinding(&bind));
    bind.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac2[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddBinding(&bind));
    EXPECT_EQ(RET_FAILED, AddBinding(&bind));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac1));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac2));
}

HWTEST_F(DhcpAddressPoolTest, IsReservedTest, TestSize.Level1)
{
    AddressBinding bind = {0};
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0b, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.1");
    ASSERT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.2");
    ASSERT_TRUE(testIp2 != 0);
    bind.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddBinding(&bind));
    bind.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac2[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddReservedBinding(testMac2));
    EXPECT_EQ(RET_FAILED, AddBinding(&bind));
    EXPECT_EQ(0, IsReserved(testMac1));
    EXPECT_EQ(1, IsReserved(testMac2));
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac3[i];
    }
    EXPECT_EQ(0, IsReserved(testMac3));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac1));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac2));
}


HWTEST_F(DhcpAddressPoolTest, IsReservedIpTest, TestSize.Level1)
{
    AddressBinding bind = {0};
    bind.bindingMode = BIND_MODE_DYNAMIC;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.1");
    ASSERT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.2");
    ASSERT_TRUE(testIp2 != 0);
    bind.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &bind));
    bind.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac2[i];
    }
    bind.bindingMode = BIND_MODE_RESERVED;
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &bind));
    EXPECT_EQ(0, IsReservedIp(&testPool, testIp1));
    EXPECT_EQ(1, IsReservedIp(&testPool, testIp2));
    bind.ipAddress = testIp1;
    EXPECT_EQ(RET_SUCCESS, RemoveLease(&testPool, &bind));
    bind.ipAddress = testIp2;
    EXPECT_EQ(RET_SUCCESS, RemoveLease(&testPool, &bind));
}

HWTEST_F(DhcpAddressPoolTest, RemoveReservedBindingTest, TestSize.Level1)
{
    AddressBinding bind = {0}, bind2 = {0};
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x01, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x02, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0x00, 0x03, 0x3c, 0x65, 0x3a, 0x0b, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.1");
    EXPECT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.2");
    EXPECT_TRUE(testIp2 != 0);
    bind.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddBinding(&bind));
    bind2.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind2.chaddr[i] = testMac2[i];
    }
    bind2.bindingMode = BIND_MODE_RESERVED;
    ASSERT_EQ(RET_SUCCESS, AddBinding(&bind2));
    EXPECT_EQ(RET_FAILED, RemoveReservedBinding(testMac1));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac1));
    AddressBinding *binding = QueryBinding(testMac2, NULL);
    ASSERT_TRUE(binding != NULL);
    EXPECT_EQ(RET_SUCCESS, RemoveReservedBinding(testMac2));
    EXPECT_EQ(RET_FAILED, RemoveReservedBinding(testMac3));
}

HWTEST_F(DhcpAddressPoolTest, ReleaseBindingTest, TestSize.Level1)
{
    AddressBinding bind = {0};
    bind.bindingMode = BIND_ASSOCIATED;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0b, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.1");
    ASSERT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.2");
    ASSERT_TRUE(testIp2 != 0);
    bind.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac1[i];
    }
    ASSERT_EQ(RET_SUCCESS, AddBinding(&bind));
    bind.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        bind.chaddr[i] = testMac2[i];
    }
    ASSERT_EQ(RET_SUCCESS, AddBinding(&bind));
    EXPECT_EQ(RET_SUCCESS, ReleaseBinding(testMac1));
    EXPECT_EQ(RET_FAILED, ReleaseBinding(testMac3));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac1));
    EXPECT_EQ(RET_SUCCESS, RemoveBinding(testMac2));
}

HWTEST_F(DhcpAddressPoolTest, AddLeaseTest, TestSize.Level1)
{
    AddressBinding lease = {0};
    lease.bindingMode = BIND_MODE_DYNAMIC;
    lease.bindingStatus = BIND_ASSOCIATED;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3d, 0x65, 0x3a, 0x09, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    ASSERT_TRUE(testIp1 != 0);
    lease.ipAddress = testIp1;
    lease.leaseTime = DHCP_LEASE_TIME;
    lease.pendingTime = 1631240659;
    lease.bindingTime = 1631240659;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac1[i];
    }
    ASSERT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac2[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    EXPECT_EQ(RET_SUCCESS, RemoveLease(&testPool, &lease));
}

HWTEST_F(DhcpAddressPoolTest, GetLeaseTest, TestSize.Level1)
{
    AddressBinding lease = {0};
    lease.bindingMode = BIND_MODE_DYNAMIC;
    lease.bindingStatus = BIND_ASSOCIATED;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    ASSERT_TRUE(testIp1 != 0);
    lease.ipAddress = testIp1;
    lease.leaseTime = DHCP_LEASE_TIME;
    lease.pendingTime = 1631240659;
    lease.bindingTime = 1631240659;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    AddressBinding *leaseRec = GetLease(&testPool, testIp1);
    ASSERT_TRUE(leaseRec != NULL);
    EXPECT_EQ(lease.ipAddress, leaseRec->ipAddress);
    EXPECT_EQ(lease.leaseTime, leaseRec->leaseTime);
    EXPECT_EQ(lease.bindingMode, leaseRec->bindingMode);
    EXPECT_EQ(lease.bindingStatus, leaseRec->bindingStatus);
    EXPECT_EQ(RET_SUCCESS, RemoveLease(&testPool, &lease));
}

HWTEST_F(DhcpAddressPoolTest, UpdateLeaseTest, TestSize.Level1)
{
    AddressBinding lease = {0};
    lease.bindingMode = BIND_MODE_DYNAMIC;
    lease.bindingStatus = BIND_ASSOCIATED;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    ASSERT_TRUE(testIp1 != 0);
    lease.ipAddress = testIp1;
    lease.leaseTime = DHCP_LEASE_TIME;
    lease.pendingTime = 1631240659;
    lease.bindingTime = 1631240659;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    AddressBinding *leaseRec = GetLease(&testPool, testIp1);
    ASSERT_TRUE(leaseRec != NULL);
    EXPECT_EQ(lease.ipAddress, leaseRec->ipAddress);
    EXPECT_EQ(lease.leaseTime, leaseRec->leaseTime);
    EXPECT_EQ(lease.bindingMode, leaseRec->bindingMode);
    EXPECT_EQ(lease.bindingStatus, leaseRec->bindingStatus);
    lease.pendingTime = 1631260680;
    lease.bindingTime = 1631260680;
    EXPECT_EQ(RET_SUCCESS, UpdateLease(&testPool, &lease));
    EXPECT_EQ(lease.leaseTime, leaseRec->leaseTime);
    EXPECT_EQ(lease.leaseTime, leaseRec->leaseTime);
    EXPECT_EQ(RET_SUCCESS, RemoveLease(&testPool, &lease));
}


HWTEST_F(DhcpAddressPoolTest, LoadBindingRecodersTest, TestSize.Level1)
{
    AddressBinding lease = {0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    ASSERT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.102");
    ASSERT_TRUE(testIp2 != 0);
    uint32_t testIp3 = ParseIpAddr("192.168.100.103");
    ASSERT_TRUE(testIp3!= 0);

    lease.bindingMode = BIND_MODE_DYNAMIC;
    lease.bindingStatus = BIND_ASSOCIATED;
    lease.pendingTime = 1631260680;
    lease.bindingTime = 1631260680;

    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0b, 0};
    lease.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac1[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    lease.ipAddress = testIp2;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac2[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));
    lease.ipAddress = testIp3;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac3[i];
    }
    EXPECT_EQ(RET_SUCCESS, AddLease(&testPool, &lease));

    EXPECT_EQ(RET_SUCCESS, SaveBindingRecoders(&testPool, 1));
    EXPECT_EQ(HASH_SUCCESS, ClearAll(&testPool.leaseTable));
    EXPECT_TRUE(testPool.leaseTable.size == 0);
    EXPECT_EQ(RET_SUCCESS, LoadBindingRecoders(&testPool));
    EXPECT_TRUE(testPool.leaseTable.size == 3);
    EXPECT_TRUE(GetLease(&testPool, testIp1) != NULL);
    EXPECT_TRUE(GetLease(&testPool, testIp2) != NULL);
    EXPECT_TRUE(GetLease(&testPool, testIp3) != NULL);
}

HWTEST_F(DhcpAddressPoolTest, GetBindingByMacTest, TestSize.Level1)
{
    AddressBinding lease = {0};
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    ASSERT_TRUE(testIp1 != 0);

    lease.bindingMode = BIND_MODE_DYNAMIC;
    lease.bindingStatus = BIND_ASSOCIATED;
    lease.pendingTime = 1631260680;
    lease.bindingTime = 1631260680;
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};

    lease.ipAddress = testIp1;
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        lease.chaddr[i] = testMac1[i];
    }
    ASSERT_EQ(RET_SUCCESS, AddBinding(&lease));
    AddressBinding *binding = QueryBinding(testMac1, 0);
    ASSERT_TRUE(binding != NULL);
    EXPECT_EQ(lease.ipAddress, binding->ipAddress);
    EXPECT_EQ(lease.leaseTime, binding->leaseTime);
    EXPECT_EQ(lease.bindingMode, binding->bindingMode);
    EXPECT_EQ(lease.bindingStatus, binding->bindingStatus);
}

