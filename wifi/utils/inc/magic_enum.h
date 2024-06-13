/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef MAGIC_ENUM_H
#define MAGIC_ENUM_H

#include <array>
#include <exception>
#include <stdexcept>
#include <string_view>
#include <string>

#    if defined(__clang__)
#        define PRETTY_FUNCTION_NAME __PRETTY_FUNCTION__
#        define ENUM_OFFSET               2
#    elif defined(__GNUC__)
#        define PRETTY_FUNCTION_NAME __PRETTY_FUNCTION__
#        define ENUM_OFFSET               51
#    elif defined(_MSC_VER)
#        define PRETTY_FUNCTION_NAME __FUNCSIG__
#        define ENUM_OFFSET               17
#    endif
namespace OHOS {
namespace Wifi {
namespace magic_enum {

const int MAGIC_ENUM_RANGE_MAX = 1024;
template <typename E, E V>
constexpr std::string_view GetEnumValueName()
{
    std::string_view name{PRETTY_FUNCTION_NAME, sizeof(PRETTY_FUNCTION_NAME) - ENUM_OFFSET};
    for (std::size_t i = name.size(); i > 0; --i) {
        if (!((name[i - 1] >= '0' && name[i - 1] <= '9') || (name[i - 1] >= 'a' && name[i - 1] <= 'z') ||
              (name[i - 1] >= 'A' && name[i - 1] <= 'Z') || (name[i - 1] == '_'))) {
            name.remove_prefix(i);
            break;
        }
    }
    if (name.size() > 0 && ((name.front() >= 'a' && name.front() <= 'z') ||
                            (name.front() >= 'A' && name.front() <= 'Z') || (name.front() == '_'))) {
        return name;
    }
    return {}; // Invalid name.
}

template <typename E, E V>
constexpr bool IsValid()
{
    return GetEnumValueName<E, V>().size() != 0;
}

template <int... Is>
constexpr auto MakeIntegerListWrapper(std::integer_sequence<int, Is...>)
{
    constexpr int halfSize = sizeof...(Is) / 2;
    return std::integer_sequence<int, (Is - halfSize)...>();
}

constexpr auto TEST_INTEGER_SEQUENCE_V =
    MakeIntegerListWrapper(std::make_integer_sequence<int, MAGIC_ENUM_RANGE_MAX>());

template <typename E, int... Is>
constexpr size_t GetEnumSize(std::integer_sequence<int, Is...>)
{
    constexpr std::array<bool, sizeof...(Is)> valid{IsValid<E, static_cast<E>(Is)>()...};
    constexpr std::size_t count = [](decltype((valid)) validValue) constexpr noexcept->std::size_t
    {
        auto nSize = std::size_t{0};
        for (std::size_t index = 0; index < validValue.size(); ++index) {
            if (validValue[index]) {
                ++nSize;
            }
        }
        return nSize;
    }
    (valid);
    return count;
}

template <typename E>
constexpr std::size_t ENUM_SIZE_V = GetEnumSize<E>(TEST_INTEGER_SEQUENCE_V);

template <typename E, int... Is>
constexpr auto GetAllValidValues(std::integer_sequence<int, Is...>)
{
    constexpr std::array<bool, sizeof...(Is)> valid{IsValid<E, static_cast<E>(Is)>()...};
    constexpr std::array<int, sizeof...(Is)> integerValue{Is...};
    std::array<int, ENUM_SIZE_V<E>> values{};
    for (std::size_t i = 0, v = 0; i < sizeof...(Is); ++i) {
        if (valid[i]) {
            values[v++] = integerValue[i];
        }
    }
    return values;
}

template <typename E, int... Is>
constexpr auto GetAllValidNames(std::integer_sequence<int, Is...>)
{
    constexpr std::array<std::string_view, sizeof...(Is)> names{GetEnumValueName<E, static_cast<E>(Is)>()...};
    std::array<std::string_view, ENUM_SIZE_V<E>> valid_names{};
    for (std::size_t i = 0, v = 0; i < names.size(); ++i) {
        if (names[i].size() != 0) {
            valid_names[v++] = names[i];
        }
    }
    return valid_names;
}

template <typename E>
constexpr auto ENUM_NAMES_V = GetAllValidNames<E>(TEST_INTEGER_SEQUENCE_V);

template <typename E>
constexpr auto ENUM_VALUES_V = GetAllValidValues<E>(TEST_INTEGER_SEQUENCE_V);

template <typename E>
constexpr std::string_view Enum2string(E V)
{
    constexpr auto validNames = ENUM_NAMES_V<E>;
    constexpr auto validValues = ENUM_VALUES_V<E>;
    constexpr auto enumSize = ENUM_SIZE_V<E>;
    for (size_t i = 0; i < enumSize; ++i) {
        if (static_cast<int>(V) == validValues[i]) {
            return validNames[i];
        }
    }
    return "";
}

template <typename E>
constexpr auto Enum2Name(E value)
{
    int num = static_cast<int>(value);
    if (num > MAGIC_ENUM_RANGE_MAX / 2 || num < -(MAGIC_ENUM_RANGE_MAX / 2)) { // 2: maxnum
        return std::to_string(static_cast<int>(value));
    } else {
        return std::string(Enum2string<E>(value));
    }
}

} // namespace magic_enum
} // namespace Wifi
} // namespace OHOS

#endif