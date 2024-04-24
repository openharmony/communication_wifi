/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_COUNTRY_CODE_DEFINE_H
#define WIFI_COUNTRY_CODE_DEFINE_H

#include <string>

namespace OHOS {
namespace Wifi {
constexpr int WIFI_COUNTRY_CODE_POLICE_DEF_LEN = 5;
constexpr const char* WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY = "persist.wifi.country_code.dynamic_update";
constexpr const char* DEFAULT_WIFI_COUNTRY_CODE_ZZ = "ZZ";  // for tablets only, priority greater than HK
constexpr const char* DEFAULT_WIFI_COUNTRY_CODE = "HK";
constexpr const char* DEFAULT_RO_RUN_MODE = "normal";
constexpr const char* FACTORY_RO_RUN_MODE = "factory";
constexpr const char* FACTORY_WIFI_COUNTRY_CODE = "const.wifi.country_code.factory";
constexpr const char* WIFI_COUNTRY_CODE_RUN_MODE = "const.wifi.country_code.runmode";
constexpr const char* WIFI_COUNTRY_CODE_CONFIG = "const.wifi.country_code.conf";
constexpr const char* WIFI_COUNTRY_CODE_CONFIG_DEFAULT = "0";
constexpr const char* DEFAULT_REGION_KEY = "const.global.region";
constexpr const char* DEFAULT_REGION = "CN";
constexpr const char* OPERATOR_NUMERIC_KEY = "ril.operator.numeric";  // plmn cached
constexpr const char* DEFAULT_OPERATOR_NUMERIC = "00000";
constexpr int WIFI_COUNTRY_CODE_SIZE = 16;
constexpr int FACTORY_WIFI_COUNTRY_CODE_SIZE = 16;
constexpr int WIFI_COUNTRY_CODE_RUN_MODE_SIZE = 16;
constexpr int WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_SIZE = 16;
constexpr int OPERATOR_NUMERIC_SIZE = 16;
constexpr int SYSTEM_PARAMETER_ERROR_CODE = 0;
constexpr int PLMN_LEN = 3;
constexpr int PLMN_SUBSTR_LEFT = 0;
constexpr int PLMN_SUBSTR_RIGHT = 3;
constexpr int SLOT_ID = 0;
constexpr int MAX_SCAN_SAVED_SIZE = 3;
constexpr unsigned int COUNTRY_CODE_EID = 7;
constexpr int DEFAULT_REGION_SIZE = 16;
constexpr int BSSID_VECTOR_INDEX_ZERO = 0;
constexpr int BSSID_VECTOR_INDEX_ONE = 1;
constexpr int BSSID_VECTOR_INDEX_TWO = 2;
constexpr int BSSID_VECTOR_INDEX_THREE = 3;
constexpr int FEATURE_MCC = 0;
constexpr int FEATURE_RCV_AP_CONNECTED = 1;
constexpr int FEATURE_RCV_SCAN_RESLUT = 2;
constexpr int FEATURE_USE_REGION = 3;
constexpr int FEATURE_USE_ZZ = 4;

struct MccEntry {
    int mnc;
    const char* iso;
    int smallestDigitsMcc;
};

/*
 * The table below is built from two resources:
 *
 * 1) ITU "Mobile Network Code (MNC) for the international
 *   identification plan for mobile terminals and mobile users"
 *   which is available as an annex to the ITU operational bulletin
 *   available here: http://www.itu.int/itu-t/bulletin/annex.html
 *
 * 2) The ISO 3166 country codes list, available here:
 *    http://www.iso.org/iso/en/prods-services/iso3166ma/02iso-3166-code-lists/index.html
 *
 * very importent：The order of mnc must be from small to large！
 */
const MccEntry MCC_TABLE[] = {
    // Fake country code, which is the default value, Scan only 2.4G channels and passively receive 5G beacons
    {0, "zz", 0},

    // Greece
    {202, "gr", 2},

    // Netherlands Kingdom of the
    {204, "nl", 2},

    // Belgium
    {206, "be", 2},

    // France
    {208, "fr", 2},

    // Monaco Principality of
    {212, "mc", 2},

    // Andorra Principality of
    {213, "ad", 2},

    // Spain
    {214, "es", 2},

    // Hungary Republic of
    {216, "hu", 2},

    // Bosnia and Herzegovina
    {218, "ba", 2},

    // Croatia Republic of
    {219, "hr", 2},

    // Serbia and Montenegro
    {220, "rs", 2},

    // Italy
    {222, "it", 2},

    // Vatican City State
    {225, "va", 2},

    // Romania
    {226, "ro", 2},

    // Switzerland Confederation of
    {228, "ch", 2},

    // Czech Republic
    {230, "cz", 2},

    // Slovak Republic
    {231, "sk", 2},

    // Austria
    {232, "at", 2},

    // United Kingdom of Great Britain and Northern Ireland
    {234, "gb", 2},

    // United Kingdom of Great Britain and Northern Ireland
    {235, "gb", 2},

    // Denmark
    {238, "dk", 2},

    // Sweden
    {240, "se", 2},

    // Norway
    {242, "no", 2},

    // Finland
    {244, "fi", 2},

    // Lithuania Republic of
    {246, "lt", 2},

    // Latvia Republic of
    {247, "lv", 2},

    // Estonia Republic of
    {248, "ee", 2},

    // Russian Federation
    {250, "ru", 2},

    // Ukraine
    {255, "ua", 2},

    // Belarus Republic of
    {257, "by", 2},

    // Moldova Republic of
    {259, "md", 2},

    // Poland Republic of
    {260, "pl", 2},

    // Germany Federal Republic of
    {262, "de", 2},

    // Gibraltar
    {266, "gi", 2},

    // Portugal
    {268, "pt", 2},

    // Luxembourg
    {270, "lu", 2},

    // Ireland
    {272, "ie", 2},

    // Iceland
    {274, "is", 2},

    // Albania Republic of
    {276, "al", 2},

    // Malta
    {278, "mt", 2},

    // Cyprus Republic of
    {280, "cy", 2},

    // Georgia
    {282, "ge", 2},

    // Armenia Republic of
    {283, "am", 2},

    // Bulgaria Republic of
    {284, "bg", 2},

    // Turkey
    {286, "tr", 2},

    // Faroe Islands
    {288, "fo", 2},

    // Abkhazia Georgia
    {289, "ge", 2},

    // Greenland Denmark
    {290, "gl", 2},

    // San Marino Republic of
    {292, "sm", 2},

    // Slovenia Republic of
    {293, "si", 2},

    // The Former Yugoslav Republic of Macedonia
    {294, "mk", 2},

    // Liechtenstein Principality of
    {295, "li", 2},

    // Montenegro Republic of
    {297, "me", 2},

    // Canada
    {302, "ca", 3},

    // Saint Pierre and Miquelon Collectivit territoriale de la Rpublique franaise
    {308, "pm", 2},

    // United States of America
    {310, "us", 3},

    // United States of America
    {311, "us", 3},

    // United States of America
    {312, "us", 3},

    // United States of America
    {313, "us", 3},

    // United States of America
    {314, "us", 3},

    // United States of America
    {315, "us", 3},

    // United States of America
    {316, "us", 3},

    // Puerto Rico
    {330, "pr", 2},

    // United States Virgin Islands
    {332, "vi", 2},

    // Mexico
    {334, "mx", 3},

    // Jamaica
    {338, "jm", 3},

    // Guadeloupe French Department of
    {340, "gp", 2},

    // Barbados
    {342, "bb", 3},

    // Antigua and Barbuda
    {344, "ag", 3},

    // Cayman Islands
    {346, "ky", 3},

    // British Virgin Islands
    {348, "vg", 3},

    // Bermuda
    {350, "bm", 2},

    // Grenada
    {352, "gd", 2},

    // Montserrat
    {354, "ms", 2},

    // Saint Kitts and Nevis
    {356, "kn", 2},

    // Saint Lucia
    {358, "lc", 2},

    // Saint Vincent and the Grenadines
    {360, "vc", 2},

    // Netherlands Antilles
    {362, "ai", 2},

    // Aruba
    {363, "aw", 2},

    // Bahamas Commonwealth of the
    {364, "bs", 2},

    // Anguilla
    {365, "ai", 3},

    // Dominica Commonwealth of
    {366, "dm", 2},

    // Cuba
    {368, "cu", 2},

    // Dominican Republic
    {370, "do", 2},

    // Haiti Republic of
    {372, "ht", 2},

    // Trinidad and Tobago
    {374, "tt", 2},

    // Turks and Caicos Islands
    {376, "tc", 2},

    // Azerbaijani Republic
    {400, "az", 2},

    // Kazakhstan Republic of
    {401, "kz", 2},

    // Bhutan Kingdom of
    {402, "bt", 2},

    // India Republic of
    {404, "in", 2},

    // India Republic of
    {405, "in", 2},

    // India Republic of
    {406, "in", 2},

    // Pakistan Islamic Republic of
    {410, "pk", 2},

    // Afghanistan
    {412, "af", 2},

    // Sri Lanka Democratic Socialist Republic of
    {413, "lk", 2},

    // Myanmar Union of
    {414, "mm", 2},

    // Lebanon
    {415, "lb", 2},

    // Jordan Hashemite Kingdom of
    {416, "jo", 2},

    // Syrian Arab Republic
    {417, "sy", 2},

    // Iraq Republic of
    {418, "iq", 2},

    // Kuwait State of
    {419, "kw", 2},

    // Saudi Arabia Kingdom of
    {420, "sa", 2},

    // Yemen Republic of
    {421, "ye", 2},

    // Oman Sultanate of
    {422, "om", 2},

    // Palestine
    {423, "ps", 2},

    // United Arab Emirates
    {424, "ae", 2},

    // Israel State of
    {425, "il", 2},

    // Bahrain Kingdom of
    {426, "bh", 2},

    // Qatar State of
    {427, "qa", 2},

    // Mongolia
    {428, "mn", 2},

    // Nepal
    {429, "np", 2},

    // United Arab Emirates
    {430, "ae", 2},

    // United Arab Emirates
    {431, "ae", 2},

    // Iran Islamic Republic of
    {432, "ir", 2},

    // Uzbekistan Republic of
    {434, "uz", 2},

    // Tajikistan Republic of
    {436, "tj", 2},

    // Kyrgyz Republic
    {437, "kg", 2},

    // Turkmenistan
    {438, "tm", 2},

    // Japan
    {440, "jp", 2},

    // Japan
    {441, "jp", 2},

    // Korea Republic of
    {450, "kr", 2},

    // Viet Nam Socialist Republic of
    {452, "vn", 2},

    // "Hong Kong, China"
    {454, "hk", 2},

    // "Macao, China"
    {455, "mo", 2},

    // Cambodia Kingdom of
    {456, "kh", 2},

    // Lao People's Democratic Republic
    {457, "la", 2},

    // China People's Republic of
    {460, "cn", 2},

    // China People's Republic of
    {461, "cn", 2},

    // "Taiwan, China"
    {466, "tw", 2},

    // Democratic People's Republic of Korea
    {467, "kp", 2},

    // Bangladesh People's Republic of
    {470, "bd", 2},

    // Maldives Republic of
    {472, "mv", 2},

    // Malaysia
    {502, "my", 2},

    // Australia
    {505, "au", 2},

    // Indonesia Republic of
    {510, "id", 2},

    // Democratic Republic of Timor-Leste
    {514, "tl", 2},

    // Philippines Republic of the
    {515, "ph", 2},

    // Thailand
    {520, "th", 2},

    // Singapore Republic of
    {525, "sg", 2},

    // Brunei Darussalam
    {528, "bn", 2},

    // New Zealand
    {530, "nz", 2},

    // Northern Mariana Islands Commonwealth of the
    {534, "mp", 2},

    // Guam
    {535, "gu", 2},

    // Nauru Republic of
    {536, "nr", 2},

    // Papua New Guinea
    {537, "pg", 2},

    // Tonga Kingdom of
    {539, "to", 2},

    // Solomon Islands
    {540, "sb", 2},

    // Vanuatu Republic of
    {541, "vu", 2},

    // Fiji Republic of
    {542, "fj", 2},

    // Wallis and Futuna Territoire franais d'outre-mer
    {543, "wf", 2},

    // American Samoa
    {544, "as", 2},

    // Kiribati Republic of
    {545, "ki", 2},

    // New Caledonia Territoire franais d'outre-mer
    {546, "nc", 2},

    // French Polynesia Territoire franais d'outre-mer
    {547, "pf", 2},

    // Cook Islands
    {548, "ck", 2},

    // Samoa Independent State of
    {549, "ws", 2},

    // Micronesia Federated States of
    {550, "fm", 2},

    // Marshall Islands Republic of the
    {551, "mh", 2},

    // Palau Republic of
    {552, "pw", 2},

    // Tuvalu
    {553, "tv", 2},

    // Niue
    {555, "nu", 2},

    // Egypt Arab Republic of
    {602, "eg", 2},

    // Algeria People's Democratic Republic of
    {603, "dz", 2},

    // Morocco Kingdom of
    {604, "ma", 2},

    // Tunisia
    {605, "tn", 2},

    // Libya Socialist People's Libyan Arab Jamahiriya
    {606, "ly", 2},

    // Gambia Republic of the
    {607, "gm", 2},

    // Senegal Republic of
    {608, "sn", 2},

    // Mauritania Islamic Republic of
    {609, "mr", 2},

    // Mali Republic of
    {610, "ml", 2},

    // Guinea Republic of
    {611, "gn", 2},

    // C?te d'Ivoire Republic of
    {612, "ci", 2},

    // Burkina Faso
    {613, "bf", 2},

    // Niger Republic of the
    {614, "ne", 2},

    // Togolese Republic
    {615, "tg", 2},

    // Benin Republic of
    {616, "bj", 2},

    // Mauritius Republic of
    {617, "mu", 2},

    // Liberia Republic of
    {618, "lr", 2},

    // Sierra Leone
    {619, "sl", 2},

    // Ghana
    {620, "gh", 2},

    // Nigeria Federal Republic of
    {621, "ng", 2},

    // Chad Republic of
    {622, "td", 2},

    // Central African Republic
    {623, "cf", 2},

    // Cameroon Republic of
    {624, "cm", 2},

    // Cape Verde Republic of
    {625, "cv", 2},

    // Sao Tome and Principe Democratic Republic of
    {626, "st", 2},

    // Equatorial Guinea Republic of
    {627, "gq", 2},

    // Gabonese Republic
    {628, "ga", 2},

    // Congo Republic of the
    {629, "cg", 2},

    // Democratic Republic of the Congo
    {630, "cg", 2},

    // Angola Republic of
    {631, "ao", 2},

    // Guinea-Bissau Republic of
    {632, "gw", 2},

    // Seychelles Republic of
    {633, "sc", 2},

    // Sudan Republic of the
    {634, "sd", 2},

    // Rwanda Republic of
    {635, "rw", 2},

    // Ethiopia Federal Democratic Republic of
    {636, "et", 2},

    // Somali Democratic Republic
    {637, "so", 2},

    // Djibouti Republic of
    {638, "dj", 2},

    // Kenya Republic of
    {639, "ke", 2},

    // Tanzania United Republic of
    {640, "tz", 2},

    // Uganda Republic of
    {641, "ug", 2},

    // Burundi Republic of
    {642, "bi", 2},

    // Mozambique Republic of
    {643, "mz", 2},

    // Zambia Republic of
    {645, "zm", 2},

    // Madagascar Republic of
    {646, "mg", 2},

    // Reunion French Department of
    {647, "re", 2},

    // Zimbabwe Republic of
    {648, "zw", 2},

    // Namibia Republic of
    {649, "na", 2},

    // Malawi
    {650, "mw", 2},

    // Lesotho Kingdom of
    {651, "ls", 2},

    // Botswana Republic of
    {652, "bw", 2},

    // Swaziland Kingdom of
    {653, "sz", 2},

    // Comoros Union of the
    {654, "km", 2},

    // South Africa Republic of
    {655, "za", 2},

    // Eritrea
    {657, "er", 2},

    // Saint Helena, Ascension and Tristan da Cunha
    {658, "sh", 2},

    // South Sudan Republic of
    {659, "ss", 2},

    // Belize
    {702, "bz", 2},

    // Guatemala Republic of
    {704, "gt", 2},

    // El Salvador Republic of
    {706, "sv", 2},

    // Honduras Republic of
    {708, "hn", 3},

    // Nicaragua
    {710, "ni", 2},

    // Costa Rica
    {712, "cr", 2},

    // Panama Republic of
    {714, "pa", 2},

    // Peru
    {716, "pe", 2},

    // Argentine Republic
    {722, "ar", 3},

    // Brazil Federative Republic of
    {724, "br", 2},

    // Chile
    {730, "cl", 2},

    // Colombia Republic of
    {732, "co", 3},

    // Venezuela Bolivarian Republic of
    {734, "ve", 2},

    // Bolivia Republic of
    {736, "bo", 2},

    // Guyana
    {738, "gy", 2},

    // Ecuador
    {740, "ec", 2},

    // French Guiana French Department of
    {742, "gf", 2},

    // Paraguay Republic of
    {744, "py", 2},

    // Suriname Republic of
    {746, "sr", 2},

    // Uruguay Eastern Republic of
    {748, "uy", 2},

    // Falkland Islands Malvinas
    {750, "fk", 2}
};
}
}
#endif