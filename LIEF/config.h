/* Copyright 2017 - 2021 A. Guinet
 * Copyright 2017 - 2022 Quarkslab
 *
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

#ifndef LIEF_CONFIG_H_
#define LIEF_CONFIG_H_

// Main formats
#define LIEF_PE_SUPPORT       1
#define LIEF_ELF_SUPPORT      1
#define LIEF_MACHO_SUPPORT    1

// Android formats
#define LIEF_OAT_SUPPORT      1
#define LIEF_DEX_SUPPORT      1
#define LIEF_VDEX_SUPPORT     1
#define LIEF_ART_SUPPORT      1

// LIEF options
#define LIEF_JSON_SUPPORT     1
#define LIEF_LOGGING_SUPPORT  1
#define LIEF_LOGGING_DEBUG    1
#define LIEF_FROZEN_ENABLED   1
/* #undef LIEF_EXTERNAL_LEAF */
/* #undef LIEF_EXTERNAL_UTF8CPP */
/* #undef LIEF_EXTERNAL_MBEDTLS */
/* #undef LIEF_EXTERNAL_FROZEN */
/* #undef LIEF_EXTERNAL_SPAN */

/* #undef LIEF_NLOHMANN_JSON_EXTERNAL */

#ifdef __cplusplus

static constexpr bool lief_pe_support      = 1;
static constexpr bool lief_elf_support     = 1;
static constexpr bool lief_macho_support   = 1;

static constexpr bool lief_oat_support     = 1;
static constexpr bool lief_dex_support     = 1;
static constexpr bool lief_vdex_support    = 1;
static constexpr bool lief_art_support     = 1;

static constexpr bool lief_json_support    = 1;
static constexpr bool lief_logging_support = 1;
static constexpr bool lief_logging_debug   = 1;
static constexpr bool lief_frozen_enabled  = 1;


#endif // __cplusplus

#endif
