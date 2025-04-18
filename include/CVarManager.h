#pragma once

// Author: Sycorax (https://github.com/TheOneAndOnlySycorax)
// Date: 04/17/2025
// License: MIT

// The MIT License (MIT)
// 
// Copyright (c) 2025 Sycorax
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

// CVarManager.h
#ifndef CVARMANAGER_H
#define CVARMANAGER_H

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <functional> // Include for std::function if preferred, but function pointer is fine


// --- SEH Helper Function Declarations ---
_NODISCARD bool SafeReadPointer(uintptr_t address, void** outValue);
_NODISCARD bool SafeReadUIntPtr(uintptr_t address, uintptr_t* outValue);

using QWORD = uint64_t;


// --- Function Pointer Typedefs (ASSUMPTIONS - Verify these!) ---
// CVarManager VTable Functions
typedef QWORD(__fastcall* EnumCVarsFn)(void* pMgr, const char** pNameListBuffer, QWORD bufferCount, void* pUnknown);
typedef void* (__fastcall* FindCVarFn)(void* pMgr, const char* szName);


// ICVar VTable Functions
typedef const char* (__fastcall* GetNameFn)(void* pICVar);
typedef DWORD(__fastcall* GetFlagsFn)(void* pICVar); // Uses DWORD from windows.h
typedef const char* (__fastcall* GetStringValueFn)(void* pICVar);
typedef void(__fastcall* SetStringValueFn)(void* pICVar, const char* szValue);
typedef void(__fastcall* SetFlagsFn)(void* pICVar, DWORD flags); // Uses DWORD from windows.h

// Enum for CVar Flags (Matches JS version - Add/Remove as needed)
enum class CVarFlags : uint32_t { // Underlying type uint32_t is fine here
    VF_NONE = 0x0,
    VF_CHEAT = 0x2,
    VF_READONLY = 0x8,
    VF_REQUIRE_APP_RESTART = 0x100,
    VF_NO_HELP = 0x200,
    VF_WHITELIST_FLAG_2 = 0x40,
    VF_WHITELIST_FLAG_1 = 0x400,
    VF_DUMPTODISK = 0x1000,
    VF_INVISIBLE = 0x4000,
    VF_CONST_CVAR = 0x8000,
    VF_NODUMP = 0x10000,
    VF_MODIFIED_BY_CONFIG = 0x20000,
    VF_BITFIELD = 0x40000,
    VF_CONTEXT_FLAG_1 = 0x80000,
    VF_DEPRECATED = 0x100000,
    VF_ALWAYS_NOTIFY = 0x200000,
    VF_BADGECHECK = 0x10000000,
    VF_NO_CONFIG_LOAD = 0x40000000,
    VF_NET_SYNCED = 0x80000000
};


// --- Logging Callback Function Type ---
// Takes a constant string reference containing the fully formatted log message.
typedef void (*LogCallbackFn)(const std::string& msg);

// --- SEH Helper Function Declarations ---
// Declare them here so they can be defined in CVarManager.cpp but used elsewhere if needed.
// The _NODISCARD attribute suggests the return value shouldn't be ignored.
_NODISCARD bool SafeReadPointer(uintptr_t address, void** outValue);
_NODISCARD bool SafeReadUIntPtr(uintptr_t address, uintptr_t* outValue);

// Structure to hold CVar data for dumping
struct CVarData {
    std::string name;
    std::string value;
    DWORD flags;
    std::string flagsString;
};

// --- New Struct to hold Dump results and summary ---
struct CVarDumpResult {
    std::vector<CVarData> cvars; // The actual CVar data
    int dumpedCount = 0;
    int skippedNoDump = 0;
    int errorCount = 0;
    int totalNamesInput = 0;   // Total names found by listCVars
};


class CVarManager {
public:
    // --- Configuration (!!! UPDATE THESE OFFSETS FOR YOUR GAME VERSION !!!) ---
    static constexpr uintptr_t G_PCVARMANAGER_OFFSET = 0x981D2B0;
    static constexpr uintptr_t ENUMCVARS_VTABLE_OFFSET = 0x180;
    static constexpr uintptr_t FINDCVAR_VTABLE_OFFSET = 0x48;

    // ICVar VTable Offsets (Relative to ICVar VTable)
    static constexpr uintptr_t GETNAME_VTABLE_OFFSET = 0x70;
    static constexpr uintptr_t GETFLAGS_VTABLE_OFFSET = 0x58;
    static constexpr uintptr_t GETSTRING_VTABLE_OFFSET = 0x28;
    static constexpr uintptr_t SETSTRING_VTABLE_OFFSET = 0x40;
    static constexpr uintptr_t SETFLAGS_VTABLE_OFFSET = 0x60;
    // --- End Configuration ---

    // --- Public Interface ---
    // Constructor now accepts an optional logger callback
    CVarManager(const char* moduleName = "StarCitizen.exe", LogCallbackFn logger = nullptr);
    ~CVarManager() = default;

    // Prevent copying/assignment
    CVarManager(const CVarManager&) = delete;
    CVarManager& operator=(const CVarManager&) = delete;

    bool IsInitialized() const;

    // Methods return std::pair<ValueType, bool> where bool is true if successful
    std::pair<std::string, bool> getValue(const std::string& name);
    std::pair<std::string, bool> getName(const std::string& name);
    std::pair<DWORD, bool> getFlags(const std::string& name);
    std::string flagsToString(DWORD flags);
    std::vector<std::string> getFlagStringsFromBitmask(uint32_t flagsValue);

    bool setValue(const std::string& name, const std::string& value);
    bool setFlags(const std::string& name, DWORD flags);

    std::pair<std::vector<std::string>, bool> listCVars();

    std::pair<CVarDumpResult, bool> dump(bool filterNoDump, bool suppress);

private:
    // --- Internal Helper Methods ---
    bool initialize(const char* moduleName);
    bool resolveManagerFunctions();
    uintptr_t getModuleBaseAddress(const char* moduleName);
    bool isValidCodePointer(uintptr_t ptr);
    void* getICVar(const std::string& name); // Returns raw ICVar pointer or nullptr
    uintptr_t getICVarMethodAddress(void* pICVar, uintptr_t offset); // Gets function ptr address

    // --- Member Variables ---
    std::string m_moduleName;
    uintptr_t m_baseAddr = 0;
    void* m_pMgr = nullptr;
    uintptr_t m_pMgrVTable = 0;
    bool m_initialized = false;
    LogCallbackFn m_logCallback = nullptr; // Store the callback

    // Resolved CVarManager function pointers
    EnumCVarsFn m_pfnEnumCVars = nullptr;
    FindCVarFn m_pfnFindCVar = nullptr;
};

#endif // CVARMANAGER_H