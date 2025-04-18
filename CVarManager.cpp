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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

// CVarManager.cpp
#include "./include/CVarManager.h"
// #include <iostream> // No longer needed for cout/cerr logging
#include <sstream>     // Needed for ostringstream formatting
#include <vector>
#include <stdexcept>
#include <psapi.h>     // For GetModuleInformation
#include <map> 

// --- Static Helper function for formatting log messages within CVarManager ---
// Takes the desired prefix (e.g., "[CVarManager INFO] ") and the raw message content.
// Returns the formatted string with newlines moved before the prefix.
// Defined static as it's only intended for use by macros within this file.
static std::string FormatCVarManagerLogMessage(const std::string& prefix, const std::string& raw_content) {
    // Find the first character that is NOT a newline
    size_t first_non_newline = raw_content.find_first_not_of('\n');
    std::string leading_newlines;
    std::string actual_content;

    if (first_non_newline == std::string::npos) {
        // String is all newlines or empty
        leading_newlines = raw_content;
        actual_content = ""; // No actual content
    }
    else {
        // Extract leading newlines
        leading_newlines = raw_content.substr(0, first_non_newline);
        // Extract the rest of the content
        actual_content = raw_content.substr(first_non_newline);
    }

    // Construct the final message: newlines first, then prefix, then content
    return leading_newlines + prefix + actual_content;
}

// --- Helper macros for logging (Refactored) ---
// These now use the m_logCallback if available and the static helper function.
#define LOG_ERROR(msg) \
    do { \
        if (m_logCallback) { \
            std::ostringstream oss_msg_content; \
            oss_msg_content << msg; \
            /* Call static helper function to format */ \
            std::string formatted_msg = FormatCVarManagerLogMessage("[CVarManager ERROR] ", oss_msg_content.str()); \
            /* Pass formatted message to the callback */ \
            m_logCallback(formatted_msg); \
        } \
    } while(0)

#define LOG_WARN(msg) \
    do { \
        if (m_logCallback) { \
            std::ostringstream oss_msg_content; \
            oss_msg_content << msg; \
            /* Call static helper function to format */ \
            std::string formatted_msg = FormatCVarManagerLogMessage("[CVarManager WARN] ", oss_msg_content.str()); \
            /* Pass formatted message to the callback */ \
            m_logCallback(formatted_msg); \
        } \
    } while(0)

#define LOG_INFO(msg) \
    do { \
        if (m_logCallback) { \
            std::ostringstream oss_msg_content; \
            oss_msg_content << msg; \
            /* Call static helper function to format */ \
            std::string formatted_msg = FormatCVarManagerLogMessage("[CVarManager INFO] ", oss_msg_content.str()); \
            /* Pass formatted message to the callback */ \
            m_logCallback(formatted_msg); \
        } \
    } while(0)

#define LOG(msg) \
    do { \
        if (m_logCallback) { \
            std::ostringstream oss_msg_content; \
            oss_msg_content << msg; \
            /* Call static helper function to format */ \
            std::string formatted_msg = FormatCVarManagerLogMessage("", oss_msg_content.str()); \
            /* Pass formatted message to the callback */ \
            m_logCallback(formatted_msg); \
        } \
    } while(0)

// --- SEH Helper Function Definitions ---
// Revised to be MinGW32 compatible - no SEH try/catch blocks

_NODISCARD bool SafeReadPointer(uintptr_t address, void** outValue) {
    if (!outValue) return false;
    if (!address) { *outValue = nullptr; return false; }
    
    // Use IsBadReadPtr as a safer alternative to SEH for MinGW
    if (IsBadReadPtr(reinterpret_cast<const void*>(address), sizeof(void*))) {
        *outValue = nullptr;
        return false;
    }
    
    *outValue = *reinterpret_cast<void**>(address);
    return true;
}

_NODISCARD bool SafeReadUIntPtr(uintptr_t address, uintptr_t* outValue) {
    if (!outValue) return false;
    if (!address) { *outValue = 0; return false; }
    
    // Use IsBadReadPtr as a safer alternative to SEH for MinGW
    if (IsBadReadPtr(reinterpret_cast<const void*>(address), sizeof(uintptr_t))) {
        *outValue = 0;
        return false;
    }
    
    *outValue = *reinterpret_cast<uintptr_t*>(address);
    return true;
}

_NODISCARD bool SafeCallFindCVar(FindCVarFn pFn, void* pMgr, const char* szName, void** outPIcvar) {
    if (!outPIcvar || !pFn || !pMgr || !szName) {
        if (outPIcvar) *outPIcvar = nullptr;
        return false;
    }
    
    // No real way to safely call an arbitrary function without SEH in MinGW
    // We'll just have to call it directly and hope for the best
    *outPIcvar = pFn(pMgr, szName);
    
    // Basic sanity check on the returned pointer
    if (!*outPIcvar || reinterpret_cast<uintptr_t>(*outPIcvar) < 0x10000) {
        *outPIcvar = nullptr;
    }
    
    return true;
}

_NODISCARD bool SafeCallGetStringValue(GetStringValueFn pFn, void* pICVar, const char** outValue) {
    if (!outValue || !pFn || !pICVar) {
        if (outValue) *outValue = nullptr;
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    *outValue = pFn(pICVar);
    return true;
}

_NODISCARD bool SafeCallGetName(GetNameFn pFn, void* pICVar, const char** outValue) {
    if (!outValue || !pFn || !pICVar) {
        if (outValue) *outValue = nullptr;
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    *outValue = pFn(pICVar);
    return true;
}

_NODISCARD bool SafeCallGetFlags(GetFlagsFn pFn, void* pICVar, DWORD* outValue) {
    if (!outValue || !pFn || !pICVar) {
        if (outValue) *outValue = 0;
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    *outValue = pFn(pICVar);
    return true;
}

_NODISCARD bool SafeCallSetStringValue(SetStringValueFn pFn, void* pICVar, const char* szValue) {
    if (!pFn || !pICVar || !szValue) {
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    pFn(pICVar, szValue);
    return true;
}

_NODISCARD bool SafeCallSetFlags(SetFlagsFn pFn, void* pICVar, DWORD flags) {
    if (!pFn || !pICVar) {
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    pFn(pICVar, flags);
    return true;
}

_NODISCARD bool SafeCallEnumCVars(EnumCVarsFn pFn, void* pMgr, const char** pNameListBuffer, QWORD bufferCount, QWORD* outActualCount) {
    if (!outActualCount || !pFn || !pMgr) {
        if (outActualCount) *outActualCount = 0;
        return false;
    }
    
    // Direct call - can't really protect this in MinGW without SEH
    *outActualCount = pFn(pMgr, pNameListBuffer, bufferCount, nullptr);
    return true;
}

// --- CVarManager Implementation ---

// Updated Constructor
CVarManager::CVarManager(const char* moduleName, LogCallbackFn logger)
    : m_moduleName(moduleName), m_logCallback(logger) // Initialize logger callback

{
    m_initialized = initialize(moduleName); // initialize uses logging macros internally now
    if (m_initialized) {
        // Use logging macros (they implicitly use m_logCallback)
        LOG_INFO("CVarManager initialized successfully");
        LOG_INFO("Manager Instance: 0x" << std::hex << reinterpret_cast<uintptr_t>(m_pMgr) << std::dec);
    }
    else {
        LOG_ERROR("CVarManager initialization failed.");
    }
}

bool CVarManager::IsInitialized() const {
    return m_initialized;
}

uintptr_t CVarManager::getModuleBaseAddress(const char* moduleName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        // Log before returning 0
        // Temporary stringstream needed because macro expects a single argument potentially concatenated with <<
        std::ostringstream temp_oss;
        temp_oss << "Failed to get handle for module: " << moduleName << " Error Code: " << GetLastError();
        LOG_ERROR(temp_oss.str());
        return 0;
    }
    return reinterpret_cast<uintptr_t>(hModule);
}

bool CVarManager::isValidCodePointer(uintptr_t ptr) {
    if (ptr == 0 || m_baseAddr == 0) return false;

    // Attempt to get module info for a more precise check
    // Initialize all fields to avoid missing initializer warnings
    MODULEINFO modInfo = { 
        NULL,                // lpBaseOfDll
        0,                   // SizeOfImage
        NULL                 // EntryPoint
    };
    HMODULE hModule = GetModuleHandleA(m_moduleName.c_str()); // Use stored module name
    if (hModule && GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        uintptr_t moduleEnd = m_baseAddr + modInfo.SizeOfImage;
        return (ptr >= m_baseAddr && ptr < moduleEnd);
    }
    else {
        // Fallback: Assume a large, reasonable size if GetModuleInformation fails
        // Log this occurrence as it's not ideal
        // LOG_WARN("GetModuleInformation failed for " << m_moduleName << ". Using fallback pointer validation range."); // Be careful logging within validation
        return (ptr >= m_baseAddr && ptr < m_baseAddr + 0x40000000); // Example large size
    }
}


bool CVarManager::initialize(const char* moduleName) {
    m_baseAddr = getModuleBaseAddress(moduleName); // This now logs errors internally
    if (!m_baseAddr) return false;

    uintptr_t pGlobalPtrAddr = m_baseAddr + G_PCVARMANAGER_OFFSET;
    void* tempMgr = nullptr;
    uintptr_t tempVTable = 0;

    // Use the SafeReadPointer declared in CVarManager.h / defined in CVarManager.cpp
    if (!SafeReadPointer(pGlobalPtrAddr, &tempMgr)) {
        std::ostringstream temp_oss;
        temp_oss << "Access violation reading CVarManager instance pointer address: 0x" << std::hex << pGlobalPtrAddr;
        LOG_ERROR(temp_oss.str());
        return false;
    }
    if (!tempMgr) {
        std::ostringstream temp_oss;
        temp_oss << "CVarManager instance pointer is NULL (at offset 0x" << std::hex << G_PCVARMANAGER_OFFSET << ")";
        LOG_ERROR(temp_oss.str());
        return false;
    }
    m_pMgr = tempMgr; // Store the valid pointer

    if (!SafeReadUIntPtr(reinterpret_cast<uintptr_t>(m_pMgr), &tempVTable)) {
        LOG_ERROR("Access violation reading CVarManager VTable pointer.");
        return false;
    }
    if (!tempVTable) {
        LOG_ERROR("CVarManager VTable pointer is NULL.");
        return false;
    }
    m_pMgrVTable = tempVTable; // Store the valid VTable pointer

    // Optional: Validate VTable pointer (using the improved check)
    if (!isValidCodePointer(m_pMgrVTable)) {
        std::ostringstream temp_oss;
        temp_oss << "CVarManager VTable pointer (0x" << std::hex << m_pMgrVTable << ") seems invalid or outside the module range.";
        LOG_WARN(temp_oss.str());
        // Continue anyway? Or return false? Depends on how critical strict validation is.
        // Let's continue for now but log the warning.
    }

    if (!resolveManagerFunctions()) {
        // resolveManagerFunctions logs specific errors
        return false;
    }

    // If we reached here, initialization is considered successful
    return true;
}


bool CVarManager::resolveManagerFunctions() {
    if (!m_pMgrVTable) return false; // Should not happen if initialize checks passed

    uintptr_t pfnEnumCVarsAddr = 0;
    uintptr_t pfnFindCVarAddr = 0;

    // Resolve EnumCVars (optional)
    if (!SafeReadUIntPtr(m_pMgrVTable + ENUMCVARS_VTABLE_OFFSET, &pfnEnumCVarsAddr)) {
        LOG_ERROR("Access violation resolving EnumCVars function pointer address.");
        m_pfnEnumCVars = nullptr; // Mark as unresolved
    }
    else if (!pfnEnumCVarsAddr) {
        std::ostringstream temp_oss;
        temp_oss << "EnumCVars function pointer is NULL (at VTable offset 0x" << std::hex << ENUMCVARS_VTABLE_OFFSET << ").";
        LOG_WARN(temp_oss.str()); // Downgrade to warning as it might not be essential
        m_pfnEnumCVars = nullptr;
    }
    else if (!isValidCodePointer(pfnEnumCVarsAddr)) { // Check validity
        std::ostringstream temp_oss;
        temp_oss << "EnumCVars function pointer (0x" << std::hex << pfnEnumCVarsAddr << ") seems invalid (at VTable offset 0x" << ENUMCVARS_VTABLE_OFFSET << ").";
        LOG_WARN(temp_oss.str());
        m_pfnEnumCVars = nullptr;
    }
    else {
        m_pfnEnumCVars = reinterpret_cast<EnumCVarsFn>(pfnEnumCVarsAddr);
        LOG_INFO("Resolved EnumCVars: 0x" << std::hex << reinterpret_cast<uintptr_t>(m_pfnEnumCVars) << std::dec);
    }


    // Resolve FindCVar (essential)
    if (!SafeReadUIntPtr(m_pMgrVTable + FINDCVAR_VTABLE_OFFSET, &pfnFindCVarAddr)) {
        LOG_ERROR("Access violation resolving FindCVar function pointer address.");
        return false; // FindCVar is essential
    }
    if (!pfnFindCVarAddr) {
        std::ostringstream temp_oss;
        temp_oss << "FindCVar function pointer is NULL (at VTable offset 0x" << std::hex << FINDCVAR_VTABLE_OFFSET << ").";
        LOG_ERROR(temp_oss.str());
        return false;
    }
    if (!isValidCodePointer(pfnFindCVarAddr)) { // Check validity
        std::ostringstream temp_oss;
        temp_oss << "FindCVar function pointer (0x" << std::hex << pfnFindCVarAddr << ") seems invalid (at VTable offset 0x" << FINDCVAR_VTABLE_OFFSET << ").";
        LOG_ERROR(temp_oss.str());
        return false; // Treat invalid pointer as fatal for FindCVar
    }

    m_pfnFindCVar = reinterpret_cast<FindCVarFn>(pfnFindCVarAddr);
    LOG_INFO("Resolved FindCVar: 0x" << std::hex << reinterpret_cast<uintptr_t>(m_pfnFindCVar) << std::dec);


    // Success requires FindCVar to be resolved. EnumCVars is optional.
    return (m_pfnFindCVar != nullptr);
}


// Internal helper to get the raw ICVar pointer (Uses SafeCallFindCVar)
void* CVarManager::getICVar(const std::string& name) {
    if (!m_initialized || !m_pfnFindCVar || name.empty()) {
        return nullptr; // Don't log here, caller will handle null return
    }

    void* pICVar = nullptr;
    if (!SafeCallFindCVar(m_pfnFindCVar, m_pMgr, name.c_str(), &pICVar)) {
        // Log the exception during the call
        LOG_ERROR("Exception occurred calling FindCVar for \"" << name << "\".");
        return nullptr; // pICVar should be null from SafeCallFindCVar on exception
    }

    // SafeCallFindCVar already nulls pICVar on failure or if result is invalid
    // if (!pICVar) {
    //    LOG_WARN("FindCVar returned null or invalid pointer for \"" << name << "\".");
    // }

    return pICVar;
}

// Internal helper to get a method address (Uses SafeReadUIntPtr)
uintptr_t CVarManager::getICVarMethodAddress(void* pICVar, uintptr_t offset) {
    if (!pICVar) return 0;

    uintptr_t vtable = 0;
    uintptr_t funcAddr = 0;

    // Read VTable pointer from ICVar instance
    if (!SafeReadUIntPtr(reinterpret_cast<uintptr_t>(pICVar), &vtable)) {
        // LOG_WARN("AV reading ICVar VTable address."); // Optional: Could log many times
        return 0;
    }
    if (!vtable) {
        // LOG_WARN("ICVar VTable address is NULL."); // Optional
        return 0;
    }
    // Don't need isValidCodePointer here, it might be outside main module but still valid

    // Read function pointer from VTable + offset
    if (!SafeReadUIntPtr(vtable + offset, &funcAddr)) {
        // LOG_WARN("AV reading ICVar Function address at offset 0x" << std::hex << offset); // Optional
        return 0;
    }
    if (!funcAddr) {
        // LOG_WARN("ICVar Function address is NULL at offset 0x" << std::hex << offset); // Optional
        return 0;
    }
    // Don't need isValidCodePointer here either for the function pointer itself

    return funcAddr;
}


// --- Public Methods (Use Safe Call Helpers, Careful Object Creation) ---

std::pair<std::string, bool> CVarManager::getValue(const std::string& name) {
    void* pICVar = getICVar(name);
    if (!pICVar) return { "", false }; // getICVar already logged failure if exception occurred

    uintptr_t funcAddr = getICVarMethodAddress(pICVar, GETSTRING_VTABLE_OFFSET);
    if (!funcAddr) {
        LOG_ERROR("Failed to resolve GetStringValue function address for \"" << name << "\".");
        return { "", false };
    }

    auto getStringFn = reinterpret_cast<GetStringValueFn>(funcAddr);
    const char* valuePtr = nullptr;

    // Call GetStringValue safely
    if (!SafeCallGetStringValue(getStringFn, pICVar, &valuePtr)) {
        LOG_ERROR("Exception calling GetStringValue for \"" << name << "\".");
        return { "", false }; // valuePtr should be null from SafeCall...
    }

    // Process the result *outside* the SEH block
    if (valuePtr) {
        // Minimal check on the returned pointer before creating std::string
        if (IsBadReadPtr(valuePtr, 1)) { // Check if first byte is readable
            LOG_WARN("GetStringValue for \"" << name << "\" returned potentially invalid pointer: 0x" << std::hex << reinterpret_cast<uintptr_t>(valuePtr) << ". Treating as empty.");
            return { "", true }; // Return success but empty string, as the call itself didn't crash
        }
        try {
            // Create the std::string - this can throw C++ exceptions (e.g., std::length_error)
            return { std::string(valuePtr), true };
        }
        catch (const std::exception& e) {
            LOG_ERROR("Std exception creating std::string from GetStringValue result for \"" << name << "\": " << e.what());
            return { "", false }; // String creation failed
        }
    }
    else {
        // Function call succeeded but returned null (legitimately empty value)
        return { "", true };
    }
}


std::pair<std::string, bool> CVarManager::getName(const std::string& name) {
    void* pICVar = getICVar(name);
    if (!pICVar) return { "", false };

    uintptr_t funcAddr = getICVarMethodAddress(pICVar, GETNAME_VTABLE_OFFSET);
    if (!funcAddr) {
        LOG_ERROR("Failed to resolve GetName function address for ICVar obtained via \"" << name << "\".");
        return { "", false };
    }

    auto getNameFn = reinterpret_cast<GetNameFn>(funcAddr);
    const char* namePtr = nullptr;

    if (!SafeCallGetName(getNameFn, pICVar, &namePtr)) {
        LOG_ERROR("Exception calling GetName for ICVar obtained via \"" << name << "\".");
        return { "", false };
    }

    if (namePtr) {
        if (IsBadReadPtr(namePtr, 1)) {
            LOG_WARN("GetName for ICVar obtained via \"" << name << "\" returned potentially invalid pointer: 0x" << std::hex << reinterpret_cast<uintptr_t>(namePtr) << ". Treating as failure.");
            return { "", false }; // Failure because name should be valid
        }
        try {
            return { std::string(namePtr), true };
        }
        catch (const std::exception& e) {
            LOG_ERROR("Std exception creating std::string from GetName result for ICVar obtained via \"" << name << "\": " << e.what());
            return { "", false };
        }
    }
    else {
        // This is unexpected, GetName should generally return a valid name
        LOG_WARN("GetName returned null for ICVar found via \"" << name << "\".");
        return { "", false }; // Treat null name pointer as failure
    }
}


std::pair<DWORD, bool> CVarManager::getFlags(const std::string& name) {
    void* pICVar = getICVar(name);
    if (!pICVar) return { 0, false };

    uintptr_t funcAddr = getICVarMethodAddress(pICVar, GETFLAGS_VTABLE_OFFSET);
    if (!funcAddr) {
        LOG_ERROR("Failed to resolve GetFlags function address for \"" << name << "\".");
        return { 0, false };
    }

    auto getFlagsFn = reinterpret_cast<GetFlagsFn>(funcAddr);
    DWORD flags = 0;

    if (!SafeCallGetFlags(getFlagsFn, pICVar, &flags)) {
        LOG_ERROR("Exception calling GetFlags for \"" << name << "\".");
        return { 0, false }; // flags should be 0 from SafeCall...
    }

    // Call succeeded
    return { flags, true };
}

std::vector<std::string> CVarManager::getFlagStringsFromBitmask(uint32_t flagsValue) {
    std::vector<std::string> flagStrings;
    uint32_t knownFlagsFound = 0;
    // Static map to hold the enum value -> string representation
    // Using static avoids recreating this map on every call
    static const std::map<CVarFlags, std::string> flagMap = {
        {CVarFlags::VF_NONE, "VF_NONE"},
        {CVarFlags::VF_CHEAT, "VF_CHEAT"},
        {CVarFlags::VF_READONLY, "VF_READONLY"},
        {CVarFlags::VF_REQUIRE_APP_RESTART, "VF_REQUIRE_APP_RESTART"},
        {CVarFlags::VF_NO_HELP, "VF_NO_HELP"},
        {CVarFlags::VF_WHITELIST_FLAG_2, "VF_WHITELIST_FLAG_2"},
        {CVarFlags::VF_WHITELIST_FLAG_1, "VF_WHITELIST_FLAG_1"},
        {CVarFlags::VF_DUMPTODISK, "VF_DUMPTODISK"},
        {CVarFlags::VF_INVISIBLE, "VF_INVISIBLE"},
        {CVarFlags::VF_CONST_CVAR, "VF_CONST_CVAR"},
        {CVarFlags::VF_NODUMP, "VF_NODUMP"},
        {CVarFlags::VF_MODIFIED_BY_CONFIG, "VF_MODIFIED_BY_CONFIG"},
        {CVarFlags::VF_BITFIELD, "VF_BITFIELD"},
        {CVarFlags::VF_CONTEXT_FLAG_1, "VF_CONTEXT_FLAG_1"},
        {CVarFlags::VF_DEPRECATED, "VF_DEPRECATED"},
        {CVarFlags::VF_ALWAYS_NOTIFY, "VF_ALWAYS_NOTIFY"},
        {CVarFlags::VF_BADGECHECK, "VF_BADGECHECK"},
        {CVarFlags::VF_NO_CONFIG_LOAD, "VF_NO_CONFIG_LOAD"},
        {CVarFlags::VF_NET_SYNCED, "VF_NET_SYNCED"}
    };

    // Iterate through the map containing actual flags (non-zero values)
    for (const auto& pair : flagMap) {
        uint32_t currentFlagBit = static_cast<uint32_t>(pair.first);
        // Check if the specific flag bit is set in the input value
        if ((flagsValue & currentFlagBit) != 0) {
            flagStrings.push_back(pair.second); // Add the known flag string
            knownFlagsFound |= currentFlagBit; // Add this bit to our tally of known flags found
        }
    }

    // --- Handling for Unknown Flags ---
    // Calculate the bits that were set in the input but didn't match any known flags
    uint32_t unknownFlags = flagsValue & (~knownFlagsFound);

    if (unknownFlags != 0) {
        // If there are unknown bits, create a string representation for them
        std::ostringstream oss;
        oss << "0x" << std::hex << unknownFlags;
        flagStrings.push_back(oss.str()); // Add this string to the vector
    }

    // --- Special handling for VF_NONE ---
    // If after checking all known flags AND unknown flags, the vector is still empty,
    // it means the original flagsValue must have been exactly 0.
    if (flagStrings.empty() && flagsValue == static_cast<uint32_t>(CVarFlags::VF_NONE)) {
        flagStrings.push_back("VF_NONE");
    }

    // Return the resulting vector of flag names.
    return flagStrings;
}

std::string CVarManager::flagsToString(DWORD flags) {
    // This function doesn't need SEH or logging changes
    std::ostringstream oss;
    bool first = true;
    auto checkFlag = [&](CVarFlags flag, const char* flagName) {
        if ((flags & static_cast<uint32_t>(flag)) != 0) {
            if (!first) oss << " | ";
            oss << flagName;
            first = false;
        }
        };

    checkFlag(CVarFlags::VF_NET_SYNCED, "VF_NET_SYNCED"); // Check high bit first maybe? Order doesn't strictly matter
    checkFlag(CVarFlags::VF_NO_CONFIG_LOAD, "VF_NO_CONFIG_LOAD");
    checkFlag(CVarFlags::VF_BADGECHECK, "VF_BADGECHECK");
    checkFlag(CVarFlags::VF_ALWAYS_NOTIFY, "VF_ALWAYS_NOTIFY");
    checkFlag(CVarFlags::VF_DEPRECATED, "VF_DEPRECATED");
    checkFlag(CVarFlags::VF_CONTEXT_FLAG_1, "VF_CONTEXT_FLAG_1");
    checkFlag(CVarFlags::VF_BITFIELD, "VF_BITFIELD");
    checkFlag(CVarFlags::VF_MODIFIED_BY_CONFIG, "VF_MODIFIED_BY_CONFIG");
    checkFlag(CVarFlags::VF_NODUMP, "VF_NODUMP");
    checkFlag(CVarFlags::VF_CONST_CVAR, "VF_CONST_CVAR");
    checkFlag(CVarFlags::VF_INVISIBLE, "VF_INVISIBLE");
    checkFlag(CVarFlags::VF_DUMPTODISK, "VF_DUMPTODISK");
    checkFlag(CVarFlags::VF_WHITELIST_FLAG_1, "VF_WHITELIST_FLAG_1");
    checkFlag(CVarFlags::VF_NO_HELP, "VF_NO_HELP");
    checkFlag(CVarFlags::VF_REQUIRE_APP_RESTART, "VF_REQUIRE_APP_RESTART");
    checkFlag(CVarFlags::VF_WHITELIST_FLAG_2, "VF_WHITELIST_FLAG_2");
    checkFlag(CVarFlags::VF_READONLY, "VF_READONLY");
    checkFlag(CVarFlags::VF_CHEAT, "VF_CHEAT");
    // Note: VF_NONE (0) won't be printed unless it's the only flag

    if (first && flags == 0) return "VF_NONE";
    if (first && flags != 0) { // Some flags set but none known?
        oss << "[Unknown Flags: 0x" << std::hex << flags << "]";
        return oss.str();
    }
    return oss.str();
}


bool CVarManager::setValue(const std::string& name, const std::string& value) {
    void* pICVar = getICVar(name);
    if (!pICVar) return false; // Can't set if not found

    // Check flags before attempting to set
    auto currentFlagsPair = getFlags(name);
    if (currentFlagsPair.second) { // Flags read successfully
        DWORD currentFlags = currentFlagsPair.first;
        if ((currentFlags & static_cast<uint32_t>(CVarFlags::VF_READONLY)) != 0) {
            LOG_ERROR("Cannot set value for CVar \"" << name << "\": VF_READONLY flag is set.");
            return false; // Fail early
        }
        if ((currentFlags & static_cast<uint32_t>(CVarFlags::VF_CONST_CVAR)) != 0) {
            LOG_ERROR("Cannot set value for CVar \"" << name << "\": VF_CONST_CVAR flag is set.");
            return false; // Fail early
        }
        // Add other checks if necessary (e.g., VF_CHEAT without cheats enabled?)
    }
    else {
        // Flags couldn't be read, proceed with caution
        LOG_WARN("Could not read flags for CVar \"" << name << "\" before setting value. Proceeding anyway.");
    }

    // Get the SetString function address
    uintptr_t funcAddr = getICVarMethodAddress(pICVar, SETSTRING_VTABLE_OFFSET);
    if (!funcAddr) {
        LOG_ERROR("Failed to resolve SetStringValue function address for \"" << name << "\".");
        return false;
    }

    auto setStringFn = reinterpret_cast<SetStringValueFn>(funcAddr);

    // Call SetStringValue safely
    if (!SafeCallSetStringValue(setStringFn, pICVar, value.c_str())) {
        LOG_ERROR("Exception calling SetStringValue for \"" << name << "\".");
        return false; // Call failed
    }

    // If we reach here, the call was made without crashing
    // LOG_INFO("SetStringValue called for \"" << name << "\" = \"" << value << "\""); // Optional success log
    return true;
}

bool CVarManager::setFlags(const std::string& name, DWORD flags) {
    LOG_WARN("setFlags: Modifying CVar flags can be unstable and is generally not recommended!");
    void* pICVar = getICVar(name);
    if (!pICVar) return false;

    uintptr_t funcAddr = getICVarMethodAddress(pICVar, SETFLAGS_VTABLE_OFFSET);
    if (!funcAddr) {
        LOG_ERROR("Failed to resolve SetFlags function address for \"" << name << "\".");
        return false;
    }

    auto setFlagsFn = reinterpret_cast<SetFlagsFn>(funcAddr);

    if (!SafeCallSetFlags(setFlagsFn, pICVar, flags)) {
        LOG_ERROR("Exception calling SetFlags for \"" << name << "\".");
        return false;
    }

    // Log success after the call
    LOG_INFO("SetFlags called for CVar \"" << name << "\" = 0x" << std::hex << flags << " (" << flagsToString(flags) << ")");
    return true;
}


std::pair<std::vector<std::string>, bool> CVarManager::listCVars() {
    if (!m_initialized) {
        LOG_ERROR("\nCannot list CVars: CVarManager not initialized.\n");
        return { {}, false };
    }
    if (!m_pfnEnumCVars) {
        LOG_ERROR("\nCannot list CVars: EnumCVars function pointer is not resolved.\n");
        return { {}, false };
    }

    QWORD cvarCount = 0;
    std::vector<const char*> namePtrBuffer; // For the C pointers
    std::vector<std::string> names;         // For the C++ strings

    // First call: Get the count
    if (!SafeCallEnumCVars(m_pfnEnumCVars, m_pMgr, nullptr, 0, &cvarCount)) {
        LOG_ERROR("\nException during EnumCVars (getting count).\n");
        return { {}, false };
    }
    if (cvarCount == 0) {
        LOG_WARN("\nEnumCVars returned 0 count. No CVars found or enumeration failed silently.\n");
        return { {}, true }; // Return success with empty list
    }
    LOG_INFO("\nEnumCVars reported " << cvarCount << " CVars. Attempting to retrieve names.");

    // Allocate buffer for pointers (can throw std::bad_alloc)
    try {
        namePtrBuffer.resize(static_cast<size_t>(cvarCount), nullptr); // Initialize with nullptrs
    }
    catch (const std::bad_alloc& e) {
        LOG_ERROR("\nFailed to allocate buffer for " << cvarCount << " EnumCVars name pointers: " << e.what() << "\n");
        return { {}, false };
    }

    // Second call: Fill the buffer
    QWORD filledCount = 0; // EnumCVars might return the actual number filled here? (API is unclear)
    if (!SafeCallEnumCVars(m_pfnEnumCVars, m_pMgr, namePtrBuffer.data(), cvarCount, &filledCount)) {
        LOG_ERROR("\nException during EnumCVars (filling buffer).\n");
        // Buffer might be partially filled or corrupted, discard results
        return { {}, false };
    }
    // Optional: Check if filledCount matches cvarCount? Depends on API behavior.
    // if (filledCount != cvarCount) {
    //     LOG_WARN("EnumCVars filled count (" << filledCount << ") differs from initial count (" << cvarCount << ").");
    // }

   // Process the buffer of char pointers into std::strings (can throw C++ exceptions)
    try {
        names.reserve(static_cast<size_t>(cvarCount)); // Reserve space
        int validNames = 0;
        int invalidPtrs = 0;
        for (size_t i = 0; i < namePtrBuffer.size(); ++i) { // Iterate up to the allocated size
            const char* namePtr = namePtrBuffer[i];
            if (namePtr) {
                // Basic pointer check before creating string
                if (IsBadReadPtr(namePtr, 1)) {
                 //   LOG_WARN("Skipping potentially invalid name pointer 0x" << std::hex << reinterpret_cast<uintptr_t>(namePtr) << " at index " << i << " from EnumCVars");
                    invalidPtrs++;
                    continue;
                }
                names.emplace_back(namePtr); // Create string (can throw std::length_error etc.)
                validNames++;
            }
            else {
                // It's possible the game legitimately puts nullptrs in the list?
                // LOG_WARN("Null name pointer encountered at index " << i << " in EnumCVars buffer.");
                invalidPtrs++;
            }
        }
        LOG_INFO("Processed EnumCVars buffer: " << validNames << " valid names, " << invalidPtrs << " null/invalid pointers.");
    }
    catch (const std::exception& e) {
        LOG_ERROR("\nStandard exception while processing EnumCVars results into std::strings: " << e.what() << "\n");
        return { {}, false }; // String creation or vector operation failed
    }

    return { names, true }; // Return the collected names
}


std::pair<CVarDumpResult, bool> CVarManager::dump(bool filterNoDump, bool suppressOutput) {
    CVarDumpResult result; // Create the result struct

    auto namesPair = listCVars(); // This logs errors internally if needed
    if (!namesPair.second) {
        LOG_ERROR("Failed to list CVars, cannot perform dump.\n");
        return { result, false }; // Return empty result with failure flag
    }

    const auto& names = namesPair.first;
    result.totalNamesInput = static_cast<int>(names.size()); // Store total count

    if (names.empty()) {
        LOG_INFO("Dump: No CVars found by listCVars().\n");
        return { result, true }; // Success, but empty dump
    }
    LOG("\n--- Starting CVar Dump ---");

    //LOG_INFO("--- Processing " << names.size() << " CVar names for dump ---"); // Log start

    // Use C++ try/catch for potential exceptions during the loop
    try {
        result.cvars.reserve(names.size()); // Reserve estimate

        // Use result struct members directly for counts
        result.dumpedCount = 0;
        result.skippedNoDump = 0;
        result.errorCount = 0;

        for (const auto& name : names) {
            if (name.empty()) {
               // LOG_WARN("Skipping empty CVar name during dump process.");
                result.errorCount++; // Count empty name as an error
                continue;
            }

            // Get Flags first for filtering
            auto flagsPair = getFlags(name);
            DWORD flags = 0;
            bool flagsOk = false;

            if (!flagsPair.second) {
             //   LOG_WARN("Dump Process: Failed to get flags for \"" << name << "\". Will proceed without flag info.");
                result.errorCount++; // Count flag error
            }
            else {
                flags = flagsPair.first;
                flagsOk = true;
            }

            // Filter based on VF_NODUMP *if* flags were read successfully
            if (flagsOk && filterNoDump && (flags & static_cast<uint32_t>(CVarFlags::VF_NODUMP)) != 0) {
                result.skippedNoDump++;
                continue; // Skip this CVar
            }

            // Get Value
            auto valuePair = getValue(name);
            bool valueOk = false;
            if (!valuePair.second) {
              //  LOG_WARN("Dump Process: Failed to get value for \"" << name << "\". Skipping this CVar.");
                result.errorCount++; // Count value error
              //  continue; // Skip this CVar
            }
            else {
                valueOk = true;
            }

            // If we got here, we have name, value, and potentially flags
            CVarData data;
            data.name = name;
            data.value = valueOk ? valuePair.first : "[Value Read Failed]";
            data.flags = flags; // Store flags (even if read failed, it'll be 0)
            data.flagsString = flagsOk ? flagsToString(flags) : "[Flags Read Failed]"; // Indicate if flags failed
            result.cvars.push_back(data); // Add to the result vector
            result.dumpedCount++;

        } // End for loop

        if (suppressOutput)
        {
            LOG("  CVar output suppressed");
        }
        
        return { result, true }; // Return populated result struct and success flag

    }
    catch (const std::exception& e) {
        // Catch standard C++ exceptions from string/vector ops in the loop
        LOG_ERROR("\nStandard exception during CVar dump processing loop: " << e.what() << "\n");
        return { {}, false }; // Return empty result and failure flag
    }
}