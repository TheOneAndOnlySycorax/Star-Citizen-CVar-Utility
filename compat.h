#pragma once

// Compatibility definitions for MinGW builds

// Define _NODISCARD if not already defined
#ifndef _NODISCARD
  #if defined(__cplusplus) && __cplusplus >= 201703L
    // Use C++17 nodiscard attribute if available
    #define _NODISCARD [[nodiscard]]
  #else
    // Otherwise, just define it as empty (no annotation)
    #define _NODISCARD
  #endif
#endif

// Helper function to convert wide string to utf8 string for file operations
#include <string>
#include <codecvt>
#include <locale>

// Convert a wide (UTF-16) string to a UTF-8 string
// This is useful for file operations when paths are stored as wide strings
inline std::string wstring_to_utf8(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// Convert a UTF-8 string to a wide (UTF-16) string
inline std::wstring utf8_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

