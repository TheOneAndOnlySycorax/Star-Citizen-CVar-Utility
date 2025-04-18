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


#define NOMINMAX // Prevent definition of min/max macros in windows.h conflicting with std::min/max

#include <windows.h>  // Core Windows API functions (handles, console, modules, etc.)
#include <thread>       // For std::thread (MainThread, sleep)
#include <chrono>       // For std::chrono::milliseconds (timing, delays)
#include <memory>       // For std::unique_ptr (g_pCVarManager)
#include <vector>       // For std::vector (ReadLineFromConsole input buffer)
#include <iomanip>      // For std::hex/dec manipulators in ostringstream
#include <utility>      // For std::pair (CVarManager return types)
#include <string>       // For std::string manipulation
#include <limits>       // Potentially for numeric limits
#include <sstream>      // For std::ostringstream, std::istringstream (formatting messages, parsing)
#include <fstream>      // For std::ofstream, std::ifstream (file I/O for dump/load)
#include <cctype>       // For std::tolower, iscntrl (input processing)
#include <algorithm>    // For std::max (cursor positioning)
#include <functional>   // For std::function (though function pointer is used for LogCallbackFn)
#include <commdlg.h>    // For GetSaveFileName, OPENFILENAME, GetOpenFileName, CommDlgExtendedError (file dialogs)
#include "./libs/MinHook.h"     // MinHook library for function hooking
#include "./include/CVarManager.h" // Include the CVarManager class definition
#include "./libs/json.hpp"      // Include the nlohmann/json library for JSON handling 

// --- Using Directives ---
using json = nlohmann::json;           // Alias for convenience when using nlohmann::json
using ordered_json = nlohmann::ordered_json; // Alias for nlohmann::ordered_json (preserves insertion order)

// --- Linker Directives ---
#pragma comment(lib, "./libs/MinHook.x64.lib") // Link against the 64-bit MinHook library
#pragma comment(lib, "comdlg32.lib")    // Link against the common dialog library for file dialogs

// --- Configuration ---
// Define the executable name of the target process for CVar interaction.
constexpr const char* TARGET_MODULE_NAME = "StarCitizen.exe";

// --- Global Variables ---
// Manages interaction with the game's CVar system.
std::unique_ptr<CVarManager> g_pCVarManager = nullptr;
// Handle to the console screen buffer for writing output.
HANDLE g_hConsoleOutput = INVALID_HANDLE_VALUE;
// Handle to this DLL module, used for unloading.
HMODULE g_hModule = nullptr;
// Handle to the console window, used for focus checks and dialog ownership.
HWND g_hConsoleWnd = NULL;

// --- Helper function to format log messages ---
/**
 * @brief Formats a log message by adding a prefix after any leading newlines.
 * Ensures the prefix appears at the start of the actual content, preserving indentation.
 * @param prefix The prefix string to add (e.g., "[DLL INFO] ").
 * @param raw_content The message content.
 * @return The formatted message string.
 */
std::string FormatLogMessage(const std::string& prefix, const std::string& raw_content) {
    size_t first_non_newline = raw_content.find_first_not_of('\n');
    std::string leading_newlines;
    std::string actual_content;
    if (first_non_newline == std::string::npos) {
        leading_newlines = raw_content;
        actual_content = "";
    }
    else {
        leading_newlines = raw_content.substr(0, first_non_newline);
        actual_content = raw_content.substr(first_non_newline);
    }
    return leading_newlines + prefix + actual_content;
}

// Forward declaration for logging macros.
void PrintToConsole(const std::string& message);

// --- DLL Logging Macros ---
// Provides convenient logging with severity levels, checking console handle validity.
// Uses FormatLogMessage to handle prefixes correctly with newlines.

// Logs a fatal error message. Use for critical errors.
#define DLL_LOG_FATAL(msg) \
    do { \
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) { \
            std::ostringstream oss_msg_content; oss_msg_content << msg; \
            std::string formatted_msg = FormatLogMessage("[DLL FATAL] ", oss_msg_content.str()); \
            PrintToConsole(formatted_msg); \
        } \
    } while(0)
// Logs a standard error message. Use for non-fatal errors.
#define DLL_LOG_ERROR(msg) \
    do { \
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) { \
            std::ostringstream oss_msg_content; oss_msg_content << msg; \
            std::string formatted_msg = FormatLogMessage("[DLL ERROR] ", oss_msg_content.str()); \
            PrintToConsole(formatted_msg); \
        } \
    } while(0)
// Logs a warning message. Use for potential issues.
#define DLL_LOG_WARN(msg) \
    do { \
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) { \
            std::ostringstream oss_msg_content; oss_msg_content << msg; \
            std::string formatted_msg = FormatLogMessage("[DLL WARN] ", oss_msg_content.str()); \
            PrintToConsole(formatted_msg); \
        } \
    } while(0)
// Logs an informational message. Use for status updates, general info.
#define DLL_LOG_INFO(msg) \
    do { \
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) { \
            std::ostringstream oss_msg_content; oss_msg_content << msg; \
            std::string formatted_msg = FormatLogMessage("[DLL INFO] ", oss_msg_content.str()); \
            PrintToConsole(formatted_msg); \
        } \
    } while(0)


// --- Helper Function to Print to Our Console ---
/**
 * @brief Writes a string message to the DLL's console output buffer.
 * Appends a newline if the message doesn't already end with one.
 * Checks if the console handle is valid before writing.
 * @param message The string message to print.
 */
void PrintToConsole(const std::string& message) {
    if (g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
        return;
    }
    DWORD charsWritten;
    std::string msgToWrite = message;
    if (message.empty() || message.back() != '\n') {
        msgToWrite += "\n";
    }
    WriteConsoleA(
        g_hConsoleOutput,
        msgToWrite.c_str(),
        static_cast<DWORD>(msgToWrite.length()),
        &charsWritten,
        NULL
    );
}

/**
 * @brief Overload of PrintToConsole to accept an ostringstream directly.
 * @param oss The output string stream containing the message to print.
 */
void PrintToConsole(const std::ostringstream& oss) {
    PrintToConsole(oss.str());
}

/**
 * @brief Writes a prompt string to the console *without* appending a newline.
 * Used for interactive prompts where user input follows on the same line.
 * Checks if the console handle is valid before writing.
 * @param prompt The prompt string to display.
 */
void PrintPromptToConsole(const std::string& prompt) {
    if (g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
        return;
    }
    DWORD charsWritten;
    WriteConsoleA(
        g_hConsoleOutput,
        prompt.c_str(),
        static_cast<DWORD>(prompt.length()),
        &charsWritten,
        NULL
    );
}

#pragma region // Console functions

// --- Helper Function to check if our console window is focused ---
/**
 * @brief Checks if the console window associated with this DLL currently has focus.
 * Requires g_hConsoleWnd to be valid.
 * @return true if the console window is the foreground window, false otherwise.
 */
bool IsConsoleFocused() {
    if (g_hConsoleWnd == NULL) {
        return false;
    }
    HWND hForegroundWnd = GetForegroundWindow();
    return (hForegroundWnd == g_hConsoleWnd);
}

// Forward declaration for unload function.
bool CheckForEndKeyAndUnload();

// --- Helper Function to Check for END key and Initiate Unload ---
/**
 * @brief Checks if the console has focus and if the END key is pressed.
 * If both conditions are true, initiates the DLL cleanup and unload sequence.
 * Cleanup includes resetting CVarManager, uninitializing MinHook, freeing the console,
 * and calling FreeLibraryAndExitThread.
 * @return true if the unload sequence was initiated, false otherwise.
 */
bool CheckForEndKeyAndUnload() {
    // Check focus FIRST
    if (!IsConsoleFocused()) {
        return false;
    }

    // Check if the END key is currently held down (only if console is focused)
    if (GetAsyncKeyState(VK_END) & 0x8000) {
        DLL_LOG_INFO("\n\nEND key detected. Initiating unload...");

        // --- Perform Cleanup ---

        // Reset CVarManager first
        if (g_pCVarManager) {
            g_pCVarManager.reset();
            DLL_LOG_INFO("CVarManager instance released.");
        }
        else {
            DLL_LOG_INFO("CVarManager instance was already null.");
        }

        // Uninitialize MinHook
        MH_STATUS mhStatus = MH_Uninitialize();
        if (mhStatus == MH_OK) {
            DLL_LOG_INFO("MinHook Uninitialized successfully.");
        }
        else {
            DLL_LOG_WARN("MinHook Uninitialization failed: " << MH_StatusToString(mhStatus));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay

        // Release Console
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) {
            DLL_LOG_INFO("Releasing console...");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay
            FreeConsole();
            g_hConsoleOutput = INVALID_HANDLE_VALUE; // Mark handle as invalid
            g_hConsoleWnd = NULL; // Clear console window handle
        }
        else {
            DLL_LOG_INFO("Console handle was already invalid or null.");
        }

        // Unload the DLL and exit this thread
        DLL_LOG_INFO("Exiting thread via FreeLibraryAndExitThread...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay

        if (g_hModule) {
            FreeLibraryAndExitThread(g_hModule, 0);
            // This thread ceases to exist here.
        }
        else {
            DLL_LOG_ERROR("g_hModule handle is null! Cannot call FreeLibraryAndExitThread correctly.");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay
            ExitThread(0); // Fallback
        }
        // ---- Code below this point is effectively unreachable ----
        return true; // Indicate unload was initiated
    }
    return false; // Console focused, but END not pressed
}

/**
 * @brief Reads a single line of text input from the console in a non-blocking, event-driven manner.
 * Processes key presses individually, handles backspace correctly, echoes printable characters,
 * converts the final input to UTF-8, and allows the END key (while focused) to trigger an unload.
 * Ignores Windows auto-repeat by processing only one character per KEY_EVENT.
 * @param hConsoleInput Handle to the console input buffer (e.g., GetStdHandle(STD_INPUT_HANDLE)).
 * @param outString Reference to a string that will receive the UTF-8 encoded input line upon successful read (Enter pressed).
 * @return true if a line was successfully read (Enter pressed), false if an error occurred or if the unload sequence was triggered via the END key.
 */
bool ReadLineFromConsole(HANDLE hConsoleInput, std::string& outString)
{
    outString.clear();
    if (hConsoleInput == INVALID_HANDLE_VALUE || hConsoleInput == NULL) {
        DLL_LOG_ERROR("Invalid console input handle in ReadLineFromConsole.");
        return false;
    }

    DWORD originalMode = 0;
    if (!GetConsoleMode(hConsoleInput, &originalMode)) {
        DLL_LOG_ERROR("GetConsoleMode failed: " << GetLastError());
        return false;
    }

    // Set console mode for event-driven input
    DWORD newMode = originalMode;
    newMode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    newMode |= ENABLE_WINDOW_INPUT;
    newMode |= ENABLE_PROCESSED_INPUT;
    if (!SetConsoleMode(hConsoleInput, newMode)) {
        DLL_LOG_ERROR("SetConsoleMode (event-driven) failed: " << GetLastError());
        SetConsoleMode(hConsoleInput, originalMode); // Attempt restore
        return false;
    }

    std::wstring wAccumulated;
    bool keepReading = true;

    while (keepReading) {
        DWORD numEvents = 0;
        if (!GetNumberOfConsoleInputEvents(hConsoleInput, &numEvents)) {
            DWORD flags;
            if (!GetHandleInformation(hConsoleInput, &flags)) {
                DLL_LOG_WARN("Console input handle appears invalid in ReadLine loop.");
                SetConsoleMode(hConsoleInput, originalMode);
                return false;
            }
            // DLL_LOG_WARN("GetNumberOfConsoleInputEvents failed: " << GetLastError()); // Optional log
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (numEvents == 0) {
            // Check for unload request while idle
            if (CheckForEndKeyAndUnload()) {
                SetConsoleMode(hConsoleInput, originalMode);
                return false; // Indicate unload
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Peek at input events
        std::vector<INPUT_RECORD> inRecords(numEvents);
        DWORD eventsRead = 0;
        if (!PeekConsoleInputW(hConsoleInput, inRecords.data(), numEvents, &eventsRead)) {
            // DLL_LOG_WARN("PeekConsoleInputW failed: " << GetLastError()); // Optional log
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        for (DWORD i = 0; i < eventsRead; i++) {
            const INPUT_RECORD& ir = inRecords[i];

            // Read and remove the event from the buffer
            INPUT_RECORD discard;
            DWORD removed = 0;
            ReadConsoleInputW(hConsoleInput, &discard, 1, &removed);
            if (removed == 0) {
                // DLL_LOG_WARN("ReadConsoleInputW read 0 events after peek."); // Optional log
                continue;
            }

            if (ir.EventType == KEY_EVENT) {
                const KEY_EVENT_RECORD& ker = ir.Event.KeyEvent;

                if (ker.bKeyDown) {
                    // Handle END key for unloading
                    if (ker.wVirtualKeyCode == VK_END) {
                        if (CheckForEndKeyAndUnload()) {
                            SetConsoleMode(hConsoleInput, originalMode);
                            return false; // Indicate unload
                        }
                    }
                    // Handle ENTER key to finalize input
                    else if (ker.wVirtualKeyCode == VK_RETURN) {
                        if (!wAccumulated.empty()) {
                            // Convert accumulated wide string to UTF-8
                            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wAccumulated.data(), static_cast<int>(wAccumulated.size()), nullptr, 0, nullptr, nullptr);
                            if (sizeNeeded > 0) {
                                outString.resize(sizeNeeded);
                                WideCharToMultiByte(CP_UTF8, 0, wAccumulated.data(), static_cast<int>(wAccumulated.size()), &outString[0], sizeNeeded, nullptr, nullptr);
                            }
                            else {
                                DLL_LOG_ERROR("WideCharToMultiByte failed during UTF-8 conversion.");
                                outString.clear();
                            }
                        }
                        PrintToConsole(""); // Echo newline
                        keepReading = false; // Stop reading loop
                        break; // Exit event processing loop
                    }
                    // Handle BACKSPACE key
                    else if (ker.wVirtualKeyCode == VK_BACK) {
                        if (!wAccumulated.empty()) {
                            wAccumulated.pop_back(); // Remove from internal buffer
                            // Erase character visually from console
                            CONSOLE_SCREEN_BUFFER_INFO csbi;
                            if (GetConsoleScreenBufferInfo(g_hConsoleOutput, &csbi)) {
                                if (csbi.dwCursorPosition.X > 0) {
                                    csbi.dwCursorPosition.X -= 1;
                                    SetConsoleCursorPosition(g_hConsoleOutput, csbi.dwCursorPosition);
                                    DWORD written;
                                    WriteConsoleA(g_hConsoleOutput, " ", 1, &written, NULL);
                                    CONSOLE_SCREEN_BUFFER_INFO csbiAfterWrite;
                                    if (GetConsoleScreenBufferInfo(g_hConsoleOutput, &csbiAfterWrite)) {
                                        if (csbiAfterWrite.dwCursorPosition.X > 0) {
                                            csbiAfterWrite.dwCursorPosition.X -= 1;
                                        }
                                        SetConsoleCursorPosition(g_hConsoleOutput, csbiAfterWrite.dwCursorPosition);
                                    }
                                }
                            }
                        }
                    }
                    // Handle printable characters
                    else {
                        WCHAR ch = ker.uChar.UnicodeChar;
                        if (ch != 0 && !iscntrl(static_cast<int>(static_cast<unsigned char>(ch)))) {
                            wAccumulated.push_back(ch); // Add to buffer
                            DWORD written;
                            WriteConsoleW(g_hConsoleOutput, &ch, 1, &written, NULL); // Echo to console
                        }
                    }
                } // End if (ker.bKeyDown)
            } // End if (ir.EventType == KEY_EVENT)

            if (!keepReading) {
                break; // Exit event loop if Enter was pressed
            }
        } // end for (processing peeked events)
    } // end while(keepReading)

    // Restore original console mode
    SetConsoleMode(hConsoleInput, originalMode);

    return true; // Reached here means Enter was pressed successfully
}


/**
 * @brief Moves the console cursor up by a specified number of lines.
 * Checks for valid console handle and non-positive line count.
 * @param lines The number of lines to move the cursor up. Must be positive.
 */
void MoveCursorUp(int lines) {
    if (lines <= 0 || g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
        return;
    }
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hConsoleOutput, &csbi)) {
        csbi.dwCursorPosition.Y = static_cast<SHORT>(
            std::max<LONG>(0L, static_cast<LONG>(csbi.dwCursorPosition.Y) - lines)
            );
        SetConsoleCursorPosition(g_hConsoleOutput, csbi.dwCursorPosition);
    }
}

/**
 * @brief Clears the current line in the console where the cursor is located.
 * Moves the cursor to the beginning of the cleared line.
 * Checks for a valid console handle.
 */
void ClearCurrentConsoleLine() {
    if (g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
        return;
    }
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD written;
    if (GetConsoleScreenBufferInfo(g_hConsoleOutput, &csbi)) {
        COORD lineStart = { 0, csbi.dwCursorPosition.Y };
        FillConsoleOutputCharacterA(
            g_hConsoleOutput,
            ' ',
            csbi.dwSize.X,
            lineStart,
            &written
        );
        SetConsoleCursorPosition(g_hConsoleOutput, lineStart);
    }
}
#pragma endregion // End Console functions


/**
 * @brief Displays the main menu of available hotkeys and actions to the console.
 */
void ShowHotkeyMenu() {
    PrintToConsole("\nStar Citizen CVar Utility v0.1 by Sycorax");
    PrintToConsole("------------------------------------------");
    PrintToConsole("Press F1 to Set a CVar value.");
    PrintToConsole("Press F2 to Get a CVar Value/Flags.");
    PrintToConsole("Press F3 to Dump CVars and save to file.");
    PrintToConsole("Press F4 to Load CVars from JSON file.");
    PrintToConsole("Press F5 to Show This Hotkey Menu.");
    PrintToConsole("Press END to unload DLL."); // Reminder: Requires console focus for unload
    PrintToConsole("------------------------------------------");
}


// --- Interactive Handler Functions ---

/**
 * @brief Handles the F1 key press: Prompts for CVar name and value, attempts to set it.
 * Verifies the change by reading back. Allows cancellation with '/quit'.
 * Checks for unload requests via END key (requires focus).
 */
void HandleSetCVar() {
    if (CheckForEndKeyAndUnload()) { return; }

    if (!g_pCVarManager || !g_pCVarManager->IsInitialized()) {
        DLL_LOG_ERROR("CVarManager not ready.");
        ShowHotkeyMenu();
        return;
    }

    std::string cvarName;
    std::string newValue;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        DLL_LOG_ERROR("Failed to get standard input handle.");
        ShowHotkeyMenu();
        return;
    }

    PrintToConsole("\n--- Set CVar Value ---");

    // --- Get CVar Name ---
    while (true) {
        if (CheckForEndKeyAndUnload()) { return; }

        PrintPromptToConsole("Enter CVar name to set (Type /quit to cancel): ");
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Delay
        if (!ReadLineFromConsole(hStdin, cvarName)) {
            DLL_LOG_ERROR("Failed to read CVar name (Possible unload/error).");
            ShowHotkeyMenu();
            return;
        }
        if (CheckForEndKeyAndUnload()) { return; } // Check again after read

        if (cvarName == "/quit") {
            PrintToConsole("[-] Operation cancelled by user.");
            ShowHotkeyMenu();
            return;
        }
        if (cvarName.empty()) {
            PrintToConsole("[!] CVar name cannot be empty. Please try again or type /quit.\n\n");
            continue;
        }
        break; // Valid name entered
    }

    // --- Check CVar Existence and display current info ---
    auto currentValuePair = g_pCVarManager->getValue(cvarName);
    bool valueReadOk = currentValuePair.second;
    auto flagsPair = g_pCVarManager->getFlags(cvarName);
    bool flagsReadOk = flagsPair.second;

    if (!valueReadOk && !flagsReadOk) {
        DLL_LOG_ERROR("\nCVar '" + cvarName + "' not found or failed to read value and flags.");
        ShowHotkeyMenu();
        return;
    }
    else {
        PrintToConsole("\n'" + cvarName + "': ");
        if (valueReadOk) {
            std::ostringstream oss;
            oss << "   Value: \"" << currentValuePair.first << "\"";
            PrintToConsole(oss.str());
        }
        else {
            PrintToConsole("   Value: [Failed to read]");
            DLL_LOG_WARN("Could not read current value for '" << cvarName << "', but flags for it might still exist. Proceeding...");
        }

        if (flagsReadOk) {
            std::ostringstream oss;
            oss << "   Flags: 0x" << std::hex << flagsPair.first << " (" << g_pCVarManager->flagsToString(flagsPair.first) << ")" << std::dec;
            PrintToConsole(oss.str());
        }
        else {
            PrintToConsole("   Flags: [Failed to read]");
            DLL_LOG_WARN("Could not read current flags for '" << cvarName << "'.");
        }
    }

    // --- Get New Value ---
    while (true) {
        if (CheckForEndKeyAndUnload()) { return; }

        PrintPromptToConsole("\nEnter new value to assign (Type /quit to cancel): ");
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Delay
        if (!ReadLineFromConsole(hStdin, newValue)) {
            DLL_LOG_ERROR("Failed to read new value (Possible unload/error).");
            return; // Exit without showing menu on read failure
        }
        if (CheckForEndKeyAndUnload()) { return; }

        if (newValue == "/quit") {
            PrintToConsole("[-] Operation cancelled by user.");
            ShowHotkeyMenu();
            return;
        }
        break; // Value entered
    }

    // --- Attempt to Set Value ---
    if (g_pCVarManager->setValue(cvarName, newValue)) {
        // Verify the change by reading back
        auto updatedValuePair = g_pCVarManager->getValue(cvarName);
        if (updatedValuePair.second) {
            DLL_LOG_INFO("Successfully set '" << cvarName << "' to \"" << updatedValuePair.first << "\"");
            // Check for discrepancies
            if (updatedValuePair.first != newValue) {
                DLL_LOG_WARN("\nValue discrepancy for '" << cvarName << "': Set='" << newValue << "', Got='" << updatedValuePair.first << "'. The game may have modified or constrained it.");
            }
        }
        else {
            DLL_LOG_ERROR("\nFailed verification read for '" << cvarName << "' after setting value '" << newValue << "'. Read operation may not be supported or assignment failed silently.");
        }
    }
    else {
        DLL_LOG_ERROR("\nsetValue call failed for CVar: '" << cvarName << "' with value: '" << newValue << "'");
    }

    PrintToConsole("----------------------"); // Separator
    ShowHotkeyMenu(); // Show menu after completion or failure
}

/**
 * @brief Handles the F2 key press: Prompts for a CVar name, retrieves and displays its value and flags.
 * Allows cancellation with '/quit'. Checks for unload requests via END key (requires focus).
 */
void HandleGetCVar() {
    if (CheckForEndKeyAndUnload()) { return; }

    if (!g_pCVarManager || !g_pCVarManager->IsInitialized()) {
        DLL_LOG_ERROR("CVarManager not ready.");
        return; // Exit if manager not ready
    }

    std::string cvarName;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        DLL_LOG_ERROR("Failed to get standard input handle.");
        return; // Exit if cannot get input handle
    }

    PrintToConsole("\n--- Get CVar Value/Flags ---");

    // --- Get CVar Name ---
    while (true) {
        if (CheckForEndKeyAndUnload()) { return; }

        PrintPromptToConsole("Enter CVar name to get (Type /quit to cancel): ");
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Delay
        if (!ReadLineFromConsole(hStdin, cvarName)) {
            DLL_LOG_ERROR("Failed to read CVar name (Possible unload/error).");
            ShowHotkeyMenu();
            return;
        }
        if (CheckForEndKeyAndUnload()) { return; }

        if (cvarName == "/quit") {
            PrintToConsole("[-] Operation cancelled by user.");
            ShowHotkeyMenu();
            return;
        }
        if (cvarName.empty()) {
            PrintToConsole("[!] CVar name input cannot be empty. Please try again or type /quit\n\n");
            continue;
        }
        break; // Valid name entered
    }

    // --- Retrieve and Display CVar Info ---
    auto valuePair = g_pCVarManager->getValue(cvarName);
    auto flagsPair = g_pCVarManager->getFlags(cvarName);
    bool valueReadSuccess = valuePair.second;
    bool flagsReadSuccess = flagsPair.second;

    if (!valueReadSuccess && !flagsReadSuccess) {
        DLL_LOG_ERROR("\nCVar '" + cvarName + "' not found or failed to read value and flags.");
    }
    else {
        PrintToConsole("\n'" + cvarName + "': ");
        if (valueReadSuccess) {
            PrintToConsole("   Value: \"" + valuePair.first + "\"");
        }
        else {
            PrintToConsole("   Value: [Failed to read]");
        }
        if (flagsReadSuccess) {
            std::ostringstream oss_flags;
            oss_flags << "   Flags: 0x" << std::hex << flagsPair.first << " (" << g_pCVarManager->flagsToString(flagsPair.first) << ")" << std::dec;
            PrintToConsole(oss_flags.str());
        }
        else {
            PrintToConsole("   Flags: [Failed to read]");
        }
    }

    PrintToConsole("----------------------------"); // Separator
    ShowHotkeyMenu();
}

// --- UTF-8 Sanitization Helper ---
/**
 * @brief Sanitizes a string to ensure it contains valid UTF-8 sequences.
 * Replaces invalid byte sequences with the Unicode Replacement Character (U+FFFD),
 * represented as "\xEF\xBF\xBD" in UTF-8. Handles overlong encodings and disallowed code points.
 * @param input The input string potentially containing invalid UTF-8.
 * @return A string with invalid sequences replaced by U+FFFD.
 */
std::string sanitize_utf8(const std::string& input) {
    std::string output;
    output.reserve(input.length());

    const char* ptr = input.c_str();
    const char* end = ptr + input.length();

    while (ptr < end) {
        unsigned char byte1 = static_cast<unsigned char>(*ptr);
        size_t remaining = end - ptr;

        if (byte1 <= 0x7F) {
            // 1-byte sequence (ASCII)
            output += static_cast<char>(byte1);
            ptr += 1;
        }
        else if (byte1 >= 0xC2 && byte1 <= 0xDF) {
            // 2-byte sequence start
            if (remaining >= 2) {
                unsigned char byte2 = static_cast<unsigned char>(*(ptr + 1));
                if (byte2 >= 0x80 && byte2 <= 0xBF) { // Valid continuation byte
                    output += static_cast<char>(byte1);
                    output += static_cast<char>(byte2);
                    ptr += 2;
                }
                else { // Invalid continuation byte
                    output += "\xEF\xBF\xBD"; // Replacement Character
                    ptr += 1; // Consume only start byte
                }
            }
            else { // Incomplete sequence
                output += "\xEF\xBF\xBD";
                ptr += 1;
            }
        }
        else if (byte1 >= 0xE0 && byte1 <= 0xEF) {
            // 3-byte sequence start
            if (remaining >= 3) {
                unsigned char byte2 = static_cast<unsigned char>(*(ptr + 1));
                unsigned char byte3 = static_cast<unsigned char>(*(ptr + 2));
                bool valid_sequence = false;

                if (byte2 >= 0x80 && byte2 <= 0xBF && byte3 >= 0x80 && byte3 <= 0xBF) { // Valid continuation bytes
                    // Check for specific invalid cases (overlong, surrogates)
                    if (byte1 == 0xE0 && byte2 < 0xA0) valid_sequence = false; // Overlong
                    else if (byte1 == 0xED && byte2 >= 0xA0) valid_sequence = false; // Surrogate
                    else valid_sequence = true;
                }

                if (valid_sequence) {
                    output += static_cast<char>(byte1);
                    output += static_cast<char>(byte2);
                    output += static_cast<char>(byte3);
                    ptr += 3;
                }
                else { // Invalid sequence
                    output += "\xEF\xBF\xBD";
                    ptr += 1; // Consume only start byte
                }
            }
            else { // Incomplete sequence
                output += "\xEF\xBF\xBD";
                ptr += 1;
            }
        }
        else if (byte1 >= 0xF0 && byte1 <= 0xF4) {
            // 4-byte sequence start
            if (remaining >= 4) {
                unsigned char byte2 = static_cast<unsigned char>(*(ptr + 1));
                unsigned char byte3 = static_cast<unsigned char>(*(ptr + 2));
                unsigned char byte4 = static_cast<unsigned char>(*(ptr + 3));
                bool valid_sequence = false;

                if (byte2 >= 0x80 && byte2 <= 0xBF && byte3 >= 0x80 && byte3 <= 0xBF && byte4 >= 0x80 && byte4 <= 0xBF) { // Valid continuation bytes
                    // Check for specific invalid cases (overlong, > U+10FFFF)
                    if (byte1 == 0xF0 && byte2 < 0x90) valid_sequence = false; // Overlong
                    else if (byte1 == 0xF4 && byte2 > 0x8F) valid_sequence = false; // > U+10FFFF
                    else valid_sequence = true;
                }

                if (valid_sequence) {
                    output += static_cast<char>(byte1);
                    output += static_cast<char>(byte2);
                    output += static_cast<char>(byte3);
                    output += static_cast<char>(byte4);
                    ptr += 4;
                }
                else { // Invalid sequence
                    output += "\xEF\xBF\xBD";
                    ptr += 1; // Consume only start byte
                }
            }
            else { // Incomplete sequence
                output += "\xEF\xBF\xBD";
                ptr += 1;
            }
        }
        else { // Invalid starting byte or continuation byte
            output += "\xEF\xBF\xBD";
            ptr += 1;
        }
    }
    return output;
}

// --- Main Dump Function ---
/**
 * @brief Handles the F3 key press: Dumps CVars using CVarManager::dump.
 * Prompts user whether to skip VF_NODUMP CVars and suppress console output.
 * Optionally prompts user to save results to a Text or JSON file via save dialog.
 * Sanitizes strings for JSON output. Checks for unload requests (requires focus).
 */
void HandleDumpCVars() {
    if (CheckForEndKeyAndUnload()) {
        return;
    }

    if (!g_pCVarManager || !g_pCVarManager->IsInitialized()) {
        DLL_LOG_ERROR("CVarManager not ready.");
        return;
    }

    // --- Configuration Variables ---
    bool skip_cvars = true;
    bool suppress_output = false;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    std::string response;
    bool readOk;

    // --- Prompt for skipping VF_NODUMP ---
    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        DLL_LOG_ERROR("\nFailed to get standard input handle for skip CVar prompt. CVars with VF_NODUMP flag will be ignored in dump.\n");
        skip_cvars = true; // Use default
    }
    else {
        PrintToConsole("\n--- Dump CVars ---");
        while (true) { // Loop for valid input
            if (CheckForEndKeyAndUnload()) { return; }

            PrintPromptToConsole("Ignore CVars with VF_NODUMP flag? (Y=Yes, N=No, Q=Quit, Default: Y): ");
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Delay

            readOk = ReadLineFromConsole(hStdin, response);
            if (!readOk) {
                DLL_LOG_ERROR("\nFailed to read response (Possible unload/error).");
                ShowHotkeyMenu();
                return;
            }

            if (response.empty()) { // Default: Yes
                skip_cvars = true;
                PrintToConsole("[-] Ignoring CVars with VF_NODUMP flag.\n");
                break;
            }
            else {
                char choice = std::tolower(static_cast<unsigned char>(response[0]));
                if (choice == 'q') { // Quit
                    PrintToConsole("[-] Operation cancelled.");
                    ShowHotkeyMenu();
                    return;
                }
                else if (choice == 'n') { // No
                    skip_cvars = false;
                    PrintToConsole("[-] Including CVars with VF_NODUMP flag.\n");
                    break;
                }
                else if (choice == 'y') { // Yes
                    skip_cvars = true;
                    PrintToConsole("[-] Ignoring CVars with VF_NODUMP flag.\n");
                    break;
                }
                else { // Invalid
                    PrintToConsole("[!] Invalid choice.\n\n");
                }
            }
        }
    }

    // --- Prompt for suppressing console output ---
    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        DLL_LOG_ERROR("\nFailed to get standard input handle for suppress output prompt. CVars will not be suppressed in console output.\n");
        suppress_output = false; // Use default
    }
    else {
        while (true) { // Loop for valid input
            if (CheckForEndKeyAndUnload()) { return; }

            PrintPromptToConsole("\nSuppress CVar output to console? (Y=Yes, N=No, Q=Quit, Default: N): ");
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Delay

            readOk = ReadLineFromConsole(hStdin, response);
            if (!readOk) {
                DLL_LOG_ERROR("\nFailed to read response (Possible unload/error).");
                ShowHotkeyMenu();
                return;
            }

            if (response.empty()) { // Default: No
                suppress_output = false;
                PrintToConsole("[-] CVar Output will not be suppressed.\n");
                break;
            }
            else {
                char choice = std::tolower(static_cast<unsigned char>(response[0]));
                if (choice == 'q') { // Quit
                    PrintToConsole("[-] Operation cancelled.");
                    ShowHotkeyMenu();
                    return;
                }
                else if (choice == 'y') { // Yes
                    suppress_output = true;
                    PrintToConsole("[-] CVar Output WILL be suppressed.\n");
                    break;
                }
                else if (choice == 'n') { // No
                    suppress_output = false;
                    PrintToConsole("[-] CVar Output will not be suppressed.\n");
                    break;
                }
                else { // Invalid
                    PrintToConsole("[!] Invalid choice.");
                }
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000)); // Delay before dump

    // --- Perform the dump ---
    PrintToConsole("\n[*] Starting CVar dump process...");
    auto dumpPair = g_pCVarManager->dump(skip_cvars, suppress_output);
    if (!dumpPair.second) { // Check dump operation status
        DLL_LOG_ERROR("Failed to perform CVar dump processing.");
        ShowHotkeyMenu();
        return;
    }

    const CVarDumpResult& dumpResult = dumpPair.first;
    const auto& cvarDump = dumpResult.cvars; // Reference dump results

    // --- Console Output ---
    if (cvarDump.empty()) {
        PrintToConsole("No CVars found or returned matching the criteria (check logs for details).");
    }
    else {
        if (!suppress_output) { // Print if not suppressed
            for (const auto& cvarData : cvarDump) {
                if (CheckForEndKeyAndUnload()) { return; } // Check during loop

                std::ostringstream oss;
                std::string flagsStr = "N/A";
                if (g_pCVarManager) {
                    flagsStr = g_pCVarManager->flagsToString(cvarData.flags);
                }
                oss << cvarData.name << " = \"" << cvarData.value << "\" [Flags: 0x"
                    << std::hex << cvarData.flags << " (" << flagsStr << ")]" << std::dec;
                PrintToConsole(oss.str());
                std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Tiny delay
            }
        }
    }
    PrintToConsole("--- Finished CVar Dump ---\n");

    if (CheckForEndKeyAndUnload()) { return; } // Check after dump

    // --- Print Dump Summary ---
    PrintToConsole("\n------ CVar Dump Summary ------");
    DLL_LOG_INFO("Total Names Found by EnumCVars: " + std::to_string(dumpResult.totalNamesInput));
    DLL_LOG_INFO("CVars Matching Criteria: " + std::to_string(dumpResult.dumpedCount));
    if (skip_cvars) {
        DLL_LOG_INFO("CVars Skipped (VF_NODUMP): " + std::to_string(dumpResult.skippedNoDump));
    }
    DLL_LOG_INFO("Errors Encountered: " + std::to_string(dumpResult.errorCount));
    PrintToConsole("-------------------------------");

    // --- Prompt for Saving File ---
    bool saveToFile = false;
    bool saveAsJson = false;

    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        DLL_LOG_WARN("Failed to get standard input handle for save prompt. Cannot ask to save.");
    }
    else {
        if (!cvarDump.empty()) { // Only ask if there's data
            // Ask *if* user wants to save
            while (true) {
                if (CheckForEndKeyAndUnload()) { return; }
                PrintPromptToConsole("\nSave dump to file? (Y=Yes, N=No, Q=Quit, Default: N): ");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                readOk = ReadLineFromConsole(hStdin, response);
                if (!readOk) {
                    DLL_LOG_ERROR("\nFailed to read response (Possible unload/error). Not saving.");
                    saveToFile = false;
                    break;
                }

                if (response.empty()) { // Default: No
                    saveToFile = false;
                    PrintToConsole("[-] Dump will not be saved to a file.");
                    break;
                }
                else {
                    char choice = std::tolower(static_cast<unsigned char>(response[0]));
                    if (choice == 'q') { // Quit
                        PrintToConsole("[-] Save operation cancelled.");
                        saveToFile = false;
                        break;
                    }
                    else if (choice == 'y') { // Yes
                        saveToFile = true;
                        break; // Proceed to format prompt
                    }
                    else if (choice == 'n') { // No
                        saveToFile = false;
                        PrintToConsole("[-] Dump will not be saved to a file.");
                        break;
                    }
                    else { // Invalid
                        PrintToConsole("[!] Invalid choice.");
                    }
                }
            }

            // Ask for format if saving
            if (saveToFile) {
                while (true) {
                    if (CheckForEndKeyAndUnload()) { return; }
                    PrintPromptToConsole("\nSave as JSON (J) or Text (T)? (Q=Quit, Default: T): ");
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    readOk = ReadLineFromConsole(hStdin, response);
                    if (!readOk) {
                        DLL_LOG_ERROR("\nFailed to read format response (Possible unload/error). Not saving.");
                        saveToFile = false; // Cancel save
                        break;
                    }

                    if (response.empty()) { // Default: Text
                        saveAsJson = false;
                        PrintToConsole("[-] Saving as Text format.\n");
                        break;
                    }
                    else {
                        char choice = std::tolower(static_cast<unsigned char>(response[0]));
                        if (choice == 'q') { // Quit
                            PrintToConsole("[-] Save operation cancelled.");
                            saveToFile = false; // Cancel save
                            break;
                        }
                        else if (choice == 'j') { // JSON
                            saveAsJson = true;
                            PrintToConsole("[-] Saving as JSON format.\n");
                            break;
                        }
                        else if (choice == 't') { // Text
                            saveAsJson = false;
                            PrintToConsole("[-] Saving as Text format.\n");
                            break;
                        }
                        else { // Invalid
                            PrintToConsole("[!] Invalid choice.");
                        }
                    }
                }
            }
        }
        else { // Dump was empty
            PrintToConsole("[-] No CVars were dumped, nothing to save.");
        }
    }

    // --- Save to File Logic ---
    if (saveToFile && !cvarDump.empty()) {
        wchar_t szFilePath[MAX_PATH] = { 0 };
        OPENFILENAMEW ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hConsoleWnd;

        LPCWSTR filter = saveAsJson ? L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0" : L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
        LPCWSTR defExt = saveAsJson ? L"json" : L"txt";

        ofn.lpstrFile = szFilePath;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrFilter = filter;
        ofn.nFilterIndex = 1;
        ofn.lpstrTitle = L"Save CVar Dump As";
        ofn.lpstrDefExt = defExt;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

        if (CheckForEndKeyAndUnload()) { return; } // Check before dialog

        // Show Save File Dialog
        if (GetSaveFileNameW(&ofn)) { // User clicked OK
            if (CheckForEndKeyAndUnload()) { return; } // Check after dialog

            char mbFilePath[MAX_PATH] = { 0 }; // For logging path
            WideCharToMultiByte(CP_ACP, 0, ofn.lpstrFile, -1, mbFilePath, MAX_PATH, NULL, NULL);
            DLL_LOG_INFO("\nUser selected path: " + std::string(mbFilePath));
            DLL_LOG_INFO("Attempting to save as " + std::string(saveAsJson ? "JSON" : "Text") + "...");

            bool saveSuccessful = false;
            std::ofstream outFile(ofn.lpstrFile); // Open file using wide path

            if (outFile.is_open()) {
                if (saveAsJson) {
                    // --- JSON Saving ---
                    ordered_json j_array = ordered_json::array();
                    try {
                        for (const auto& cvarData : cvarDump) {
                            ordered_json j_cvar;
                            j_cvar["cVarName"] = sanitize_utf8(cvarData.name); // Sanitize strings
                            j_cvar["value"] = sanitize_utf8(cvarData.value);   // Sanitize strings
                            j_cvar["flags"] = g_pCVarManager->getFlagStringsFromBitmask(cvarData.flags);
                            j_array.push_back(j_cvar);
                        }
                        // If loop succeeded, dump JSON to file
                        DLL_LOG_INFO("Dumping JSON Data to file...");
                        outFile << j_array.dump(2); // Pretty print with 2 spaces
                        saveSuccessful = true;
                    }
                    catch (const json::exception& e) {
                        DLL_LOG_ERROR("JSON Exception during object creation or dump: " + std::string(e.what()));
                        saveSuccessful = false;
                        // Goto removed, flow continues to close/report
                    }
                    catch (const std::exception& e) {
                        DLL_LOG_ERROR("Standard Exception during JSON creation or dump: " + std::string(e.what()));
                        saveSuccessful = false;
                    }
                    catch (...) {
                        DLL_LOG_ERROR("Unknown exception during JSON creation or dump.");
                        saveSuccessful = false;
                    }
                    // Label used by goto removed as goto was removed.
                    // cleanup_and_report: // Removed label

                }
                else { // Text Saving
                    // --- Text Saving Logic ---
                    try {
                        // Write summary header
                        outFile << "------ CVar Dump Summary ------\n";
                        outFile << "Total Names Found by EnumCVars: " << dumpResult.totalNamesInput << "\n";
                        if (skip_cvars) {
                            outFile << "CVars Skipped (VF_NODUMP): " << dumpResult.skippedNoDump << "\n";
                        }
                        outFile << "Errors Encountered: " << dumpResult.errorCount << "\n";
                        outFile << "CVars Written: " << dumpResult.dumpedCount << "\n";
                        outFile << "-------------------------------\n\n";

                        // Write each CVar line
                        for (const auto& cvarData : cvarDump) {
                            std::string flagsStr = "N/A";
                            if (g_pCVarManager) {
                                flagsStr = g_pCVarManager->flagsToString(cvarData.flags);
                            }
                            outFile << cvarData.name << " = \"" << cvarData.value << "\" [Flags: 0x"
                                << std::hex << cvarData.flags << " (" << flagsStr
                                << ")]" << std::dec << "\n";
                        }
                        saveSuccessful = true;
                    }
                    catch (const std::exception& e) {
                        DLL_LOG_ERROR("Exception during Text file writing: " + std::string(e.what()));
                        saveSuccessful = false;
                    }
                    catch (...) {
                        DLL_LOG_ERROR("Unknown exception during Text file writing.");
                        saveSuccessful = false;
                    }
                } // End if/else (JSON vs Text)

                outFile.close(); // Close file stream

                // Report final status
                if (saveSuccessful) {
                    PrintToConsole("[+] CVar Dump successfully saved.");
                }
                else {
                    PrintToConsole("[-] CVar Dump saving failed. Check logs for details.");
                    // Optional: Attempt to delete failed file
                }
            }
            else { // Failed to open file
                DLL_LOG_ERROR("Failed to open selected file for writing: " + std::string(mbFilePath));
            }
        }
        else { // User cancelled Save Dialog or error occurred
            if (CheckForEndKeyAndUnload()) { return; } // Check after dialog
            DWORD dialogError = CommDlgExtendedError();
            if (dialogError == 0) { // User cancelled
                PrintToConsole("[-] File save cancelled by user.");
            }
            else { // Dialog error
                DLL_LOG_ERROR("GetSaveFileName failed. CommDlgExtendedError code: " + std::to_string(dialogError));
            }
        }
    }
    else if (saveToFile && cvarDump.empty()) { // User chose save, but dump was empty
        PrintToConsole("[-] No CVars to save.");
    }

    if (CheckForEndKeyAndUnload()) { return; } // Final check
    ShowHotkeyMenu(); // Show menu again
}

/**
 * @brief Prints an example of the expected JSON format for loading CVars to the console.
 */
void PrintJsonFormatExample() {
    PrintToConsole("\nExpected JSON Format:");
    PrintToConsole("   The JSON file should contain an array of objects.");
    PrintToConsole("   Each object MUST have a 'cVarName' (string) and 'value' (string).");
    PrintToConsole("   The 'flags' key array is optional and is currently ignored.");
    PrintToConsole("\n   Example:");
    PrintToConsole(R"(      [
        {
          "cVarName": "p_rigid_gforce_scale",
          "value": "0.5",
          "flags": ["VF_NONE"]
        },
        {
          "cVarName": "p_fly_mode",
          "value": "0"
        },
        {
          "cVarName": "v_qdrive.instant_qt",
          "value": "1",
          "flags": []
        }
      ])");
    // PrintToConsole("------------------------------------"); // Separator not present in code
}

/**
 * @brief Handles the F4 key press: Loads CVar settings from a user-selected JSON file.
 * Displays format example, prompts for confirmation, shows open file dialog.
 * Parses JSON, validates structure, and attempts to set each CVar via CVarManager.
 * Reports a summary. Checks for unload requests (requires focus).
 */
void HandleLoadCVarsFromJson() {
    if (CheckForEndKeyAndUnload()) { return; }

    if (!g_pCVarManager || !g_pCVarManager->IsInitialized()) {
        DLL_LOG_ERROR("CVarManager not ready.");
        ShowHotkeyMenu();
        return;
    }

    PrintToConsole("\n--- Load CVars from JSON File ---");

    // Show format and ask to continue
    PrintJsonFormatExample();
    PrintPromptToConsole("\nPress Enter to continue and open file dialog, or type /quit to cancel: ");

    // Handle confirmation/cancellation
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    std::string response;
    if (hStdin != INVALID_HANDLE_VALUE && hStdin != NULL) {
        bool readOk = ReadLineFromConsole(hStdin, response);
        if (!readOk || response == "/quit") { // Check read status and /quit command
            PrintToConsole("[-] Operation cancelled.");
            ShowHotkeyMenu();
            return;
        }
        // Proceed if Enter pressed or other input given
    }
    else {
        DLL_LOG_WARN("Could not get input handle to confirm proceeding.");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Delay
    }

    // --- Step 1: Open File Dialog ---
    wchar_t szFilePath[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hConsoleWnd; // Use console window handle
    ofn.lpstrFile = szFilePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = L"Select CVar JSON File";
    ofn.lpstrDefExt = L"json";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    // DLL_LOG_INFO("Opening file dialog..."); // Optional log

    if (!GetOpenFileNameW(&ofn)) { // User cancelled or dialog error
        if (CheckForEndKeyAndUnload()) { return; } // Check after dialog
        DWORD dialogError = CommDlgExtendedError();
        if (dialogError == 0) {
            PrintToConsole("[-] File selection cancelled by user.");
        }
        else {
            DLL_LOG_ERROR("GetOpenFileName failed. CommDlgExtendedError code: " << dialogError);
        }
        ShowHotkeyMenu();
        return;
    }

    // --- Step 2: Read File Content ---
    if (CheckForEndKeyAndUnload()) { return; } // Check after dialog success
    std::wstring wFilePath = szFilePath;
    char mbFilePath[MAX_PATH] = { 0 }; // For logging
    WideCharToMultiByte(CP_UTF8, 0, wFilePath.c_str(), -1, mbFilePath, MAX_PATH, NULL, NULL);
    DLL_LOG_INFO("User selected file: " << mbFilePath);

     std::ifstream jsonFile(wstring_to_utf8(wFilePath)); // Convert from wide path to UTF-8
    if (!jsonFile.is_open()) {
        DLL_LOG_ERROR("Failed to open file: " << mbFilePath);
        ShowHotkeyMenu();
        return;
    }

    // --- Step 3: Parse JSON ---
    json jsonData;
    try {
        DLL_LOG_INFO("\nParsing JSON file...");
        jsonData = json::parse(jsonFile); // Parse file stream
        jsonFile.close(); // Close after parsing
    }
    catch (json::parse_error& e) { // Handle JSON parsing errors
        DLL_LOG_ERROR("JSON parsing error: " << e.what() << " at byte " << e.byte);
        PrintToConsole("[!] Please ensure the file matches the expected format:");
        PrintJsonFormatExample();
        jsonFile.close();
        ShowHotkeyMenu();
        return;
    }
    catch (const std::exception& e) { // Handle other exceptions
        DLL_LOG_ERROR("Error reading/parsing JSON file: " << e.what());
        jsonFile.close();
        ShowHotkeyMenu();
        return;
    }
    catch (...) { // Handle unknown exceptions
        DLL_LOG_ERROR("Unknown error during JSON parsing.");
        jsonFile.close();
        ShowHotkeyMenu();
        return;
    }

    // --- Step 4: Validate JSON structure ---
    if (!jsonData.is_array()) { // Root must be an array
        DLL_LOG_ERROR("JSON parsing failed: Root element is not an array.");
        PrintToConsole("[!] The root element must be an array `[...]`.");
        PrintJsonFormatExample();
        ShowHotkeyMenu();
        return;
    }

    // --- Step 5: Process Each CVar Entry ---
    DLL_LOG_INFO("Processing " << jsonData.size() << " entries from JSON...\n");
    int successCount = 0;
    int failureCount = 0;
    int skippedCount = 0;

    for (const auto& item : jsonData) { // Iterate through array elements
        if (CheckForEndKeyAndUnload()) { return; } // Check during loop

        if (!item.is_object()) { // Skip non-object entries
            DLL_LOG_WARN("\nSkipping non-object entry in JSON array.");
            skippedCount++;
            continue;
        }

        // Validate required keys and types ("cVarName": string, "value": string)
        if (!item.contains("cVarName") || !item["cVarName"].is_string() ||
            !item.contains("value") || !item["value"].is_string())
        {
            std::string entryName = "[Unknown/Invalid]"; // Try to get name for logging
            if (item.contains("cVarName") && item["cVarName"].is_string()) {
                entryName = item["cVarName"].get<std::string>();
            }
            else if (item.contains("cVarName")) {
                entryName = "[Invalid Type: " + std::string(item["cVarName"].type_name()) + "]";
            }
            DLL_LOG_WARN("\nSkipping entry '" << entryName << "' due to missing/invalid 'cVarName' or 'value' (must be strings).");
            // DLL_LOG_WARN("Offending item data: " << item.dump()); // Optional log
            skippedCount++;
            continue;
        }

        std::string cvarName = item["cVarName"].get<std::string>();
        std::string value = item["value"].get<std::string>();

        if (cvarName.empty()) { // Skip entries with empty names
            DLL_LOG_WARN("\nSkipping entry with empty 'cVarName'.");
            skippedCount++;
            continue;
        }

        // Attempt to set the CVar
        DLL_LOG_INFO("\nAttempting to set '" << cvarName << "' = \"" << value << "\"");
        if (g_pCVarManager->setValue(cvarName, value)) {
            // Optional verification read
            auto verifyPair = g_pCVarManager->getValue(cvarName);
            if (verifyPair.second) { // Verification succeeded
                if (verifyPair.first == value) {
                    DLL_LOG_INFO("Successfully set '" << cvarName << "' to \"" << value << "\"");
                }
                else { // Readback value differs
                    DLL_LOG_WARN("Set '" << cvarName << "' to \"" << value << "\", but read back \"" << verifyPair.first << "\". Game might have modified or constrained it.");
                }
            }
            else { // Verification failed
                DLL_LOG_WARN("Set '" << cvarName << "' to \"" << value << "\", but failed to verify readback.");
            }
            successCount++;
        }
        else { // setValue call failed
            DLL_LOG_ERROR("Failed to set CVar '" << cvarName << "' to value \"" << value << "\"");
            failureCount++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5)); // Short delay
    } // End CVar processing loop

    // --- Step 6: Report Summary ---
    PrintToConsole("\n--- JSON Load Summary ---");
    DLL_LOG_INFO("Processed " << jsonData.size() << " entries.");
    DLL_LOG_INFO("Successfully set: " << successCount);
    DLL_LOG_INFO("Failed to set:    " << failureCount);
    DLL_LOG_INFO("Skipped entries:  " << skippedCount);
    PrintToConsole("-------------------------");

    ShowHotkeyMenu(); // Show menu after completion
}


// --- Main DLL Thread ---
/**
 * @brief The main execution thread for the DLL.
 * Handles console allocation, waits for the target module, initializes MinHook,
 * finds the CVar manager pointer, creates the CVarManager wrapper, and runs the interactive hotkey loop.
 * Also handles cleanup on unload request (END key requires focus).
 * @param lpReserved Receives the HMODULE of this DLL instance.
 * @return 0 on successful unload, 1 on critical initialization error.
 */
DWORD WINAPI MainThread(LPVOID lpReserved) {
    g_hModule = reinterpret_cast<HMODULE>(lpReserved);

    // --- Console Allocation ---
    if (!AllocConsole()) {
        // Failed to allocate, try attaching to existing console
        g_hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
            OutputDebugStringA("[DLL FATAL] AllocConsole failed & could not get handle.\n"); // Log failure
            return 1; // Critical failure
        }
        g_hConsoleWnd = GetConsoleWindow(); // Try to get HWND
        PrintToConsole("[DLL INFO] AllocConsole failed, attached existing console."); // Use PrintToConsole now
    }
    else {
        // Allocated new console successfully
        g_hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_hConsoleOutput == INVALID_HANDLE_VALUE || g_hConsoleOutput == NULL) {
            OutputDebugStringA("[DLL FATAL] AllocConsole OK but GetStdHandle failed.\n"); // Log failure
            if (g_hConsoleWnd) FreeConsole(); // Clean up allocated console
            return 1; // Critical failure
        }
        g_hConsoleWnd = GetConsoleWindow(); // Get HWND
        if (g_hConsoleWnd == NULL) {
            PrintToConsole("[DLL WARN] AllocConsole succeeded but GetConsoleWindow failed!");
        }
        PrintToConsole("[DLL INFO] Console allocated."); // Use PrintToConsole now
    }

    // --- Redirect Standard Streams ---
    FILE* f_null_out = nullptr;
    FILE* f_null_err = nullptr;
    if (freopen_s(&f_null_out, "NUL:", "w", stdout) != 0) {
        DLL_LOG_ERROR("Failed to redirect stdout."); // Macros are safe now
    }
    if (freopen_s(&f_null_err, "NUL:", "w", stderr) != 0) {
        DLL_LOG_ERROR("Failed to redirect stderr."); // Macros are safe now
    }

    DLL_LOG_INFO("DLL Initializing...");
    if (g_hConsoleWnd == NULL) {
        DLL_LOG_WARN("Could not obtain console window handle. Focus checks will be disabled.");
    }
    DLL_LOG_INFO("Waiting for target module: " << TARGET_MODULE_NAME << "...");

    // --- Wait for Target Module ---
    HMODULE hTargetModule = NULL;
    while (hTargetModule == NULL) {
        if (CheckForEndKeyAndUnload()) { return 0; }
        hTargetModule = GetModuleHandleA(TARGET_MODULE_NAME);
        if (!hTargetModule) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Delay
        }
        if (CheckForEndKeyAndUnload()) { return 0; }
    }
    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(hTargetModule);
    DLL_LOG_INFO("Target module found. Base Address: 0x" << std::hex << baseAddr << std::dec);

    // --- Initialize MinHook ---
    if (MH_Initialize() != MH_OK) {
        DLL_LOG_ERROR("MinHook initialization failed! Unloading.");
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE && g_hConsoleOutput != NULL) {
            FreeConsole(); g_hConsoleWnd = NULL;
        }
        return 1; // Exit on failure
    }
    DLL_LOG_INFO("MinHook Initialized.");

    // --- Wait for CVarManager Pointer ---
    DLL_LOG_INFO("\nWaiting for CVarManager pointer...");
    void* gameCVarMgrPtr = nullptr;
    uintptr_t pGlobalPtrAddr = baseAddr + CVarManager::G_PCVARMANAGER_OFFSET;
    int wait_attempts = 0;
    const int max_wait_attempts = 500;
    int consecutive_valid_reads = 0;
    const int required_consecutive_reads = 10; // Stability requirement

    // Loop to find and stabilize the pointer (using direct read)
    while (wait_attempts < max_wait_attempts) {
        if (CheckForEndKeyAndUnload()) { return 0; }

        // Perform direct read (potentially unsafe if offset wrong or accessed too early)
        try { // Using try/except can mitigate crashes, but adds overhead. Direct read used here.
            gameCVarMgrPtr = *reinterpret_cast<void**>(pGlobalPtrAddr);
        }
        catch (...) {
            DLL_LOG_FATAL("Unhandled exception reading CVarManager pointer at: 0x" << std::hex << pGlobalPtrAddr << ". Unloading DLL...");
            MH_Uninitialize();
            if (g_hConsoleOutput != INVALID_HANDLE_VALUE) { FreeConsole(); g_hConsoleWnd = NULL; }
            //  if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
            return 1;
        }


        if (gameCVarMgrPtr != nullptr) { // Pointer found
            if (consecutive_valid_reads == 0) { // First time found
                DLL_LOG_INFO("Pointer for CVarManager found @ 0x" << std::hex << gameCVarMgrPtr << std::dec);
                DLL_LOG_INFO("\nPerforming stability check...\n\n"); // Need newlines for cursor move
            }
            consecutive_valid_reads++;
            // Update stability progress indicator
            if (consecutive_valid_reads == 1 || consecutive_valid_reads == required_consecutive_reads || wait_attempts % 1 == 0) {
                if (CheckForEndKeyAndUnload()) { MH_Uninitialize(); return 0; }
                std::ostringstream log;
                log << "[DLL INFO] Waiting... (Pointer=0x" << std::hex << gameCVarMgrPtr << std::dec << ", Stable Read: " << consecutive_valid_reads << "/" << required_consecutive_reads << ")";
                MoveCursorUp(1); ClearCurrentConsoleLine(); PrintToConsole(log.str());
            }
            if (consecutive_valid_reads >= required_consecutive_reads) { // Stable enough
                MoveCursorUp(1); ClearCurrentConsoleLine(); // Clean up last status line
                DLL_LOG_INFO("Pointer appears to be stable. Proceeding...");
                break; // Exit wait loop
            }
        }
        else { // Pointer is null
            if (consecutive_valid_reads > 0) { // Was valid, now null
                DLL_LOG_INFO("Pointer became null, resetting count.");
                MoveCursorUp(1); ClearCurrentConsoleLine(); // Clean up last status line
                PrintToConsole("[DLL INFO] Waiting for CVarManager pointer..."); // Reprint waiting message
            }
            consecutive_valid_reads = 0; // Reset counter
            // Update waiting progress indicator
            if (wait_attempts % 1 == 0) {
                if (CheckForEndKeyAndUnload()) { MH_Uninitialize(); return 0; }
                std::ostringstream log;
                log << "[DLL INFO] Waiting for CVarManager pointer... (Attempt " << wait_attempts + 1 << "/" << max_wait_attempts << ")";
                MoveCursorUp(1); ClearCurrentConsoleLine(); PrintToConsole(log.str());
            }
        }
        wait_attempts++;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait before next attempt
    }

    if (consecutive_valid_reads < required_consecutive_reads) { // Timed out
        MoveCursorUp(1); ClearCurrentConsoleLine(); // Clean up last status line
        DLL_LOG_ERROR("Timed out waiting for stable CVarManager pointer. Unloading.");
        MH_Uninitialize();
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE) { FreeConsole(); g_hConsoleWnd = NULL; }
        //if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
        return 1; // Exit on failure
    }

    // --- Create CVarManager Instance ---
    DLL_LOG_INFO("\nCreating CVarManager instance...");
    try {
        // Instantiate CVarManager wrapper, passing logger callback
        g_pCVarManager = std::make_unique<CVarManager>(
            TARGET_MODULE_NAME,
            static_cast<LogCallbackFn>(PrintToConsole)
        );
    }
    catch (const std::exception& e) { // Handle creation exceptions
        DLL_LOG_ERROR("Exception in CVarManager creation: " << e.what());
        g_pCVarManager.reset();
        MH_Uninitialize();
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE) { FreeConsole(); g_hConsoleWnd = NULL; }
        //if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
        return 1; // Exit on failure
    }
    catch (...) { // Handle unknown creation exceptions
        PrintToConsole("\n[ERROR] Unknown exception during CVarManager creation.");
        g_pCVarManager.reset();
        MH_Uninitialize();
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE) { FreeConsole(); g_hConsoleWnd = NULL; }
        //if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
        return 1; // Exit on failure
    }

    // --- Verify CVarManager Initialization ---
    DLL_LOG_INFO("\nVerifying CVarManager internal initialization...");
    if (!g_pCVarManager || !g_pCVarManager->IsInitialized()) { // Check if CVarManager initialized correctly internally
        DLL_LOG_ERROR("CVarManager failed initialization check. Unloading.");
        g_pCVarManager.reset();
        MH_Uninitialize();
        if (g_hConsoleOutput != INVALID_HANDLE_VALUE) { FreeConsole(); g_hConsoleWnd = NULL; }
        //if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
        return 1; // Exit on failure
    }

    DLL_LOG_INFO("CVarManager Ready.");
    ShowHotkeyMenu(); // Display interactive menu

    // --- Main Interactive Loop ---
    // Listens for hotkeys and the unload key.
    while (true) {
        // Check for unload request (requires console focus)
        if (CheckForEndKeyAndUnload()) {
            return 0; // Thread exits within CheckForEndKeyAndUnload
        }

        // Check hotkey states (using GetAsyncKeyState & 1 for key press detection)
        bool f1 = (GetAsyncKeyState(VK_F1) & 1);
        bool f2 = (GetAsyncKeyState(VK_F2) & 1);
        bool f3 = (GetAsyncKeyState(VK_F3) & 1);
        bool f4 = (GetAsyncKeyState(VK_F4) & 1);
        bool f5 = (GetAsyncKeyState(VK_F5) & 1);

        // Call appropriate handler function
        if (f1) {
            HandleSetCVar();
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        else if (f2) {
            HandleGetCVar();
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        else if (f3) {
            HandleDumpCVars();
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        else if (f4) {
            HandleLoadCVarsFromJson();
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        else if (f5) {
            ShowHotkeyMenu();
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        else {
            // No relevant key pressed, yield CPU
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    } // End main loop

    // --- Unreachable Fallback Cleanup ---
    // This code should not be reached if the loop/unload logic is correct.
    DLL_LOG_WARN("Main loop exited unexpectedly! Performing fallback cleanup...");
    if (g_pCVarManager) {
        g_pCVarManager.reset();
    }
    MH_Uninitialize();
    if (g_hConsoleOutput != INVALID_HANDLE_VALUE) {
        FreeConsole(); g_hConsoleWnd = NULL;
    }
    //if (g_hModule) FreeLibraryAndExitThread(g_hModule, 1); else ExitThread(1);
    ExitThread(1); // Fallback exit
    return 1; // Should be unreachable
}


// --- DllMain Entry Point ---
/**
 * @brief Standard DLL entry point function called by the OS.
 * Handles process attach/detach and thread attach/detach notifications.
 * Creates the main worker thread on process attach.
 * @param hModule Handle to the DLL module.
 * @param ul_reason_for_call Reason for the function call (e.g., DLL_PROCESS_ATTACH).
 * @param lpReserved Reserved parameter (context specific).
 * @return TRUE on success, FALSE on failure (prevents DLL loading on attach failure).
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE hThread = nullptr;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Called when DLL is loaded
        DisableThreadLibraryCalls(hModule); // Optimization: disable thread attach/detach calls
        // Create the main worker thread
        hThread = CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        if (hThread) {
            CloseHandle(hThread); // Close handle, thread runs independently
        }
        else {
            OutputDebugStringA("[DLL FATAL] Failed to create MainThread in DllMain.\n"); // Log critical failure
            return FALSE; // Prevent DLL load on thread creation failure
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // Ignored due to DisableThreadLibraryCalls
        break;

    case DLL_PROCESS_DETACH:
        // Called when DLL is unloaded or process exits.
        // Primary cleanup happens in MainThread via CheckForEndKeyAndUnload.
        // Cleanup here is unreliable on forced termination.
        break;
    }
    return TRUE; // Success
}

// --- SafeReadPointer Implementation (Assumed to exist or be provided elsewhere) ---
/**
 * @brief Safely reads a pointer-sized value from a given memory address.
 * Uses memory validation (VirtualQuery) and/or SEH to prevent crashes.
 * NOTE: The actual implementation is expected to be provided elsewhere or uncommented if present.
 * @param address The memory address to read from.
 * @param ppResult Pointer to a `void*` variable that will receive the read pointer value.
 * @return true if the read was successful, false otherwise.
 */
 /*
 #include <windows.h>

 bool SafeReadPointer(uintptr_t address, void** ppResult) {
     if (!ppResult) return false;
     *ppResult = nullptr;

     MEMORY_BASIC_INFORMATION mbi;
     if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
         return false; // Cannot query address
     }
     if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
         return false; // Memory not committed or not readable
     }

     __try {
         *ppResult = *reinterpret_cast<void**>(address);
         return true; // Read successful
     }
     __except (EXCEPTION_EXECUTE_HANDLER) {
         return false; // Access violation or other exception
     }
 }
 */