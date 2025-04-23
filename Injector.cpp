// Author: Sycorax (https://github.com/TheOneAndOnlySycorax)
// Date: 04/18/2025
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
// THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

/**
 * @file Injector.cpp
 * @brief Launches Star Citizen either directly (using backed-up login data) or via the RSI Launcher,
 *        injects necessary DLLs immediately upon game start, monitors for login failures in direct mode,
 *        and handles cleanup. Adheres to specific user requirements regarding injection timing and cleanup.
 *
 * @version 0.2
 *
 * Compilation: Requires C++ compiler (supporting C++11 features like thread, atomic) and Windows SDK.
 *              Link against Shlwapi.lib and Shell32.lib.
 *              Example (g++ via MinGW-w64):
 *              g++ Injector.cpp -o Injector.exe -std=c++11 -static -lshlwapi -lshell32
 */

 // --- Standard & Windows Headers ---
#include <windows.h>      // Core Windows API functions (Processes, Files, Handles, Environment, etc.)
#include <tlhelp32.h>     // Process snapshot functions (CreateToolhelp32Snapshot, Process32First/Next)
#include <shellapi.h>     // Shell functions, specifically ShellExecuteExW for running elevated commands
#include <shlwapi.h>      // Shell Lightweight Utility library (PathCombineW, PathFindFileNameW, etc.)
#include <iostream>       // Standard Input/Output streams (std::cout, std::wcout, std::cerr, std::wcerr)
#include <string>         // std::string and std::wstring for handling text
#include <vector>         // std::vector for dynamic arrays (used for error/success strings)
#include <thread>         // std::thread for running the log monitor concurrently
#include <map>            // std::map for parsing command-line arguments
#include <fstream>        // std::ifstream for reading the log file
#include <chrono>         // std::chrono for time durations and sleeping (std::this_thread::sleep_for)
#include <atomic>         // std::atomic for thread-safe boolean flag (g_loginFailed)
#include <cstdio>         // C Standard Input/Output library (needed for _wsplitpath_s)
#include <cstdlib>        // C Standard Library (needed for _MAX_DRIVE, _MAX_DIR used by _wsplitpath_s)

#include <sstream>   // For string splitting
#include <algorithm> // For trimming helpers


// --- Linker Directives ---
// Link necessary Windows libraries directly in the source code for convenience.
#pragma comment(lib, "Shlwapi.lib") // For PathCombineW, PathFindFileNameW etc.
#pragma comment(lib, "Shell32.lib") // For ShellExecuteExW

// --- Configuration Constants ---
// Define default values and filenames used throughout the application.
// These can be overridden by command-line arguments where applicable.
const wchar_t* GAME_PROCESS_NAME = L"StarCitizen.exe";              // Target game executable name
const wchar_t* RSI_LAUNCHER_EXE = L"RSI Launcher.exe";              // RSI Launcher executable name
const wchar_t* LOGIN_DATA_FILE = L"loginData.json";                 // Login data file created by game/launcher
const wchar_t* LOGIN_DATA_BACKUP_FILE = L"loginData_backup.json";   // Backup file used for direct launch persistence
const wchar_t* GAME_LOG_FILE = L"Game.log";                         // Game log file to monitor for login status
const wchar_t* MAIN_DLL_DEFAULT = L"dllmain.dll";                   // Default name/relative path of the primary DLL to inject
const wchar_t* DEFAULT_LAUNCHER_DIR = L"C:\\Program Files\\Roberts Space Industries\\RSI Launcher";  // Default RSI Launcher installation directory
const wchar_t* DEFAULT_GAME_DIR = L"C:\\Program Files\\Roberts Space Industries\\StarCitizen\\LIVE"; // Default Star Citizen LIVE installation directory
const wchar_t* DEFAULT_GAME_ARGS =                                  // Default command-line arguments for launching StarCitizen.exe directly
L"-no_login_dialog -envtag PUB --client-login-show-dialog 0 --services-config-enabled 1 "
L"--system-trace-service-enabled 1 --system-trace-env-id pub-sc-alpha-410-9650658 "
L"--grpc-client-endpoint-override https://pub-sc-alpha-410-9650658.test1.cloudimperiumgames.com:443";

const wchar_t* EAC_BYPASS_VAR = L"EOS_USE_ANTICHEATCLIENTNULL";

// --- Global State ---
// Used for inter-thread communication regarding login status.
std::atomic<bool> g_loginFailed(false); // Atomic boolean flag. Set to true by MonitorLogFile if a login error is detected. Read by the main thread.

// --- Helper Functions ---

// --- String Helper Functions ---
static inline std::wstring& ltrim(std::wstring& s, const wchar_t* t = L" \t\n\r\f\v\"") {
    s.erase(0, s.find_first_not_of(t));
    return s;
}
static inline std::wstring& rtrim(std::wstring& s, const wchar_t* t = L" \t\n\r\f\v\"") {
    s.erase(s.find_last_not_of(t) + 1);
    return s;
}
static inline std::wstring& trim(std::wstring& s, const wchar_t* t = L" \t\n\r\f\v\"") {
    return ltrim(rtrim(s, t), t);
}
std::vector<std::wstring> split_and_trim(const std::wstring& s, wchar_t delimiter) {
    std::vector<std::wstring> tokens;
    std::wstring token;
    std::wstringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        std::wstring trimmed_token = trim(token);
        if (!trimmed_token.empty()) {
            tokens.push_back(trimmed_token);
        }
    }
    return tokens;
}

// Helper to trim leading/trailing whitespace and quotes from a wstring
static inline std::wstring trim_quotes_and_space(const std::wstring& s) {
    size_t first = s.find_first_not_of(L" \t\n\r\f\v\"");
    if (std::wstring::npos == first) {
        return s; // String is all whitespace/quotes or empty
    }
    size_t last = s.find_last_not_of(L" \t\n\r\f\v\"");
    return s.substr(first, (last - first + 1));
}

// Helper to replace all occurrences of a substring
static inline void replace_all(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    if (from.empty())
        return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

// --- End String Helper Functions ---

/**
 * @brief Combines two path components into a single path string using the Windows API function PathCombineW.
 *        Provides a fallback mechanism using basic string concatenation if PathCombineW fails.
 * @param p1 The first path component (typically a directory path, e.g., L"C:\\Dir").
 * @param p2 The second path component (typically a filename or subdirectory, e.g., L"File.txt").
 * @return The fully combined path as a std::wstring (e.g., L"C:\\Dir\\File.txt").
 */
std::wstring JoinPath(const std::wstring& p1, const std::wstring& p2) {
    wchar_t combinedPath[MAX_PATH]; // Buffer to hold the combined path
    // Attempt to combine paths using the safer API function
    if (PathCombineW(combinedPath, p1.c_str(), p2.c_str()) == NULL) {
        // Log a warning if the API function fails
        std::wcerr << L"[WARN] PathCombineW failed, using basic concatenation for " << p1 << L" and " << p2 << std::endl;
        // Basic fallback logic: ensure a single backslash separator
        std::wstring result = p1;
        if (!result.empty() && result.back() != L'\\' && result.back() != L'/') {
            result += L'\\'; // Add separator if missing
        }
        result += p2; // Append the second part
        return result;
    }
    // Return the path successfully combined by the API
    return std::wstring(combinedPath);
}

/**
 * @brief Extracts the filename part (including extension) from a full path string.
 *        Uses the Windows API function PathFindFileNameW for reliable extraction.
 * @param path The full path string (e.g., L"C:\\Dir\\File.exe").
 * @return The filename component as a std::wstring (e.g., L"File.exe"). Returns an empty string if path is empty or invalid.
 */
std::wstring GetFileName(const std::wstring& path) {
    // PathFindFileNameW returns a pointer to the filename part within the original string
    const wchar_t* filename = PathFindFileNameW(path.c_str());
    // Construct a new wstring from the pointer
    return std::wstring(filename);
}

/**
 * @brief Extracts the directory path (including drive letter, if present) from a full path string.
 *        Uses the C runtime function _wsplitpath_s, with a fallback mechanism using string searching.
 * @param path The full path string (e.g., L"C:\\Dir\\Subdir\\File.exe").
 * @return The directory path as a std::wstring (e.g., L"C:\\Dir\\Subdir"). Returns "." (current directory) on significant failure.
 */
std::wstring GetDirectory(const std::wstring& path) {
    wchar_t drive[_MAX_DRIVE]; // Buffer for drive letter (e.g., "C:")
    wchar_t dir[_MAX_DIR];     // Buffer for directory path (e.g., "\\Dir\\Subdir\\")
    // Attempt to split the path into its components using the secure C runtime function
    errno_t err = _wsplitpath_s(path.c_str(), drive, _MAX_DRIVE, dir, _MAX_DIR, nullptr, 0, nullptr, 0);
    if (err != 0) {
        // Log a warning if splitting fails
        std::wcerr << L"[WARN] _wsplitpath_s failed for path: " << path << std::endl;
        // Fallback: Manually find the last directory separator
        size_t lastSlash = path.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            // Return the substring up to (but not including) the last separator
            return path.substr(0, lastSlash);
        }
        // If no separator found, return "." indicating the current directory as a fallback
        return L".";
    }
    // Combine the drive and directory parts successfully obtained from _wsplitpath_s
    std::wstring result = std::wstring(drive) + std::wstring(dir);
    // Clean up trailing backslash unless it's the root directory (e.g., "C:\")
    if (result.length() > 3 && (result.back() == L'\\' || result.back() == L'/')) {
        result.pop_back(); // Remove the trailing separator
    }
    return result;
}


/**
 * @brief Parses command-line arguments passed to the program into a key-value map.
 *        Supports arguments of the form "--key value" and standalone flags like "--flag".
 *        Arguments not starting with "--" are ignored.
 * @param argc The argument count (from `wmain`).
 * @param argv The argument vector (from `wmain`).
 * @return A `std::map<std::wstring, std::wstring>` where keys are the argument names (e.g., L"--gameDir")
 *         and values are the corresponding argument values or an empty wstring for flags.
 */
std::map<std::wstring, std::wstring> parse_args(int argc, wchar_t* argv[]) {
    std::map<std::wstring, std::wstring> args;
    // Iterate through command line arguments, starting from index 1 (index 0 is program name)
    for (int i = 1; i < argc; ++i) {
        // Check if the argument starts with "--" and if there is another argument potentially following it
        if (wcsncmp(argv[i], L"--", 2) == 0 && i + 1 < argc) {
            // Check if the *next* argument also starts with "--". If so, the current one is a flag.
            if (wcsncmp(argv[i + 1], L"--", 2) != 0) {
                // Current argument is a key, next argument is its value
                args[argv[i]] = argv[i + 1];
                ++i; // Increment 'i' again to skip the value in the next iteration
            }
            else {
                // Current argument is a flag followed by another option
                args[argv[i]] = L""; // Store the flag with an empty value
            }
        }
        else if (wcsncmp(argv[i], L"--", 2) == 0) {
            // Current argument starts with "--" but is the last argument or the next doesn't exist. Treat as a flag.
            args[argv[i]] = L""; // Store the flag with an empty value
        }
        // Ignore arguments that do not start with "--"
    }
    return args; // Return the map of parsed arguments
}

/**
 * @brief Converts a potentially relative path into a fully qualified absolute path using GetFullPathNameW.
 * @param relativePath The input path string, which can be relative (e.g., "MinHook.dll") or absolute.
 * @return The full absolute path as a std::wstring. Returns an empty string if path resolution fails.
 */
std::wstring get_absolute_path(const std::wstring& relativePath) {
    wchar_t buffer[MAX_PATH]; // Buffer to store the resulting full path
    // Call the Windows API function to resolve the path
    DWORD result = GetFullPathNameW(relativePath.c_str(), MAX_PATH, buffer, nullptr);
    // Check for errors (result 0) or buffer overflow (result > MAX_PATH)
    if (result == 0 || result > MAX_PATH) {
        std::wcerr << L"[ERROR] Failed to resolve path: " << relativePath << L" | Error: " << GetLastError() << std::endl;
        return L""; // Return empty string on failure
    }
    // Return the absolute path stored in the buffer
    return std::wstring(buffer);
}

/**
 * @brief Checks if a file (and specifically not a directory) exists at the given path.
 * @param path The full path to the item to check.
 * @return `true` if a file exists at the specified path, `false` otherwise (e.g., path doesn't exist, is a directory, or error occurred).
 */
bool file_exists(const std::wstring& path) {
    // Get the file attributes
    DWORD attrs = GetFileAttributesW(path.c_str());
    // Check if GetFileAttributesW succeeded (attrs != INVALID_FILE_ATTRIBUTES)
    // AND check if the FILE_ATTRIBUTE_DIRECTORY flag is *not* set.
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

/**
 * @brief Checks if a directory exists at the given path.
 * @param path The full path to the item to check.
 * @return `true` if a directory exists at the specified path, `false` otherwise (e.g., path doesn't exist, is a file, or error occurred).
 */
bool directory_exists(const std::wstring& path) {
    // Get the file attributes
    DWORD attrs = GetFileAttributesW(path.c_str());
    // Check if GetFileAttributesW succeeded (attrs != INVALID_FILE_ATTRIBUTES)
    // AND check if the FILE_ATTRIBUTE_DIRECTORY flag *is* set.
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
}


/**
 * @brief Copies a file from a source path to a destination path using CopyFileW.
 *        This function will overwrite the destination file if it already exists.
 * @param src The full path to the source file.
 * @param dst The full path for the destination file.
 * @return `true` if the copy operation was successful, `false` otherwise.
 */
bool copy_file(const std::wstring& src, const std::wstring& dst) {
    // Call CopyFileW. The third parameter 'FALSE' indicates that overwriting the destination is allowed.
    if (!CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
        // Log an error if the copy fails
        std::wcerr << L"[ERROR] Failed to copy file: " << src << L" -> " << dst << L" | Error: " << GetLastError() << std::endl;
        return false; // Indicate failure
    }
    // Log success information
    std::wcout << L"[INFO] Copied file: " << src << L" -> " << dst << std::endl;
    return true; // Indicate success
}

/**
 * @brief Deletes the file specified by the path, if it exists and is actually a file (not a directory).
 *        Uses DeleteFileW. Logs warnings on failure, except for "file not found" errors during the delete attempt.
 * @param path The full path to the file to be deleted.
 */
void clear_or_delete_file(const std::wstring& path) {
    // First, check if the item exists and is a file
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Attempt to delete the file
        if (!DeleteFileW(path.c_str())) {
            DWORD err = GetLastError();
            // Only log a warning if the error is something other than "file not found"
            // (covers race conditions where the file disappears between check and delete)
            if (err != ERROR_FILE_NOT_FOUND) {
                std::wcerr << L"[WARN] Failed to delete file: " << path << L" | Error: " << err << std::endl;
            }
        }
        else {
            // Log successful deletion
            std::wcout << L"[INFO] Deleted file: " << path << std::endl;
        }
    }
    else {
        // Handle potential errors during the initial attribute check
        DWORD err = GetLastError();
        // Only log unexpected errors, not common "not found" errors.
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            std::wcerr << L"[WARN] Could not get attributes (pre-delete check) for: " << path << L" | Error: " << err << std::endl;
        }
        // If file/path not found, no deletion is needed, and no message is logged (especially important for cleanup steps).
    }
}

/**
 * @brief Retrieves the size of a specified file using GetFileSizeEx.
 * @param path The full path to the file whose size is needed.
 * @param fileSize [out] A reference to a LARGE_INTEGER structure where the file size (in bytes) will be stored upon success.
 * @return `true` if the file size was successfully obtained, `false` if the file could not be opened or the size could not be read.
 */
bool get_file_size(const std::wstring& path, LARGE_INTEGER& fileSize) {
    // Attempt to open the file with read access, allowing others to read, write, or delete it simultaneously.
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // Check if the file handle is valid
    if (hFile == INVALID_HANDLE_VALUE) {
        // Don't log a warning if the file simply wasn't found (this can be normal)
        if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
            std::wcerr << L"[WARN] GetFileSize: Could not open file handle: " << path << L" | Error: " << GetLastError() << std::endl;
        }
        return false; // Indicate failure
    }
    // Get the file size using the handle
    BOOL result = GetFileSizeEx(hFile, &fileSize);
    // Close the file handle promptly
    CloseHandle(hFile);
    // Check if GetFileSizeEx failed
    if (!result) {
        std::wcerr << L"[WARN] GetFileSizeEx failed for: " << path << L" | Error: " << GetLastError() << std::endl;
        return false; // Indicate failure
    }
    // Success
    return true;
}


/**
 * @brief Launches a new process using the CreateProcessW API function. Allows specifying whether the new process
 *        should get its own console window or have its standard input/output/error streams redirected to NUL
 *        (effectively suppressing console output).
 * @param exePath The full, absolute path to the executable file to launch.
 * @param args The command-line arguments to pass to the executable.
 * @param pi [out] A reference to a PROCESS_INFORMATION structure that will receive the handles (hProcess, hThread)
 *               and IDs (dwProcessId, dwThreadId) of the newly created process and its primary thread.
 * @param workingDir An optional full path specifying the working directory for the new process. If empty,
 *                   the parent process's current directory is used.
 * @param createNewConsole If `true`, the function uses the `CREATE_NEW_CONSOLE` flag, giving the new process its
 *                         own console window (typical for launching the game).
 *                         If `false`, the function redirects the standard input, output, and error handles of the
 *                         new process to the `NUL` device, preventing it from writing to or inheriting the parent's console
 *                         (useful for launching the GUI-based RSI Launcher).
 * @return `true` if the process was launched successfully (CreateProcessW returned success), `false` otherwise.
 */
bool LaunchProcessWithArgs(const std::wstring& exePath, const std::wstring& args, PROCESS_INFORMATION& pi, const std::wstring& workingDir = L"", bool createNewConsole = true) {
    // Construct the command line string. Needs to be mutable for CreateProcessW.
    // Enclose executable path in quotes to handle spaces.
    std::wstring cmdLine = L"\"" + exePath + L"\" " + args;

    // Initialize STARTUPINFO structure (controls window appearance, std handles, etc.)
    STARTUPINFOW si{};
    si.cb = sizeof(si); // Set structure size

    // Initialize PROCESS_INFORMATION structure (receives process/thread info)
    ZeroMemory(&pi, sizeof(pi));

    // Determine the working directory pointer (null if empty string provided)
    const wchar_t* cwd = workingDir.empty() ? nullptr : workingDir.c_str();

    // Initialize creation flags and handle inheritance setting
    DWORD creationFlags = 0;    // Process creation flags (e.g., CREATE_NEW_CONSOLE)
    BOOL inheritHandles = FALSE; // Whether the child process inherits handles from the parent

    // --- Setup NUL Redirection Handles (if needed) ---
    HANDLE hNulInput = INVALID_HANDLE_VALUE;
    HANDLE hNulOutput = INVALID_HANDLE_VALUE;
    HANDLE hNulError = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa{}; // Security attributes for creating inheritable handles

    // --- Configure based on createNewConsole flag ---
    if (!createNewConsole) {
        // === Setup for Suppressing Console Output (Redirecting to NUL) ===
        // std::wcout << L"[DEBUG] Setting up std handle redirection to NUL for: " << GetFileName(exePath) << std::endl;

        // Initialize SECURITY_ATTRIBUTES to make handles inheritable
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE; // Crucial: Handles created using this struct will be inheritable
        sa.lpSecurityDescriptor = NULL; // Use default security descriptor

        // Open the NUL device for Standard Input (Child will read from NUL)
        hNulInput = CreateFileW(
            L"NUL",                             // Special device name
            GENERIC_READ,                       // Read access
            FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow sharing
            &sa,                                // Make handle inheritable
            OPEN_EXISTING,                      // NUL always exists
            0,                                  // Default attributes
            NULL                                // No template file
        );
        if (hNulInput == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[ERROR] Failed to open NUL device for input redirection. Error: " << GetLastError() << std::endl;
            return false; // Cannot proceed
        }

        // Open the NUL device for Standard Output (Child will write to NUL)
        hNulOutput = CreateFileW(
            L"NUL",
            GENERIC_WRITE,                    // Write access
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,                              // Make handle inheritable
            OPEN_EXISTING,
            0,
            NULL
        );
        if (hNulOutput == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[ERROR] Failed to open NUL device for output redirection. Error: " << GetLastError() << std::endl;
            CloseHandle(hNulInput); // Clean up the input handle we already opened
            return false; // Cannot proceed
        }

        // Redirect Standard Error to the same NUL handle as Standard Output
        hNulError = hNulOutput; // It's common and efficient to reuse the output handle

        // --- Configure STARTUPINFO for Redirection ---
        si.dwFlags |= STARTF_USESTDHANDLES; // Tell CreateProcess to use the hStd* handles below
        si.hStdInput = hNulInput;           // Set standard input to NUL read handle
        si.hStdOutput = hNulOutput;         // Set standard output to NUL write handle
        si.hStdError = hNulError;           // Set standard error to NUL write handle

        // --- Set CreateProcess Flags for Redirection ---
        // Handles specified in STARTUPINFO *must* be inherited
        inheritHandles = TRUE;
        // No specific creation flags needed (don't use CREATE_NEW_CONSOLE or DETACHED_PROCESS if redirecting std handles)
        creationFlags = 0;

    }
    else {
        // === Setup for Creating a New Console (e.g., for the Game) ===
        creationFlags = CREATE_NEW_CONSOLE; // Flag to give the process its own console window
        inheritHandles = FALSE; // Standard handles should not be inherited from the parent injector console
    }

    // --- Attempt to Create the Process ---
    BOOL result = CreateProcessW(
        nullptr,               // lpApplicationName: Use NULL, specify executable in command line
        &cmdLine[0],           // lpCommandLine: Must be a mutable wide string
        nullptr,               // lpProcessAttributes: Default security
        nullptr,               // lpThreadAttributes: Default security
        inheritHandles,        // bInheritHandles: TRUE for redirection, FALSE otherwise
        creationFlags,         // dwCreationFlags: Flags like CREATE_NEW_CONSOLE or 0
        nullptr,               // lpEnvironment: Inherit parent's environment block
        cwd,                   // lpCurrentDirectory: Working directory for the child process
        &si,                   // lpStartupInfo: Pointer to STARTUPINFO structure
        &pi                    // lpProcessInformation: Receives process/thread handles and IDs
    );

    // --- Cleanup Parent's NUL Handles ---
    // The parent process MUST close its copies of the handles created for redirection,
    // regardless of whether CreateProcess succeeded or failed. The child process received
    // its own copies if inheritHandles was TRUE.
    if (hNulInput != INVALID_HANDLE_VALUE) CloseHandle(hNulInput);
    if (hNulOutput != INVALID_HANDLE_VALUE) CloseHandle(hNulOutput); // Closed once handles both output/error if reused


    // --- Check CreateProcess Result ---
    if (!result) {
        std::wcerr << L"[ERROR] Failed to launch process '" << GetFileName(exePath) << L"'. Error: " << GetLastError() << std::endl;
        // Optionally log more details here for debugging launch failures
        return false; // Indicate launch failure
    }

    // Success: Log the launch info and return true
    std::wcout << L"[INFO] Launched process '" << GetFileName(exePath) << L"'. PID: " << pi.dwProcessId << std::endl;
    return true;
}

/**
 * @brief Runs a specified command with elevated administrator privileges using ShellExecuteExW and the "runas" verb.
 *        This will typically trigger a User Account Control (UAC) prompt if elevation is required.
 * @param command The full path to the executable file to execute with elevation (e.g., "setx.exe", "reg.exe").
 * @param args The command-line arguments to pass to the elevated executable.
 * @param wait If `true` (the default), the function will block and wait until the elevated process terminates.
 *             If `false`, the function returns immediately after initiating the launch (useful for fire-and-forget).
 * @return `true` if the `ShellExecuteExW` call successfully initiated the launch attempt (this does *not* guarantee that the
 *         elevated process itself completed successfully or that the user approved the UAC prompt). Returns `false` if `ShellExecuteExW`
 *         failed to initiate the launch (e.g., file not found, user cancelled UAC).
 */
bool RunElevated(const std::wstring& command, const std::wstring& args, bool wait = true) {
    // Initialize the SHELLEXECUTEINFO structure
    // Initialize all fields to avoid missing initializer warnings
    SHELLEXECUTEINFOW sei = { 
        sizeof(sei),         // cbSize
        0,                   // fMask 
        NULL,                // hwnd
        NULL,                // lpVerb
        NULL,                // lpFile
        NULL,                // lpParameters
        NULL,                // lpDirectory
        0,                   // nShow
        0,                   // hInstApp
        NULL,                // lpIDList
        NULL,                // lpClass
        NULL,                // hkeyClass
        0,                   // dwHotKey
        {0},                 // Anonymous union (HANDLE_PTR or hIcon/hMonitor)
        NULL                 // hProcess
    };
    sei.cbSize = sizeof(sei);         // Must set the size of the structure
    sei.lpVerb = L"runas";            // Specify the "runas" verb to request elevation
    sei.lpFile = command.c_str();     // Path to the executable to run
    sei.lpParameters = args.c_str();  // Arguments for the executable
    sei.nShow = SW_HIDE;              // Request that the elevated process window (if any) be hidden
    sei.fMask = SEE_MASK_NOCLOSEPROCESS; // Ask ShellExecuteExW to return a process handle if possible

    // Attempt to execute the command with elevation
    if (ShellExecuteExW(&sei)) {
        // ShellExecuteExW succeeded in initiating the launch
        //std::wcout << L"[INFO] Launched elevated process: " << GetFileName(command) << L" " << args << std::endl;

        // Handle waiting logic based on the 'wait' parameter and whether a valid handle was returned
        if (wait && sei.hProcess != NULL) {
            // Wait indefinitely for the elevated process to terminate
            WaitForSingleObject(sei.hProcess, INFINITE);
            // Close the process handle now that we're done waiting
            CloseHandle(sei.hProcess);
          //  std::wcout << L"[INFO] Elevated process finished." << std::endl;
        }
        else if (!wait && sei.hProcess != NULL) {
            // If not waiting, we still need to close the handle we received
            CloseHandle(sei.hProcess);
        }
        else if (wait && sei.hProcess == NULL) {
            // Handle the case where ShellExecuteEx succeeded but didn't provide a process handle (can happen)
            // We cannot wait in this scenario.
            std::wcerr << L"[WARN] Elevated process handle was NULL, cannot wait for completion (process might have finished instantly or handle unavailable)." << std::endl;
        }
        return true; // Indicate that the launch attempt was successful
    }
    else {
        // ShellExecuteExW failed to initiate the launch
        DWORD err = GetLastError();
        std::wcerr << L"[ERROR] Failed to launch elevated process '" << GetFileName(command) << L"'. Error: " << err << std::endl;
        // Provide specific feedback if the error suggests UAC denial
        if (err == ERROR_CANCELLED) {
            std::wcerr << L"          (Elevation prompt may have been denied by the user.)" << std::endl;
        }
        return false; // Indicate launch initiation failure
    }
}

/**
 * @brief Injects a specified DLL into a target process using the classic CreateRemoteThread technique.
 *        This involves allocating memory in the target process's address space, writing the full path
 *        of the DLL into that memory, obtaining the address of the `LoadLibraryW` function (which is
 *        typically shared across processes via kernel32.dll), and then creating a new thread in the
 *        target process that executes `LoadLibraryW` with the DLL path as its argument.
 * @param pid The Process ID (PID) of the target process into which the DLL should be injected.
 * @param dllPath The full, absolute path to the DLL file to be injected.
 * @return `true` if the injection process completed and `LoadLibraryW` likely succeeded in the remote process
 *         (indicated by a non-zero exit code from the remote thread), `false` otherwise (due to errors in
 *         opening the process, memory allocation/writing, thread creation, or if `LoadLibraryW` failed remotely).
 */
bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
    // --- Pre-condition Checks ---
    if (pid == 0) {
        std::wcerr << L"[ERROR] InjectDLL: Invalid target PID (0)." << std::endl;
        return false; // Cannot inject into PID 0
    }
    if (dllPath.empty() || !file_exists(dllPath)) {
        // DLL path must be valid and the file must exist
        std::wcerr << L"[ERROR] InjectDLL: DLL path is empty or file not found: " << dllPath << std::endl;
        return false;
    }

    // --- Step 1: Open the Target Process ---
    // Request necessary access rights:
    // PROCESS_QUERY_INFORMATION: Allows querying basic info (might be needed internally).
    // PROCESS_CREATE_THREAD: Essential for creating the remote thread.
    // PROCESS_VM_OPERATION: Needed for VirtualAllocEx and VirtualFreeEx.
    // PROCESS_VM_WRITE: Needed to write the DLL path into the target's memory.
    // PROCESS_VM_READ: Might be needed for certain address lookups or internal operations.
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, // Handles should not be inherited by child processes of this injector
        pid    // The target Process ID
    );
    // Check if opening the process failed
    if (!hProc) {
        std::wcerr << L"[ERROR] InjectDLL: OpenProcess failed (PID: " << pid << L"). Error: " << GetLastError() << std::endl;
        return false; // Cannot proceed without a process handle
    }

    // --- Step 2: Allocate Memory in Target Process for DLL Path ---
    // Calculate the size needed for the DLL path string, including the null terminator.
    size_t dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    // Allocate memory within the target process's virtual address space.
    // MEM_COMMIT | MEM_RESERVE: Commits and reserves the memory pages.
    // PAGE_READWRITE: Sets memory protection to allow reading and writing.
    void* allocMem = VirtualAllocEx(hProc, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        // Handle memory allocation failure
        std::wcerr << L"[ERROR] InjectDLL: VirtualAllocEx failed in target process (PID: " << pid << L"). Error: " << GetLastError() << std::endl;
        CloseHandle(hProc); // Clean up the opened process handle
        return false;
    }

    // --- Step 3: Write the DLL Path into Allocated Memory ---
    // Copy the DLL path string into the memory region allocated in the target process.
    if (!WriteProcessMemory(hProc, allocMem, dllPath.c_str(), dllPathSize, nullptr)) {
        // Handle writing failure
        std::wcerr << L"[ERROR] InjectDLL: WriteProcessMemory failed in target process (PID: " << pid << L"). Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE); // Free the allocated memory on failure
        CloseHandle(hProc); // Clean up the opened process handle
        return false;
    }

    // --- Step 4: Get the Address of LoadLibraryW ---
    // Get the memory address of the LoadLibraryW function from kernel32.dll.
    // This address is typically the same across processes loading the standard kernel32.dll.
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        // Handle failure to get the function address
        std::wcerr << L"[ERROR] InjectDLL: GetProcAddress(LoadLibraryW) failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE); // Clean up allocated memory
        CloseHandle(hProc); // Clean up process handle
        return false;
    }

    // --- Step 5: Create a Remote Thread in the Target Process ---
    // Create a new thread in the target process that will start execution at the LoadLibraryW address.
    // The argument passed to the thread is the pointer to the DLL path string we wrote into the target's memory.
    HANDLE hThread = CreateRemoteThread(
        hProc,                            // Handle to the target process
        nullptr,                          // Default thread security attributes
        0,                                // Default stack size for the new thread
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, // Starting function for the thread (LoadLibraryW)
        allocMem,                         // Argument passed to LoadLibraryW (pointer to the DLL path)
        0,                                // Creation flags (0 = run immediately)
        nullptr                           // Pointer to receive thread ID (not needed here)
    );
    if (!hThread) {
        // Handle remote thread creation failure
        std::wcerr << L"[ERROR] InjectDLL: CreateRemoteThread failed in target process (PID: " << pid << L"). Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE); // Clean up allocated memory
        CloseHandle(hProc); // Clean up process handle
        return false;
    }

    // --- Step 6: Wait for the Remote Thread to Complete ---
    // Wait indefinitely for the remote thread (which is executing LoadLibraryW) to finish.
    WaitForSingleObject(hThread, INFINITE);
    std::wstring dllFilename = GetFileName(dllPath); // Get filename for logging
    //std::wcout << L"[INFO] Injection thread finished for: " << dllFilename << std::endl;

    // --- Step 7: Check the Result of LoadLibraryW via Thread Exit Code ---
    DWORD exitCode = 0; // Variable to store the remote thread's exit code
    // Get the exit code. For a thread calling LoadLibraryW, the exit code will be
    // the HMODULE (base address) of the loaded DLL on success, or 0 on failure.
    GetExitCodeThread(hThread, &exitCode);

    // --- Step 8: Cleanup Resources ---
    // Free the memory allocated in the target process for the DLL path.
    VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
    // Close the handle to the remote thread.
    CloseHandle(hThread);
    // Close the handle to the target process.
    CloseHandle(hProc);

    // --- Step 9: Interpret the Result ---
    if (exitCode == 0) {
        // LoadLibraryW failed within the remote thread.
        std::wcerr << L"[ERROR] LoadLibraryW failed in the remote process for " << dllFilename << L" (Remote Thread ExitCode=0)." << std::endl;
        std::wcerr << L"        Check DLL dependencies, architecture (must be x64), and ensure DllMain returns TRUE." << std::endl;
        return false; // Indicate injection failure
    }
    else {
        // LoadLibraryW likely succeeded. Log the success and the returned HMODULE.
        std::wcout << L"[SUCCESS] DLL injected successfully: " << dllFilename << L" (LoadLibrary HMODULE: " << std::hex << exitCode << std::dec << L")" << std::endl;
        return true; // Indicate injection success
    }
}

/**
 * @brief Finds the Process ID (PID) of the first running process that matches the provided executable name.
 *        Uses the ToolHelp32Snapshot API to enumerate processes. The comparison is case-insensitive.
 * @param procName The name of the executable file (e.g., L"StarCitizen.exe") to search for.
 * @return The Process ID (PID) of the first matching process found. Returns 0 if no matching process is found
 *         or if an error occurs during the process snapshot enumeration.
 */
DWORD GetProcessID(const wchar_t* procName) {
    PROCESSENTRY32W entry{}; // Structure to hold information about a single process
    entry.dwSize = sizeof(PROCESSENTRY32W); // Initialize the size member is required by the API

    // Create a snapshot including all processes currently running in the system.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // Check if snapshot creation failed
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[ERROR] CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return 0; // Return 0 (invalid PID) on failure
    }

    DWORD pid = 0; // Variable to store the found PID, default to 0 (not found)

    // Attempt to get the information for the first process in the snapshot
    if (Process32FirstW(snapshot, &entry)) {
        // Loop through the rest of the processes in the snapshot
        do {
            // Compare the executable file name of the current process with the target name (case-insensitive)
            if (_wcsicmp(entry.szExeFile, procName) == 0) {
                // Match found! Store the Process ID
                pid = entry.th32ProcessID;
                break; // Exit the loop since we found the first match
            }
        } while (Process32NextW(snapshot, &entry)); // Move to the next process in the snapshot
    }
    else {
        // Handle potential error when getting the first process
        DWORD err = GetLastError();
        // ERROR_NO_MORE_FILES is expected if the process list is empty, so don't log it as an error.
        if (err != ERROR_NO_MORE_FILES) {
            std::wcerr << L"[ERROR] Process32FirstW failed. Error: " << err << std::endl;
        }
    }

    // Close the snapshot handle to release system resources
    CloseHandle(snapshot);

    // Return the found PID (will be 0 if no match was found)
    return pid;
}

/**
 * @brief Monitors the specified game log file for specific login failure or success strings in a separate thread.
 *        This function is designed to run concurrently with the main application logic, specifically during the
 *        "Direct Launch" mode (when using `loginData_backup.json`).
 *
 *        - If a known login **failure** string is detected, it sets the global atomic flag `g_loginFailed` to `true`
 *          and the monitoring thread terminates. The main thread should periodically check this flag.
 *        - If a known login **success** string is detected, the monitoring thread prints an informational message
 *          and terminates gracefully without setting the failure flag.
 *        - If the target game process (identified by `gamePid`) terminates for any other reason, the monitoring
 *          thread detects this, resets the `g_loginFailed` flag (if not already set by an error), prints an
 *          informational message, and terminates.
 *
 * @param logFilePath The full, absolute path to the game's log file (typically "Game.log").
 * @param gamePid The Process ID (PID) of the game process (`StarCitizen.exe`) being monitored.
 */
void MonitorLogFile(std::wstring logFilePath, DWORD gamePid) {
    std::wcout << L"\n[INFO] Monitoring log file: " << logFilePath << std::endl;

    // Define the specific log messages that indicate login failure
    std::vector<std::string> errorStrings = {
        "[Error] CDiffusionCryClient::OnConnected The initiate login failed [Team_GameServices][Login]",
        "{SET_ACCOUNT_STATE} state [kAccountLoginFailed]",
        "CServicesThread::UpdateAccountStatus connection account login failed"
    };

    // Define specific log messages that indicate login success
    std::vector<std::string> successStrings = {
        "<Legacy login response> [CIG-net] User Login Success",
        "<Legacy login queue status> Legacy login success [Team_GameServices][Login]"
    };

    std::ifstream logStream;             // Input file stream used to read the log file
    LARGE_INTEGER lastSize = {};         // Stores the size of the log file from the previous check cycle
    lastSize.QuadPart = 0;               // Initialize size to 0
    bool firstCheck = true;             // Flag: Read the entire file on the first iteration?
    bool gameProcessExists = true;      // Flag: Controls the main monitoring loop; set to false if game process exits

    // Main monitoring loop: continues as long as the game process is believed to be running
    while (gameProcessExists) {
        // === Step 1: Check if the target game process is still alive ===
        DWORD exitCode = STILL_ACTIVE; // Assume it's active
        // Attempt to open the process with minimal query rights
        HANDLE hCheckExist = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
        // Check if opening failed OR getting exit code failed OR the exit code is not STILL_ACTIVE
        if (hCheckExist == NULL || !GetExitCodeProcess(hCheckExist, &exitCode) || exitCode != STILL_ACTIVE) {
            // Game process has terminated or become inaccessible
            std::wcout << L"[INFO] Log Monitor: Game process (PID: " << gamePid << ") terminated or inaccessible. Stopping monitor." << std::endl;
            gameProcessExists = false; // Set flag to exit the while loop
        }
        // Close the temporary handle used for the check
        if (hCheckExist) CloseHandle(hCheckExist);
        // Exit the loop immediately if the process check failed
        if (!gameProcessExists) {
            break;
        }

        // === Step 2: Check the status and size of the log file ===
        LARGE_INTEGER currentSize = {};   // To store the current file size
        bool fileExistsNow = file_exists(logFilePath); // Check if file exists currently
        bool sizeRead = false;          // Flag: Was reading the size successful?
        if (fileExistsNow) {
            sizeRead = get_file_size(logFilePath, currentSize); // Get current size if file exists
        }

        // === Step 3: Handle Log File Not Existing ===
        if (!fileExistsNow) {
            // If the log file doesn't exist (e.g., hasn't been created yet, or was deleted)
            std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before checking again
            lastSize.QuadPart = 0; // Reset the last known size
            firstCheck = true;     // Ensure full read if it reappears
            continue;              // Go to the next iteration of the while loop
        }

        // === Step 4: Read New Content if File Grew or First Check ===
        // Proceed only if we could read the size AND (the size increased OR it's the first check)
        if (sizeRead && (currentSize.QuadPart > lastSize.QuadPart || firstCheck)) {
            // Open the log file for reading in binary mode (safer for seeking)
            logStream.open(logFilePath.c_str(), std::ios::in | std::ios::binary);
            if (logStream.is_open()) {
                std::streampos readStartPos = 0; // Position in file to start reading from

                // If this isn't the first check, seek past the content we've already read
                if (!firstCheck) {
                    readStartPos = lastSize.QuadPart;
                    logStream.seekg(readStartPos, std::ios::beg);
                    // If seeking fails (e.g., file changed unexpectedly), reset to read from beginning
                    if (logStream.fail()) {
                        std::wcerr << L"[WARN] Log Monitor: Failed seek operation in " << logFilePath << L". Resetting position." << std::endl;
                        logStream.clear(); // Clear stream error flags
                        readStartPos = 0; // Start from beginning
                        logStream.seekg(readStartPos, std::ios::beg);
                        lastSize.QuadPart = 0; // Reset last known size
                    }
                }
                else {
                    // On the first check, explicitly set lastSize to 0 to ensure reading starts from beginning
                    lastSize.QuadPart = 0;
                }

                firstCheck = false; // Mark the first check as completed
                std::string line;   // Buffer to hold each line read

                // Read lines from the current position
                while (std::getline(logStream, line)) {
                    // --- Check for LOGIN FAILURE strings ---
                    for (const auto& errorStr : errorStrings) {
                        // Use string::find for efficient substring search
                        if (line.find(errorStr) != std::string::npos) {
                            // *** FAILURE DETECTED ***
                            std::wcerr << L"[ALERT] Detected login failure string in log!" << std::endl;
                            std::cerr << "        \"" << line << "\"" << std::endl; // Print the matching line
                            g_loginFailed = true; // Set the global atomic flag
                            logStream.close();    // Close the file stream
                            std::wcout << L"[INFO] Log monitor stopping." << std::endl;
                            return; // Exit the MonitorLogFile function immediately
                        }
                    } // End error string check loop

                    // --- Check for LOGIN SUCCESS strings (only if no error found) ---
                    for (const auto& successStr : successStrings) {
                        if (line.find(successStr) != std::string::npos) {
                            // *** SUCCESS DETECTED ***
                            std::wcout << L"[INFO] Detected login success string in log." << std::endl;
                            std::cout << "        \"" << line << "\"" << std::endl; // Print the matching line
                            // IMPORTANT: Do *not* set g_loginFailed flag
                            logStream.close(); // Close the file stream
                            std::wcout << L"[INFO] Log monitor stopping." << std::endl;
                            return; // Exit the MonitorLogFile function gracefully
                        }
                    } // End success string check loop

                    // If neither error nor success string found in this line, update our position marker
                    lastSize.QuadPart = logStream.tellg(); // Record the position after reading the line
                } // End while getline loop

                // --- After reading all available lines, check the stream state ---
                if (logStream.eof()) {
                    // Reached the end of the file normally
                    logStream.clear(); // Clear the EOF flag
                    logStream.seekg(0, std::ios::end); // Ensure position is at the very end
                    lastSize.QuadPart = logStream.tellg(); // Update lastSize accurately
                }
                else if (logStream.fail()) {
                    // A non-EOF read error occurred (e.g., bad character data)
                    std::wcerr << L"[WARN] Log Monitor: Non-fatal read error occurred in " << logFilePath << std::endl;
                    logStream.clear(); // Clear error flags to allow closing and retry later
                    // Keep the last known *good* size before the error occurred
                }
                // Implicit else: No error, no EOF (shouldn't happen after getline loop)

                logStream.close(); // Close the file stream
            }
            else {
                // Failed to open the log file (e.g., permissions, locked)
                std::wcerr << L"[WARN] Log Monitor: Could not open log file: " << logFilePath << std::endl;
                lastSize.QuadPart = 0; // Reset size knowledge
                firstCheck = true;     // Force retry opening next cycle
            }
        }
        else if (sizeRead && currentSize.QuadPart < lastSize.QuadPart) {
            // --- Handle Log File Shrinking ---
            // This indicates the file was likely cleared or truncated by the game
            std::wcout << L"[INFO] Log Monitor: Log file size decreased. Resetting position." << std::endl;
            lastSize.QuadPart = 0; // Reset position marker
            firstCheck = true;     // Force full re-read from beginning
        }
        else if (!sizeRead && fileExistsNow) {
            // --- Handle Inability to Read Size ---
            // File exists, but we couldn't get its size (permissions? locked?)
            std::wcerr << L"[WARN] Log Monitor: Could not read size of existing file: " << logFilePath << std::endl;
            lastSize.QuadPart = 0; // Reset position marker
            firstCheck = true;     // Force retry next cycle
        }
        // Implicit else: If sizeRead and size hasn't changed, do nothing this cycle.

        // Wait for a short duration before the next check cycle
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    // If the loop exited because the game process terminated normally (not due to detected error/success),
    // ensure the global failure flag is reset.
    g_loginFailed = false;
}


//UNUSED
/**
 * @brief Parses `build_manifest.id` to extract Tag, Branch, and P4 Change Number.
 * @param manifestPath The full path to the `build_manifest.id` file.
 * @param outTag [out] Reference to store the extracted "Tag" value.
 * @param outBranch [out] Reference to store the extracted "Branch" value.
 * @param outP4ChangeNum [out] Reference to store the extracted "RequestedP4ChangeNum" value.
 * @return `true` if the file was parsed successfully and all keys found, `false` otherwise.
 *         Logs warnings on failure and success details on success.
 */
bool parse_build_manifest(const std::wstring& manifestPath,
    std::wstring& outTag,
    std::wstring& outBranch,
    std::wstring& outP4ChangeNum)
{
    std::wifstream manifestFile(manifestPath);
    if (!manifestFile.is_open()) {
        //std::wcerr << L"[WARN] Could not open build manifest file: " << manifestPath << std::endl;
        return false;
    }

    std::wstring line;
    bool tagFound = false, branchFound = false, p4Found = false;

    // Simple line-by-line parsing looking for specific keys
    while (std::getline(manifestFile, line)) {
        size_t colonPos = line.find(L':');
        if (colonPos == std::wstring::npos) continue; // Skip lines without a colon

        std::wstring key = line.substr(0, colonPos);
        std::wstring value = line.substr(colonPos + 1);

        // Trim key and value
        key = trim_quotes_and_space(key);
        value = trim_quotes_and_space(value);
        // Remove trailing comma if present
        if (!value.empty() && value.back() == L',') {
            value.pop_back();
        }
        value = trim_quotes_and_space(value); // Trim again after removing comma

        if (key == L"Tag" && !value.empty()) {
            outTag = value;
            tagFound = true;
        }
        else if (key == L"Branch" && !value.empty()) {
            outBranch = value;
            branchFound = true;
        }
        else if (key == L"RequestedP4ChangeNum" && !value.empty()) {
            outP4ChangeNum = value;
            p4Found = true;
        }

        if (tagFound && branchFound && p4Found) {
            break; // Found all required values
        }
    }

    manifestFile.close();

    if (!tagFound || !branchFound || !p4Found) {
        //std::wcerr << L"[WARN] Failed to find all required keys (Tag, Branch, RequestedP4ChangeNum) in " << manifestPath << std::endl;
        return false;
    }

    //std::wcout << L"[INFO] Successfully parsed build manifest:" << std::endl;
    //std::wcout << L"        Tag: " << outTag << std::endl;
    //std::wcout << L"        Branch: " << outBranch << std::endl;
    //std::wcout << L"        P4ChangeNum: " << outP4ChangeNum << std::endl;
    return true;
}

//UNUSED
/**
 * @brief Constructs Star Citizen command-line arguments based on manifest data.
 *        Formats `--system-trace-env-id` and `--grpc-client-endpoint-override`.
 * @param tag The build tag from the manifest (e.g., L"public").
 * @param branch The branch name from the manifest (e.g., L"sc-alpha-4.1.0").
 * @param p4ChangeNum The P4 change number from the manifest (e.g., L"9687209").
 * @return A `std::wstring` containing the constructed command-line argument string.
 *         Logs the constructed identifier and final arguments.
 */
std::wstring construct_game_args_from_manifest(const std::wstring& tag, const std::wstring& branch, const std::wstring& p4ChangeNum) {
    // --- Apply transformations ---
    std::wstring processedTag = tag;
    // Convert "public" to "pub", lowercase others for consistency?
    // Simple case for now based on example:
    if (processedTag == L"public") {
        processedTag = L"pub";
    }
    else {
        // Lowercase other tags if needed, or handle specific cases
        std::transform(processedTag.begin(), processedTag.end(), processedTag.begin(), ::towlower);
    }


    std::wstring processedBranch = branch;
    // Remove dots from branch: "sc-alpha-4.1.0" -> "sc-alpha-410"
    replace_all(processedBranch, L".", L"");

    // P4 Change number usually used as is
    std::wstring processedP4 = p4ChangeNum;

    // --- Construct the identifier ---
    std::wstring identifier = processedTag + L"-" + processedBranch + L"-" + processedP4;
    //std::wcout << L"[INFO] Constructed identifier: " << identifier << std::endl;

    // --- Build the argument string ---
    // Base arguments that seem constant
    std::wstring baseArgs = L"-no_login_dialog -envtag PUB --client-login-show-dialog 0 --services-config-enabled 1 --system-trace-service-enabled 1 "; // Note trailing space

    // Dynamic arguments
    std::wstring systemTraceArg = L"--system-trace-env-id " + identifier;
    std::wstring grpcEndpointArg = L"--grpc-client-endpoint-override https://" + identifier + L".test1.cloudimperiumgames.com:443"; // Assuming domain structure

    std::wstring finalArgs = baseArgs + systemTraceArg + L" " + grpcEndpointArg;

    //std::wcout << L"[INFO] Constructed game arguments based on manifest." << std::endl;
    return finalArgs;
}

/**
 * @brief Parses `settings.json` to extract the command-line parameters string.
 * @param settingsPath The full path to the `settings.json` file.
 * @param outParams [out] Reference to store the extracted parameters string value.
 * @return `true` if the file was parsed successfully and the "parameters" key found, `false` otherwise.
 *         Logs warnings on failure and success details on success.
 */
bool parse_settings_json(const std::wstring& settingsPath, std::wstring& outParams) {
    std::wifstream settingsFile(settingsPath);
    if (!settingsFile.is_open()) {
        std::wcerr << L"[WARN] Could not open settings file: " << settingsPath << std::endl;
        return false;
    }

    std::wstring line;
    bool paramsFound = false;
    const std::wstring paramKey = L"\"parameters\""; // Search for the key including quotes

    while (std::getline(settingsFile, line)) {
        size_t keyPos = line.find(paramKey);
        if (keyPos != std::wstring::npos) {
            // Found the key, now find the colon after it
            size_t colonPos = line.find(L':', keyPos + paramKey.length());
            if (colonPos != std::wstring::npos) {
                // Extract the value part after the colon
                std::wstring valuePart = line.substr(colonPos + 1);

                // Trim whitespace, quotes, and trailing comma if present
                valuePart = trim_quotes_and_space(valuePart); // Use existing helper
                if (!valuePart.empty() && valuePart.back() == L',') {
                    valuePart.pop_back();
                }
                valuePart = trim_quotes_and_space(valuePart); // Trim again

                if (!valuePart.empty()) {
                    outParams = valuePart;
                    paramsFound = true;
                    break; // Found what we needed
                }
                else {
                    std::wcerr << L"[WARN] Found \"parameters\" key in " << settingsPath << L" but the value appears empty after trimming." << std::endl;
                    // Continue searching just in case, though unlikely format
                }
            }
        }
    }

    settingsFile.close();

    if (!paramsFound) {
        std::wcerr << L"[WARN] Failed to find \"parameters\" key in " << settingsPath << std::endl;
        return false;
    }

    std::wcout << L"[INFO] Successfully parsed \"parameters\" from settings file." << std::endl;
    // Optional: Log extracted params for debugging
    // std::wcout << L"        Parameters: " << outParams << std::endl;
    return true;
}

/**
 * @brief Forcefully terminates a process using its Process ID (PID) via TerminateProcess.
 *        Includes checks to see if the process has already exited before or during the termination attempt.
 * @param pid The Process ID (PID) of the process to be terminated.
 * @param processNameHint A descriptive name string (e.g., L"StarCitizen.exe") used purely for logging purposes to make output clearer.
 * @return `true` if the process was successfully terminated or was already found to be terminated, `false` if termination failed for other reasons.
 */
bool TerminateProcessByPid(DWORD pid, const std::wstring& processNameHint) {
    // Check for invalid PID input
    if (pid == 0) {
        std::wcerr << L"[ERROR] TerminateProcess: Invalid PID (0) provided for " << processNameHint << "." << std::endl;
        return false;
    }

    // Attempt to open the target process with PROCESS_TERMINATE access right
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        // If opening failed, check the reason
        DWORD err = GetLastError();
        // ERROR_INVALID_PARAMETER often indicates the process with that PID no longer exists
        if (err == ERROR_INVALID_PARAMETER) {
            std::wcout << L"[INFO] TerminateProcess: Process " << processNameHint << L" (PID: " << pid << L") already terminated (OpenProcess failed with ERROR_INVALID_PARAMETER)." << std::endl;
            return true; // Consider it successfully "terminated" if it's already gone
        }
        // Report other errors preventing opening the process
        std::wcerr << L"[ERROR] Failed to open process " << processNameHint << L" for termination (PID: " << pid << L"). Error: " << err << std::endl;
        return false; // Indicate failure
    }

    // Attempt to terminate the process using the obtained handle
    BOOL result = TerminateProcess(hProcess, 1); // Use a non-zero exit code (convention for forced termination)
    DWORD lastErr = GetLastError(); // Capture the error code immediately after TerminateProcess

    // Close the process handle regardless of the termination result
    CloseHandle(hProcess);

    // Check if TerminateProcess reported failure
    if (!result) {
        // If termination failed, it's possible the process exited *just* between OpenProcess and TerminateProcess.
        // Perform a quick check to see if the process is still active.
        DWORD exitCodeCheck = 0;
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        // If we can't query status OR the process is confirmed not active...
        if (hCheck == NULL || !GetExitCodeProcess(hCheck, &exitCodeCheck) || exitCodeCheck != STILL_ACTIVE) {
            // Assume it exited successfully just before or during our termination attempt
            std::wcout << L"[INFO] TerminateProcess: Process " << processNameHint << L" (PID: " << pid << L") exited before or during termination attempt." << std::endl;
            if (hCheck) CloseHandle(hCheck); // Close the check handle if opened
            return true; // Consider it success if it's gone
        }
        if (hCheck) CloseHandle(hCheck); // Close the check handle if process was still active

        // If the process is still demonstrably active AND TerminateProcess failed, report the specific error
        std::wcerr << L"[ERROR] Failed to terminate process " << processNameHint << L" (PID: " << pid << L"). Error: " << lastErr << std::endl;
        return false; // Indicate termination failure
    }

    // Termination likely succeeded
    std::wcout << L"[INFO] Terminated process " << processNameHint << L" (PID: " << pid << L")." << std::endl;
    // Add a small delay to allow the OS some time to clean up process resources more fully before proceeding
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return true; // Indicate termination success
}


// --- Environment Variable Management ---

/**
 * @brief Sets the required environment variable for EAC bypass, both locally and persistently (system-wide).
 *        Requires elevation for system-wide changes.
 * @return `true` if setting attempts were initiated successfully, `false` otherwise.
 */
bool SetEnvironmentVariables() {
    std::wcout << L"[INFO] Setting environment variable for EAC bypass (requires elevation): \"" << EAC_BYPASS_VAR << L"=1\"" << std::endl;

    // Set system-wide persistent variable using setx. Waits for completion.
    std::wstring setxArgs = L"/M ";
    setxArgs += EAC_BYPASS_VAR;
    setxArgs += L" 1";
    if (!RunElevated(L"setx", setxArgs, true)) { // true = wait
        std::wcerr << L"[ERROR] Failed to set system environment variable via setx." << std::endl;
        // Attempt immediate cleanup via registry if setx failed, before returning failure
        RunElevated(L"REG", L"delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /F /V " + std::wstring(EAC_BYPASS_VAR), true);
        SetEnvironmentVariableW(EAC_BYPASS_VAR, nullptr); // Clean up local too
        return false;
    }

    // Also set the variable for the current injector process and its direct children.
    if (!SetEnvironmentVariableW(EAC_BYPASS_VAR, L"1")) {
        std::wcerr << L"[WARN] Failed to set local environment variable. Error: " << GetLastError() << std::endl;
        // Don't necessarily fail the whole operation for local failure if system one worked, but log it.
    }

    std::wcout << L"[INFO] Environment variable set." << std::endl;
    return true;
}

/**
 * @brief Cleans up the environment variables set for EAC bypass, both locally and persistently.
 *        Requires elevation for system-level changes.
 * @param forInjectorExit If true, indicates this is the final cleanup before the injector exits.
 */
void CleanupEnvironmentVariables(bool forInjectorExit = false) {
     std::wcout << L"\n--- Final Cleanup ---" << std::endl;
    
    std::wcout << L"[INFO] Cleaning up environment variable (requires elevation): " << EAC_BYPASS_VAR << std::endl;

    // Attempt to unset/clear the system variable using setx first. Waits for completion.
    std::wstring setxArgs = L"/M ";
    setxArgs += EAC_BYPASS_VAR;
    setxArgs += L" \"\""; // Set to empty string
    RunElevated(L"setx", setxArgs, true); // true = wait

    // Follow up with REG delete for robustness, ensuring it's removed from the registry.
    RunElevated(L"REG", L"delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /F /V " + std::wstring(EAC_BYPASS_VAR), true); // true = wait

    // Clean up the variable in the current injector process environment block.
    SetEnvironmentVariableW(EAC_BYPASS_VAR, nullptr);

    if (forInjectorExit) {
        std::wcout << L"[INFO] Environment variable cleanup complete." << std::endl;
    }
    else {
        std::wcout << L"[INFO] Environment variable cleanup performed." << std::endl;
    }
}

/**
 * @brief Displays the help message containing program description, usage, and options.
 */
void ShowHelp() {
    std::wcout << L"\n=== Star Citizen Injector/Launcher Help ===\n\n";
    std::wcout << L"Description:\n";
    std::wcout << L"  Launches Star Citizen and injects specified DLLs immediately after the game starts.\n";
    std::wcout << L"  Supports two launch modes:\n";
    std::wcout << L"    1. Direct Launch: If a '" << LOGIN_DATA_BACKUP_FILE << L"' exists, it restores\n";
    std::wcout << L"       this data and automatically launches " << GAME_PROCESS_NAME << L" directly.\n";
    std::wcout << L"       'In this mode, it monitors '" << GAME_LOG_FILE << L"' for login failures and\n";
    std::wcout << L"        will restart using the RSI Launcher if a failure is detected.\n\n";
    std::wcout << L"    2. Via RSI Launcher: If no backup of login data exists, it starts '" << RSI_LAUNCHER_EXE << L"',\n";
    std::wcout << L"       waits for the user to launch the game via the launcher, injects DLLs,\n";
    std::wcout << L"       attempts to create '" << LOGIN_DATA_BACKUP_FILE << L"', and closes the launcher.\n";
    std::wcout << L"       This mode requires elevated privileges for environment variable setup/cleanup.\n\n";
    
    std::wcout << L"  Why dose this program need to backup 'loginData.json'?:\n";
    std::wcout << L"    Star Citizen requires 'loginData.json' to run and automatically deletes it on exit.\n"; 
    std::wcout << L"    So by creating a backup of this file, it ensures that there is valid data to restore\n";
    std::wcout << L"    whenever this program automatically launches the game.\n\n";


    std::wcout << L"Usage:\n";
    std::wcout << L"  Injector.exe [options]\n\n";

    std::wcout << L"Options:\n";
    std::wcout << L"  -h, --help\n";
    std::wcout << L"      Show this help message and exit.\n\n";

    std::wcout << L"  -i, --inject <list>\n";
    std::wcout << L"      Specifies a comma separated list of DLL paths to inject (relative or absolute).\n";
    std::wcout << L"      Paths with spaces might need internal quotes depending on the shell." << std::endl;
    std::wcout << L"      Example: --inject \"Test.dll, ../MyMod/Mod.dll, C:/Other/Tool.dll\"" << std::endl;
    std::wcout << L"      Default: \"" << MAIN_DLL_DEFAULT << L"\"\n\n";

    std::wcout << L"  --gameDir <path>\n";
    std::wcout << L"      Specifies the path to the Star Citizen installation directory\n";
    std::wcout << L"      (e.g., \"C:\\Program Files\\Roberts Space Industries\\StarCitizen\\LIVE\").\n";
    std::wcout << L"      Default: \"" << DEFAULT_GAME_DIR << L"\"\n\n";

    std::wcout << L"  --launcherDir <path>\n";
    std::wcout << L"      Specifies the path to the RSI Launcher installation directory.\n";
    std::wcout << L"      Default: \"" << DEFAULT_LAUNCHER_DIR << L"\"\n\n";

    std::wcout << L"  --gameArgs \"<arguments>\"\n";
    std::wcout << L"      Specifies Star Citizen's command-line arguments to use when launching the game directly.\n";
    std::wcout << L"      Enclose the entire argument string in double quotes.\n";
    std::wcout << L"      If this option is not used, the program will attempt to automatically determine\n"; // Added auto-detect info
    std::wcout << L"      the correct arguments by parsing 'Settings.json' in the game's EastAntiCheat directory.\n";
    std::wcout << L"      If the automatic procedure fails, it will fall back to the internal default:\n"; // Added fallback info
    std::wcout << L"            \"" << DEFAULT_GAME_ARGS << L"\"\n\n";

    std::wcout << L"Example:\n";
    std::wcout << L"  Injector.exe --gameDir \"D:\\Games\\StarCitizen\\LIVE\" --inject \"MyOverlay.dll\"\n\n";
}







// --- Main Program Entry Point ---
/**
 * @brief Main function for the Star Citizen Injector/Launcher.
 *        Handles command line arguments, determines launch mode (Direct or Launcher),
 *        sets/cleans environment variables, launches/detects the game, injects DLLs,
 *        optionally monitors the log file, handles cleanup, and manages restarting
 *        the process if login fails in Direct mode.
 * @param argc Number of command line arguments.
 * @param argv Array of wide character command line argument strings.
 * @return 0 on successful completion, 1 on critical failure.
 */
int wmain(int argc, wchar_t* argv[]) {
    // Print program header
    std::wcout << L"=== Star Citizen Injector/Launcher v0.2 by Sycorax ===" << std::endl;
    std::wcout << L"Use -h or --help for command line options\n" << std::endl;
    // --- Help Option Check ---
    // Check for -h or --help *before* parsing other arguments or doing work.
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            ShowHelp();
            return 0; // Exit cleanly after showing help
        }
    }
    // Display help hint if no help flag was provided
    

    // --- Argument Parsing & Path Setup ---
    // Manually parse critical arguments to check for duplicates and required values
    std::wstring injectArgValue = L"";
    std::wstring gameDirValue = L"";
    std::wstring launcherDirValue = L"";
    std::wstring gameArgsValue = L"";

    bool injectFlagFound = false;
    bool gameDirFlagFound = false;
    bool launcherDirFlagFound = false;
    bool gameArgsFlagFound = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring currentArg = argv[i];

        // Helper lambda to check for duplicate flags and get the value
        // Added 'isInjectArg' boolean parameter for special handling
        auto parse_single_arg = [&](const std::wstring& flagShort, const std::wstring& flagLong,
            bool& flagFound, std::wstring& valueStore, bool isInjectArg) -> bool // Added isInjectArg
            {
                if (currentArg == flagShort || currentArg == flagLong) {
                    // --- Duplicate Check ---
                    if (flagFound) {
                        std::wcerr << L"[FATAL] Argument " << currentArg << L" can only be specified once." << std::endl;
                        ShowHelp();
                        return false; // Indicate fatal error
                    }
                    flagFound = true;

                    // --- Value Presence Check ---
                    // Check if there is a next argument AND it doesn't start with '-'
                    bool valueProvided = (i + 1 < argc && argv[i + 1][0] != L'-');

                    if (valueProvided) {
                        // A potential value exists next
                        valueStore = argv[i + 1];

                        // *** Conditional Empty Value Check ***
                        // Check for empty value ONLY if it's NOT the inject argument
                        if (!isInjectArg && valueStore.empty()) {
                            std::wcerr << L"[FATAL] Argument " << currentArg << L" cannot have an empty value." << std::endl;
                            ShowHelp();
                            return false;
                        }
                        // If it IS the inject argument, we accept an empty value (e.g., --inject "")

                        i++; // Consume the value argument
                        return true; // Success, flag and value processed
                    }
                    else {
                        // No value provided (either last argument or next starts with '-')

                        // *** Conditional Required Value Check ***
                        // Check if a value was required ONLY if it's NOT the inject argument
                        if (!isInjectArg) {
                            std::wcerr << L"[FATAL] Argument " << currentArg << L" requires a value." << std::endl;
                            ShowHelp();
                            return false; // Indicate fatal error for non-inject args
                        }
                        // If it IS the inject argument, it's okay if no value follows.
                        // valueStore will remain empty (or its default), which the later logic handles.
                        return true; // Success, flag processed, value was optional/absent
                    }
                }
                return true; // Argument didn't match this flag, continue checking others
            }; // End of lambda definition

        // Parse arguments using the lambda, passing 'true' for isInjectArg only for -i/--inject
        if (!parse_single_arg(L"-i", L"--inject", injectFlagFound, injectArgValue, true)) return 1;
        if (!parse_single_arg(L"", L"--gameDir", gameDirFlagFound, gameDirValue, false)) return 1;
        if (!parse_single_arg(L"", L"--launcherDir", launcherDirFlagFound, launcherDirValue, false)) return 1;
        if (!parse_single_arg(L"", L"--gameArgs", gameArgsFlagFound, gameArgsValue, false)) return 1;

        // You could add checks for other arguments here if needed
        // else if (currentArg starts with '-') { /* Handle unknown arguments? */ }

    } // End argument parsing loop

    // Determine final values, using defaults if flags weren't found
    std::wstring gameDirArg = gameDirFlagFound ? gameDirValue : DEFAULT_GAME_DIR;
    std::wstring launcherDirArg = launcherDirFlagFound ? launcherDirValue : DEFAULT_LAUNCHER_DIR;
    std::wstring gameArgs = gameArgsFlagFound ? gameArgsValue : DEFAULT_GAME_ARGS; // Renamed to avoid conflict

    std::vector<std::wstring> injectDllsRel;

    if (injectFlagFound) {
        // Flag WAS provided, use the comma-separated value from CLI
        if (injectArgValue.empty()) { // Should be caught by parser, but double-check
            std::wcout << L"[INFO] Internal error: -i/--inject flag found but value is empty. Using default DLL: " << MAIN_DLL_DEFAULT << std::endl;
            injectDllsRel.push_back(MAIN_DLL_DEFAULT);
        }
        // Split the value obtained from the command line
        injectDllsRel = split_and_trim(injectArgValue, L',');
        if (injectDllsRel.empty()) {
            // Splitting resulted in nothing valid
            std::wcout << L"[INFO] No valid DLL paths found after parsing list. Using default DLL: " << MAIN_DLL_DEFAULT << std::endl;
            injectDllsRel.push_back(MAIN_DLL_DEFAULT);
        }

    }
    else {
            std::wcout << L"[INFO] No -i/--inject argument provided. Using default DLL: " << MAIN_DLL_DEFAULT << std::endl;
            // Add the *single* default path directly to the vector
            injectDllsRel.push_back(MAIN_DLL_DEFAULT);
    }

    // Check if we actually have any DLLs to inject *now*
    if (injectDllsRel.empty()) {
        std::wcout << L"[INFO] No DLLs configured for injection. Using default DLL: " << MAIN_DLL_DEFAULT << std::endl;
        injectDllsRel.push_back(MAIN_DLL_DEFAULT);
    }    

    // Resolve Inject DLLs
    std::vector<std::wstring> injectDllsAbs;
    bool allInjectDllsResolved = true;
    for (const auto& relPath : injectDllsRel) {
        std::wstring absPath = get_absolute_path(relPath);
        if (absPath.empty()) {
            std::wcerr << L"[FATAL] Could not resolve DLL path to absolute path: " << relPath << std::endl;
            allInjectDllsResolved = false;
        }
        else {
            injectDllsAbs.push_back(absPath);
        }
    }
    if (!allInjectDllsResolved) {
        std::wcerr << L"Please check -i/--inject arguments and file locations." << std::endl;
        return 1; // Exit if any DLL path resolution failed
    }

    // Resolve all relative paths to their absolute forms
    std::wstring gameDir = get_absolute_path(gameDirArg);
    std::wstring launcherDir = get_absolute_path(launcherDirArg);

    // Validate that base paths could be resolved; exit if not
    if (gameDir.empty() || launcherDir.empty()) {
        std::wcerr << L"[FATAL] Could not resolve one or more required base paths:" << std::endl;
        if (gameDir.empty()) std::wcerr << L"  - Game directory resolution failed: " << gameDirArg << std::endl;
        if (launcherDir.empty()) std::wcerr << L"  - Launcher directory resolution failed: " << launcherDirArg << std::endl;
        std::wcerr << L"Please check arguments and file/directory locations." << std::endl;
        return 1; // Indicate critical failure
    }

    // Construct full paths to specific files and directories using the resolved base paths
    std::wstring gameBin64Dir = JoinPath(gameDir, L"Bin64");                      // Game's Bin64 directory
    std::wstring exePath = JoinPath(gameBin64Dir, GAME_PROCESS_NAME);             // Full path to StarCitizen.exe
    std::wstring loginDataPath = JoinPath(gameDir, LOGIN_DATA_FILE);              // Full path to loginData.json
    std::wstring loginBackupPath = JoinPath(gameDir, LOGIN_DATA_BACKUP_FILE);     // Full path to loginData_backup.json
    std::wstring gameLogPath = JoinPath(gameDir, GAME_LOG_FILE);                  // Full path to Game.log
    std::wstring rsiLauncherPath = JoinPath(launcherDir, RSI_LAUNCHER_EXE);       // Full path to RSI Launcher.exe
    //std::wstring buildManifestPath = JoinPath(gameDir, L"build_manifest.id");   // Currently unused
    std::wstring gameEACDir = JoinPath(gameDir, L"EasyAntiCheat");                        // Game's Easy Anti Cheat directory
    std::wstring settingsJsonPath = JoinPath(gameEACDir, L"Settings.json");

    // --- Pre-flight Checks ---
    if (!directory_exists(gameDir)) { std::wcerr << L"[FATAL] Game directory not found: " << gameDir << std::endl; return 1; }
    if (!file_exists(exePath)) { std::wcerr << L"[FATAL] Game executable not found: " << exePath << std::endl; return 1; }
    if (!directory_exists(launcherDir)) { std::wcerr << L"[FATAL] Launcher directory not found: " << launcherDir << std::endl; return 1; }
    if (!file_exists(rsiLauncherPath)) { std::wcerr << L"[FATAL] RSI Launcher executable not found: " << rsiLauncherPath << std::endl; return 1; }

    // Validate Inject DLLs existence
    bool allInjectDllsExist = true;
    for (const auto& absPath : injectDllsAbs) {
        if (!file_exists(absPath)) {
            std::wcerr << L"[FATAL] Specified DLL not found: " << absPath << std::endl;
            allInjectDllsExist = false;
        }
    }
    if (!allInjectDllsExist) {
        std::wcerr << L"Please check -i/--inject arguments and file locations." << std::endl;
        return 1;
    }

    // Validate other essential file existence
    if (!file_exists(exePath)) { std::wcerr << L"[FATAL] Game executable not found: " << exePath << std::endl; return 1; }
    if (!file_exists(rsiLauncherPath)) { std::wcerr << L"[FATAL] RSI Launcher executable not found: " << rsiLauncherPath << std::endl; return 1; }

    // --- Dynamic Game Argument Construction ---
    std::wcout << L"\n--- Game Argument Configuration ---" << std::endl;
    // Check if the user *didn't* specify custom arguments
    if (!gameArgsFlagFound) {
        // Attempt to parse the manifest
        //std::wcout << L"[INFO] --gameArgs not specified. Attempting to read build manifest file in game directory..." << std::endl;

        //std::wstring manifestTag, manifestBranch, manifestP4;
        //if (parse_build_manifest(buildManifestPath, manifestTag, manifestBranch, manifestP4)) {
        // gameArgs = construct_game_args_from_manifest(manifestTag, manifestBranch, manifestP4);
        // std::wcout << L"[INFO] Using dynamically constructed game arguments." << std::endl;
        
        //Attempt to parse EAC settings file
        std::wcout << L"[INFO] --gameArgs not specified." << std::endl;
        std::wcout << L"[INFO] Attempting to parse Settings.json file in the game's EasyAntiCheat directory to get game arguments..." << std::endl;
        std::wstring extractedParams;
        if (parse_settings_json(settingsJsonPath, extractedParams)) {
            gameArgs = extractedParams;
            std::wcout << L"[INFO] Using arguments from settings file." << std::endl;
        }
        else {
            // Parsing failed or file not found, use the hardcoded default
            std::wcout << L"[WARN] Failed to get arguments from settings file. Using default values." << std::endl;
        }
        std::wcout << L"[INFO] Final Game Args: " << gameArgs << std::endl;
    }
    else {
        // User specified arguments, respect their choice
        std::wcout << L"[INFO] Using game arguments provided via --gameArgs." << std::endl;
    }
    
    // --- Main Application Loop ---
    // This loop allows the entire process (launch/detect, inject, monitor) to be restarted.
    // The primary reason for restarting is if a direct launch fails due to login issues,
    // requiring a run through the RSI Launcher path to get fresh login data.
    std::wcout << L"\n--- Initalization ---" << std::endl;
    while (true) {
        // --- Reset State Variables for Current Iteration ---
        g_loginFailed = false;              // Reset the login failure flag detected by the monitor thread
        DWORD gamePid = 0;                  // PID of the StarCitizen.exe process for this iteration
        DWORD launcherPid = 0;              // PID of the RSI Launcher.exe process (if used this iteration)
        PROCESS_INFORMATION piGame{};       // Process info if we launch the game directly this iteration
        ZeroMemory(&piGame, sizeof(piGame)); // Ensure handles start NULL
        std::thread logMonitorThread;       // Thread object for log monitoring (created only if needed)
        bool launchedDirectly = false;      // Flag indicating if this iteration uses the direct launch path
        bool injectionFullySucceeded = false;// Flag tracking if DLLs were injected successfully this iteration
        bool backupCreatedThisRun = false;  // Flag indicating if backup was made during an RSI Launcher run this iteration
        bool envVarsSetThisRun = false;     // Track if env vars were set for this run (for cleanup logic)

        // --- Initial Cleanup for this Iteration ---
        // Clear the game log file at the start of each attempt to ensure fresh monitoring.
        std::wcout << L"[INFO] Clearing game log file: " << gameLogPath << std::endl;
        clear_or_delete_file(gameLogPath);

        // --- Phase 1: Set Env Vars & Launch/Detect ---
        // The environment variables needed for injection are set *before* launching either process path.
        // This requires elevation and happens at the start of each potential launch attempt (loop iteration).
        if (!SetEnvironmentVariables()) {
            std::wcerr << L"[FATAL] Failed initial environment variable setup. Exiting." << std::endl;
            // Cleanup is attempted within SetEnvironmentVariables on failure, so just exit here.
            return 1;
        }
        envVarsSetThisRun = true; // Mark env vars as successfully set for this iteration

        // Determine the launch strategy: Use backup if available, otherwise use RSI Launcher.
        if (file_exists(loginBackupPath)) {
            // === Direct Launch Path ===
            // Backup file exists, attempt to launch the game directly using it.
            std::wcout << L"[MODE] Backup file found. Attempting direct game launch." << std::endl;
            launchedDirectly = true; // Set the mode flag for this iteration

            // Check if the game process is already running from a previous launch/attempt
            gamePid = GetProcessID(GAME_PROCESS_NAME);
            if (gamePid != 0) {
                // Game already running - use the existing process instance.
                std::wcout << L"[WARN] " << GAME_PROCESS_NAME << L" (PID: " << gamePid << L") is already running. Using existing process." << std::endl;
                // Ensure our process handles are null since we didn't launch it this time.
                piGame.hProcess = NULL;
                piGame.hThread = NULL;
            }
            else {
                // Game not running - launch it using the backup data.
                std::wcout << L"[INFO] Restoring login data from backup..." << std::endl;
                // Copy the backup file to the active loginData.json location.
                if (!copy_file(loginBackupPath, loginDataPath)) {
                    // This is critical - if backup exists but can't be copied, direct launch fails.
                    std::wcerr << L"[ERROR] Failed to restore login data from backup: " << loginBackupPath << std::endl;
                    if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars before exiting
                    return 1; // Exit program; manual intervention needed.
                }

                // Launch StarCitizen.exe, giving it its own console window.
                if (gameArgsFlagFound) {
                    std::wcout << L"[INFO] Launching " << GetFileName(exePath) << L" with arguments..." << std::endl;
                }
                if (!LaunchProcessWithArgs(exePath, gameArgs, piGame, gameBin64Dir, true)) { // true = new console
                    std::wcerr << L"[ERROR] Failed to launch game executable directly." << std::endl;
                    // Clean up the potentially corrupted login data we just copied.
                    clear_or_delete_file(loginDataPath);
                    if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars before exiting
                    return 1; // Exit program on launch failure.
                }
                // Store the PID of the process we just launched.
                gamePid = piGame.dwProcessId;

                // Wait briefly after launch to allow the process to initialize somewhat before injection.
                //std::wcout << L"[INFO] Waiting briefly after launch..." << std::endl;
                //std::this_thread::sleep_for(std::chrono::seconds(8));
            }
            // Proceed to Phase 2 (Injection) after this block. gamePid should now be valid.

        }
        else {
            // === RSI Launcher Path ===
            // Backup file does not exist. Need to use the RSI Launcher to obtain valid login data.
            std::wcout << L"[MODE] Backup file not found. Using RSI Launcher to obtain login data." << std::endl;
            launchedDirectly = false; // Set the mode flag for this iteration

            // --- Begin RSI Launcher Procedure ---
            std::wcout << L"\n--- RSI Launcher Procedure ---" << std::endl;
            // Environment variables were already set at the start of Phase 1.

            // 1. Launch the RSI Launcher Executable
            // Use the option to suppress its console output by redirecting std handles.
            std::wcout << L"[INFO] Launching RSI Launcher (Output suppressed)..." << std::endl;
            PROCESS_INFORMATION rsiPi{}; // Structure to receive launcher process info
            if (!LaunchProcessWithArgs(rsiLauncherPath, L"", rsiPi, launcherDir, false)) { // false = no new console/redirect output
                std::wcerr << L"[ERROR] Failed to launch RSI Launcher executable." << std::endl;
                if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars before exiting
                return 1; // Exit on failure
            }
            launcherPid = rsiPi.dwProcessId; // Store the Launcher's PID
            // Close the handles to the launcher process immediately; we only need the PID for potential termination later.
            if (rsiPi.hProcess) CloseHandle(rsiPi.hProcess);
            if (rsiPi.hThread) CloseHandle(rsiPi.hThread);

            // 2. Wait for the User to Launch the Game
            // The user needs to interact with the RSI Launcher GUI, log in, and press the "Launch Game" button.
            std::wcout << L"\n[ACTION REQUIRED] Please log in via the RSI Launcher and launch Star Citizen." << std::endl;
            std::wcout << L"                 Waiting for '" << GAME_PROCESS_NAME << L"' process to appear (Timeout approx. 10 minutes)..." << std::endl;

            gamePid = 0; // Reset game PID for polling
            int wait_cycles = 0;
            const int max_wait_cycles = 300; // Approx. 10 minutes (300 cycles * 2 seconds/cycle)

            while (gamePid == 0 && wait_cycles < max_wait_cycles) {
                gamePid = GetProcessID(GAME_PROCESS_NAME); // Check if the game process exists now
                if (gamePid == 0) {
                    // Game not found yet, check if the RSI Launcher is still running
                    DWORD launcherExitCode = STILL_ACTIVE;
                    HANDLE hCheckLauncher = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, launcherPid);
                    // If we can't check launcher status OR it's confirmed exited...
                    if (hCheckLauncher == NULL || !GetExitCodeProcess(hCheckLauncher, &launcherExitCode) || launcherExitCode != STILL_ACTIVE) {
                        std::wcerr << L"[ERROR] RSI Launcher process (PID: " << launcherPid << ") exited unexpectedly before the game was launched." << std::endl;
                        if (hCheckLauncher) CloseHandle(hCheckLauncher);
                        if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars before exiting
                        return 1; // Exit program
                    }
                    if (hCheckLauncher) CloseHandle(hCheckLauncher); // Close the check handle

                    // Wait for 2 seconds before polling again
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    wait_cycles++; // Increment wait cycle counter
                }
            } // End wait loop

            // Check if we timed out waiting for the game process
            if (gamePid == 0) {
                std::wcerr << L"[ERROR] Timed out waiting for " << GAME_PROCESS_NAME << L" to start via RSI Launcher." << std::endl;
                // Terminate the launcher if it's still running
                if (launcherPid != 0) TerminateProcessByPid(launcherPid, RSI_LAUNCHER_EXE);
                if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars before exiting
                return 1; // Exit on timeout
            }

            // Game process has been detected!
            std::wcout << L"[INFO] Game detected (PID: " << gamePid << ") launched via RSI Launcher." << std::endl;
            // Proceed directly to Phase 2 (Injection).
        } // End Mode Selection (if/else)


         // --- Phase 2: Inject DLLs ---
         // This phase executes if gamePid was successfully obtained in Phase 1 (from either launch path).
        if (gamePid != 0) {
            // Perform a final check: Is the game process *still* running right before we inject?
            DWORD exitCodeCheckInject = STILL_ACTIVE;
            // Request necessary permissions for injection
            HANDLE hCheckInject = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, gamePid);

            if (hCheckInject != NULL && GetExitCodeProcess(hCheckInject, &exitCodeCheckInject) && exitCodeCheckInject == STILL_ACTIVE) {
                // Process is confirmed active, close the check handle and proceed with injection.
                // Note: We reuse hCheckInject for the actual injection if needed, or reopen with necessary rights in InjectDLL.
                // For simplicity here, let InjectDLL handle opening its own handle. Close the check handle.
                if (hCheckInject) CloseHandle(hCheckInject);
                hCheckInject = NULL; // Avoid double close later

                // === Perform Injection ===
                std::wcout << L"\n--- DLL Injection ---" << std::endl;

                // Optional: Wait a few seconds to let the game process initialize further before injecting.
                // std::wcout << L"[INFO] Waiting briefly before injection..." << std::endl;
                // std::this_thread::sleep_for(std::chrono::seconds(5));

                std::wcout << L"[INFO] Injecting specified DLLs into game process PID: " << gamePid << std::endl;

                bool allDllsInjected = true; // Assume success until a failure occurs

                // --- Inject Specified DLLs (in order) ---
                for (const auto& dllPath : injectDllsAbs) {
                    //std::wcout << L"       - Injecting: " << dllPath << std::endl;
                    if (!InjectDLL(gamePid, dllPath)) {
                        std::wcerr << L"[ERROR] Failed to inject DLL: " << dllPath << std::endl;
                        allDllsInjected = false; // Mark overall failure
                        // Optionally: break here if one failure should stop subsequent injections
                        // break;
                    }
                    //else {
                    //    std::wcout << L"       - Successfully injected: " << dllPath << std::endl;
                    //}
                    // Optional: Short delay between injections if needed by DLLs
                   // std::this_thread::sleep_for(std::chrono::seconds(1)); // Short delay example
                }

                // Determine overall injection success
                injectionFullySucceeded = allDllsInjected;

                // Check if all required injections were successful
                if (injectionFullySucceeded) {
                    std::wcout << L"[SUCCESS] All specified DLLs injected successfully." << std::endl;
                }
                else { // <<<< START OF BLOCK WHERE ERROR OCCURRED >>>>
                    // Handle injection failure
                    std::wcerr << L"[ERROR] One or more required DLL injections failed." << std::endl;

                    // Terminate the game process *only* if we launched it directly this run
                    if (launchedDirectly && piGame.hProcess) {
                        std::wcerr << L"        Terminating the launched game process due to injection failure." << std::endl;
                        TerminateProcessByPid(gamePid, GAME_PROCESS_NAME);
                    }
                    else {
                        std::wcerr << L"        Game process was launched via RSI Launcher or already running; not terminating it." << std::endl;
                        std::wcerr << L"        Manual intervention may be required to close the game." << std::endl;
                    }

                    // Ensure launcher is closed if it was used this run and injection failed
                    if (!launchedDirectly && launcherPid != 0) {
                        TerminateProcessByPid(launcherPid, RSI_LAUNCHER_EXE);
                    }
                    // Close game handles if we created them
                    if (piGame.hProcess) CloseHandle(piGame.hProcess);
                    if (piGame.hThread) CloseHandle(piGame.hThread);
                    clear_or_delete_file(loginDataPath);
                    // Clean up env vars before exiting
                    if (envVarsSetThisRun) CleanupEnvironmentVariables(false);
                    return 1; // Exit due to injection failure

                }
            }
            else {
                // Game process died between launch/detection and this injection attempt.
                std::wcerr << L"[ERROR] Game process (PID: " << gamePid << ") exited or became inaccessible before injection could occur." << std::endl;
                if (hCheckInject) CloseHandle(hCheckInject); // Close the check handle if it was opened
                // Clean up our direct launch handles if they exist
                if (piGame.hProcess) CloseHandle(piGame.hProcess);
                if (piGame.hThread) CloseHandle(piGame.hThread);
                // Clean up launcher path resources if necessary
                if (!launchedDirectly && launcherPid != 0) TerminateProcessByPid(launcherPid, RSI_LAUNCHER_EXE);
                clear_or_delete_file(loginDataPath);
                // Clean up environment variables before exiting
                if (envVarsSetThisRun) CleanupEnvironmentVariables(false);
                return 1; // Exit because game didn't stay running long enough
            }
        }
        else {
            // Control flow should not reach here if Phase 1 succeeded. Indicates a logic error or invalid PID.
            std::wcerr << L"[ERROR] Internal State Error: Game PID invalid before injection stage." << std::endl;
            // Attempt cleanup just in case handles were somehow set
            if (piGame.hProcess) CloseHandle(piGame.hProcess);
            if (piGame.hThread) CloseHandle(piGame.hThread);
            clear_or_delete_file(loginDataPath);
            // Clean up env vars if they were set
            if (envVarsSetThisRun) CleanupEnvironmentVariables(false);
            return 1;
        }

        // --- Phase 3: Post-Injection Launcher Tasks ---
        // This section only executes if the program used the RSI Launcher path *and* DLL injection succeeded.
        if (!launchedDirectly && injectionFullySucceeded) {
            std::wcout << L"\n--- Post-Injection Launcher Tasks ---" << std::endl;

            // Wait longer *after* injection to give the game (and potentially injected code)
            // ample time to perform login and write the loginData.json file.
            std::wcout << L"[INFO] Waiting after injection for login data file finalization (approx. 15 seconds)..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(15));

            // 3. Attempt to backup the loginData.json file now that the game should have created it.
            std::wcout << L"[INFO] Checking for login data file for backup..." << std::endl;
            if (file_exists(loginDataPath)) {
                std::wcout << L"[INFO] Found " << LOGIN_DATA_FILE << ". Attempting backup..." << std::endl;
                if (copy_file(loginDataPath, loginBackupPath)) {
                    backupCreatedThisRun = true; // Set flag indicating backup was successful this run
                    std::wcout << L"[INFO] Backup created successfully: " << loginBackupPath << std::endl;
                }
                else {
                    std::wcerr << L"[WARN] Failed to backup login data file. Check permissions/disk space." << std::endl;
                    // Continue without backup, but log warning.
                }
            }
            else {
                // Continue without backup.
                std::wcerr << L"[WARN] " << LOGIN_DATA_FILE << " not found after injection and waiting. Cannot create backup." << std::endl;
            }

            // 4. Terminate the RSI Launcher process now that the game is running and backup attempted.
            if (launcherPid != 0) {
                std::wcout << L"[INFO] Closing RSI Launcher (PID: " << launcherPid << ")..." << std::endl;
                if (!TerminateProcessByPid(launcherPid, RSI_LAUNCHER_EXE)) {
                    std::wcerr << L"[WARN] Failed to automatically close the RSI Launcher (may already be closed)." << std::endl;
                }
            }

            // Environment variables are NOT cleaned up here. They persist until the game exits or the injector restarts/fails.
            // Log whether the backup succeeded for user information.
            if (!backupCreatedThisRun) {
                std::wcout << L"[WARN] Completed Launcher Mode tasks, but login data backup was NOT created." << std::endl;
            }
            else {
                std::wcout << L"[INFO] Completed Launcher Mode tasks, including login data backup creation." << std::endl;
            }
        } // End post-injection launcher tasks


            // --- Phase 4: Monitoring & Waiting ---
            // This phase runs if the game process is valid (gamePid != 0) AND injection fully succeeded.
        if (gamePid != 0 && injectionFullySucceeded) {
            std::wcout << L"\n--- Game Monitoring & Waiting ---" << std::endl;

            // Start the log monitor thread ONLY if the game was launched directly (using backup)
            if (launchedDirectly) {
                std::wcout << L"[INFO] Starting log monitor (Direct Launch Mode active)." << std::endl;
                // Final check: ensure game process is still alive right before creating thread
                DWORD exitCodeMonitorCheck = STILL_ACTIVE;
                HANDLE hMonitorCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
                if (hMonitorCheck != NULL && GetExitCodeProcess(hMonitorCheck, &exitCodeMonitorCheck) && exitCodeMonitorCheck == STILL_ACTIVE) {
                    if (hMonitorCheck) CloseHandle(hMonitorCheck); // Close check handle
                    // Create and detach the monitoring thread to run concurrently
                    logMonitorThread = std::thread(MonitorLogFile, gameLogPath, gamePid);
                    // Check if thread creation succeeded
                    if (logMonitorThread.joinable()) {
                        logMonitorThread.detach(); // Detach the thread to let it run independently
                        std::wcout << L"[INFO] Log monitor thread started successfully." << std::endl;
                    }
                    else {
                        // Handle rare thread creation failure
                        std::wcerr << L"[ERROR] Failed to create log monitor thread!" << std::endl;
                        // If monitor fails, terminate game if we launched it, then clean up and exit program
                        if (piGame.hProcess) TerminateProcessByPid(gamePid, GAME_PROCESS_NAME);
                        clear_or_delete_file(loginDataPath);
                        if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up before exit
                        return 1;
                    }
                }
                else {
                    // Game died just before monitor thread could start
                    std::wcerr << L"[ERROR] Game process exited before log monitor thread could start." << std::endl;
                    if (hMonitorCheck) CloseHandle(hMonitorCheck);
                    // Clean up our direct launch handles if necessary
                    if (piGame.hProcess) CloseHandle(piGame.hProcess);
                    if (piGame.hThread) CloseHandle(piGame.hThread);
                    clear_or_delete_file(loginDataPath);
                    // Clean up environment variables before exiting
                    if (envVarsSetThisRun) CleanupEnvironmentVariables(false);
                    return 1; // Exit as game isn't running
                }
            }
            else {
                // Game was launched via RSI Launcher, no log monitoring is needed by this tool.
                std::wcout << L"[INFO] Log monitoring disabled (Launcher Mode active)." << std::endl;
            }

            // --- Main Wait Loop ---
            // Waits here until either the game process exits OR (if monitoring) a login failure is detected.
            std::wcout << L"[INFO] Waiting for game process (PID: " << gamePid << ") to exit..." << std::endl;
            std::wcout << L"       You may close this program manually if done, or wait for the game to close." << std::endl;
            while (true) {
                // === Check 1: Login Failure (only in Direct Launch mode) ===
                if (launchedDirectly && g_loginFailed) {
                    // Login failure detected by the monitor thread!
                    std::wcerr << L"\n[CRITICAL] Login failure detected in log" << std::endl;
                    std::wcerr << L"             Terminating game and deleting potentially invalid login data." << std::endl;
                    TerminateProcessByPid(gamePid, GAME_PROCESS_NAME); // Force close the game
                    // Clean up environment variables *before* restarting the loop
                    if (envVarsSetThisRun) CleanupEnvironmentVariables(false);
                    envVarsSetThisRun = false; // Mark as cleaned up before restart
                    clear_or_delete_file(loginBackupPath);             // Delete the problematic backup
                    clear_or_delete_file(loginDataPath);               // Delete the problematic current data
                    std::wcout << L"[INFO] Restarting process to use RSI Launcher mode in 5 seconds..." << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5)); // Pause before restarting
                    goto restart_main_loop; // Use goto to jump to the beginning of the outer while loop
                }

                // === Check 2: Game Process Exit ===
                DWORD exitCode = STILL_ACTIVE; // Assume running
                HANDLE hCheckWait = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
                // If handle is invalid OR GetExitCode fails OR exit code shows not running...
                if (hCheckWait == NULL || !GetExitCodeProcess(hCheckWait, &exitCode) || exitCode != STILL_ACTIVE) {
                    // Game has exited or become inaccessible.
                    std::wcout << L"\n[INFO] Game process (PID: " << gamePid << ") has exited ";
                    // Log exit code if available
                    if (exitCode != STILL_ACTIVE && hCheckWait != NULL) {
                        std::wcout << L"(Exit Code: " << exitCode << L")";
                    }
                    std::wcout << std::endl;
                    if (hCheckWait) CloseHandle(hCheckWait); // Close the check handle
                    break; // Exit the waiting loop, proceed to post-game cleanup
                }
                // Close the check handle if the process is still running
                if (hCheckWait) CloseHandle(hCheckWait);

                // Wait for a short interval before checking again to avoid busy-waiting
                std::this_thread::sleep_for(std::chrono::seconds(2));
            } // End of main wait loop (game exited normally)

        }
        else {
            // Should not be reachable if previous checks worked correctly (injection failed or bad PID)
            std::wcerr << L"[ERROR] Internal State Error: Reached monitoring stage unexpectedly (PID=" << gamePid << ", InjectionSuccess=" << injectionFullySucceeded << "). Exiting." << std::endl;
            // Cleanup just in case
            if (piGame.hProcess) CloseHandle(piGame.hProcess);
            if (piGame.hThread) CloseHandle(piGame.hThread);
            clear_or_delete_file(loginDataPath);
            if (envVarsSetThisRun) CleanupEnvironmentVariables(false); // Clean up env vars
            return 1;
        }

        // Delete the current loginData.json file. This ensures that if the backup exists,
        // the next run will use the direct launch path. If backup doesn't exist, this has no effect.
        std::wcout << L"[INFO] Deleting current login data file (if exists): " << loginDataPath << std::endl;
        clear_or_delete_file(loginDataPath);

        // --- Phase 5: Post-Game Exit Cleanup ---
        // This code executes after the main wait loop breaks, meaning the game process has terminated normally.
        // Perform final cleanup actions before the injector program exits.
        if (envVarsSetThisRun) CleanupEnvironmentVariables(true); // Perform FINAL cleanup (only if they were set this run)


        // Clean up game process handles IF we were the ones who launched it directly in this iteration.
        // Closing NULL handles is safe.
        if (piGame.hProcess) CloseHandle(piGame.hProcess);
        if (piGame.hThread) CloseHandle(piGame.hThread);

        // Normal program termination point
        std::wcout << L"[INFO] Program finished normally after game exit." << std::endl;
        return 0; // Exit the application successfully

        // --- Restart Label ---
        // This label is the target for the 'goto' statement used when a login failure occurs
        // during direct launch mode, forcing a restart of the main application loop.
    restart_main_loop:;
        // --- Cleanup Before Restarting Loop ---
        // Ensure process handles are closed before the next iteration starts.
        if (piGame.hProcess) CloseHandle(piGame.hProcess);
        if (piGame.hThread) CloseHandle(piGame.hThread);
        // Note: The detached logMonitorThread will exit on its own when it detects the game process is gone or finds an error/success.
        // Note: Environment variables were cleaned up *before* the goto jump.

        // Print message indicating the restart reason
        std::wcout << L"\n-----------------------------------------" << std::endl;
        std::wcout << L"Restarting main process loop due to login failure..." << std::endl;
        std::wcout << L"-----------------------------------------\n" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Brief pause before the next loop iteration

    } // End while(true) - Main Application Loop

        // This point should technically not be reached due to exit conditions within the loop.
    return 0;
}