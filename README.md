# Star Citizen CVar Utility & Injector
[![Language](https://img.shields.io/badge/language-C%2B%2B-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-brightgreen.svg)](https://www.microsoft.com/windows/)
[![IDE](https://img.shields.io/badge/IDE-Visual%20Studio%202022-purple.svg)](https://visualstudio.microsoft.com/)

## Overview and Features
This project provides the source code for a DLL to interact with Star Citizen's CVar system in-game, along with an injector application (`Injector.exe`) that manages automatic launching of the game and injecting DLLs into it's process.


*   **Injector (`Injector.exe`):**    
    
    *Handles the controlled launch sequence of Star Citizen, along with the subsequent loading of the Minhook and CVar Utility DLL into the game process. This tool is not required to inject the DLLs as any basic injector can be used.*

    *   Launches Star Citizen directly (using backed-up login data) or via the RSI Launcher.
    *   Manages `loginData.json` backup/restore for automatically launching `StarCitizen.exe`, bypassing the RSI Launcher.
    *   Automatically injects `dllmain.dll` and `minhook.x64.dll` upon game start.
    *   Handles potential login failures in direct launch mode by restarting via the launcher.
    
    *   Configurable paths via command-line arguments.

*   **CVar Utility DLL (`dllmain.dll`):**
    
    *Once loaded by an injector, this DLL provides the interactive console and functions for inspecting and modifying CVars during gameplay.*
    
    *   Provides an interactive console window accessible via hotkeys.
    
    *   Get/Set CVar values and flags.
    
    *   Dumps CVars to console or file (Text/JSON).
    
    *   Load CVars into game from a JSON file.

## Prerequisites

*   Windows 10/11 (x64)

*   Visual Studio 2022 with C++ Desktop Development workload.

*   Star Citizen installed.

## Building

1.  Clone the repository.

2.  Open the `.sln` file in Visual Studio 2022.

3.  Select `Release` and `x64` configuration.

4.  Build the solution (`Build > Build Solution` or `Ctrl+Shift+B`). 

5.  When done, the output files (`Injector.exe`, `dllmain.dll`, and `minhook.x64.dll` ) should be located in the `x64/Release/` directory.

## Injector Usage
1.  Ensure `Injector.exe`, `dllmain.dll`, and `minhook.x64.dll` are in the same directory.

2.  Run `Injector.exe`. It may request Administrator privileges for environment variable setup.

*   <details>
    <summary>Command-Line Arguments (Optional)</summary>

    *   **`-h, --help`**
        *   Show the help message and exit.
    
    *   **`--gameDir <path>`**
        *   Specify the path to the Star Citizen installation directory
    
        *   (e.g., `"C:\Program Files\Roberts Space Industries\StarCitizen\LIVE"`).
    
    *   **`--launcherDir <path>`**
        *   Specify the path to the RSI Launcher installation directory.
    
    *   **`--minhookPath <path>`**
        *   Specify the path (relative or absolute) to the MinHook DLL (e.g., `minhook.x64.dll`).
    
        *   This is typically required by the main DLL.
    
    *   **`--mainDLLPath <path>`**
        *   Specify the path (relative or absolute) to the primary DLL to inject (e.g., `MyMod.dll`).
    
    *   **`--gameArgs "<arguments>"`**
        *   Specify the command-line arguments to use when launching `StarCitizen.exe` directly.
        
        *   Enclose the entire argument string in double quotes if it contains spaces.

    * **Example:**
        ```bash
        Injector.exe --gameDir "D:\Games\StarCitizen\LIVE" --mainDLLPath "SC_CVar_Utility.dll"
        ```
    </details>

*   <details>
    <summary>Launch Behavior</summary>

    *   **If `loginData_backup.json` is *not* found** in the game directory:
        *   The RSI Launcher will start.
   
        *   **Action Required:** Log in and launch the game via the launcher. This generates a fresh `loginData.json`.
   
        *   The injector detects the game process, injects the DLLs, attempts to create `loginData_backup.json` from the generated `loginData.json`, and closes the launcher.
   
    *   **If `loginData_backup.json` *is* found:**
        *   The injector restores the login data by copying `loginData_backup.json` to `loginData.json`.
        *   `StarCitizen.exe` is launched directly, bypassing the launcher.
   
        *   The injector injects the DLLs.
   
        *   (In this mode, the injector also monitors `Game.log` for login errors).
    </details>

*   <details>
    <summary>Why is `loginData_backup.json` needed?</summary>

    *   `StarCitizen.exe` requires a valid `loginData.json` file in its directory to authenticate and launch successfully. However, the game automatically deletes `loginData.json` upon closing.
   
    *   To enable direct launch (bypassing the RSI Launcher), the injector creates a backup (`loginData_backup.json`) after the game is launched via the RSI Launcher.
   
    *   On subsequent runs, if the backup exists, the injector restores it as `loginData.json` before starting `StarCitizen.exe`, providing the necessary authentication data. Thus allowing the game to run.
    </details>

## DLL Console Usage

Once the DLL is injected, its console window will appear. You can interact with it using these hotkeys:
*   **`F1` - Set CVar:** Prompts for a CVar name and a new value to assign.

*   **`F2` - Get CVar:** Prompts for a CVar name and displays its current value and flags.

*   **`F3` - Dump CVars:** Dumps CVar information to the console, with options to save to a Text or JSON file.

*   **`F4` - Load CVars:** Loads and applies CVars from a JSON file.

*   **`F5` - Show Menu:** Shows the hotkey menu.

*   **`END` - Unload DLL:** Safely unloads the DLL from the game.

*   <details>
    <summary><b>JSON Format for Loading CVars (F4)</b></summary>
    
    When using the `F4` Load CVars function, the selected JSON file must adhere to the following structure:
    *   The root element must be a JSON array `[...]`.
    
    *   Each element within the array must be a JSON object `{...}`.
    
    *   Each object *must* contain the following key-value pairs:
        *   `"cVarName"`: A string representing the name of the console variable.
    
        *   `"value"`: A string representing the desired value to set for the CVar.
    
    *   Each object *can optionally* contain:
        *   `"flags"`: An array of strings representing the CVar's flags (e.g., `["VF_CHEAT"]`). This key is currently ignored by the loading function but can be included for informational purposes or if generated by the Dump (F3) function.

    * **Example `CVars.json`:**

        ```json
        [
          {
            "cVarName": "p_rigid_gforce_scale",
            "value": "0.5",
            "flags": ["VF_CHEAT"]
          },
          {
            "cVarName": "p_fly_mode",
            "value": "0"
          },
          {
            "cVarName": "v_qdrive.instant_qt",
            "value": "0",
            "flags": []
          },
          {
            "cVarName": "r_DisplayInfo",
            "value": "3"
          }
        ]
        ```
    </details>
## Dependencies

*   [MinHook](https://github.com/TsudaKageyu/minhook) (Included in `./libs/`)
*   [nlohmann/json](https://github.com/nlohmann/json) (Included in `./libs/`)

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.