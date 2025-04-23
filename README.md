# Star Citizen CVar Utility & Injector
[![Language](https://img.shields.io/badge/language-C%2B%2B-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-brightgreen.svg)](https://www.microsoft.com/windows/)
[![IDE](https://img.shields.io/badge/IDE-Visual%20Studio%202022-purple.svg)](https://visualstudio.microsoft.com/)

## Overview and Features
This project provides the source code for a DLL to interact with Star Citizen's CVar system in-game, along with an injector application (`Injector.exe`) that manages automatic launching of the game and injecting DLLs into it's process.


* **Injector (`Injector.exe`):**    
    
    *Handles the controlled launch sequence of Star Citizen, along with the subsequent loading of the Minhook and CVar Utility DLL into the game process. This tool is not required to inject the DLLs as any basic injector can be used.*

    * Launches Star Citizen directly (using backed-up login data) or via the RSI Launcher.
    * Manages `loginData.json` backup/restore for automatically launching `StarCitizen.exe`, bypassing the RSI Launcher.
    * Automatically injects `dllmain.dll` and `minhook.x64.dll` upon game start.
    * Handles potential login failures in direct launch mode by restarting via the launcher.
    
    *   Configurable paths via command-line arguments.

*   **CVar Utility DLL (`dllmain.dll`):**
    
    *Once loaded by an injector, this DLL provides the interactive console and functions for inspecting and modifying CVars during gameplay.*
    
    * Provides an interactive console window accessible via hotkeys.
    
    * Get/Set CVar values and flags.
    
    * Dumps CVars to console or file (Text/JSON).
    
    * Load CVars into game from a JSON file.

## Prerequisites

* Windows 10/11 or Linux

    * For Windows:
        - Visual Studio 2022 with C++ Desktop Development workload.
    * For Linux:
        - See [Building](https://github.com/TheOneAndOnlySycorax/Star-Citizen-CVar-Utility#building) section

* Star Citizen installed.

* Easy Anti Cheat bypassed

## Building

- **Using Windows 10/11:**
    * Clone the repository.
    
    * Open the `.sln` file in Visual Studio 2022.
    
    * Select `Release` and `x64` configuration.
    
    * Build the solution (`Build > Build Solution` or `Ctrl+Shift+B`). 
    
    * When done, the output files (`Injector.exe`, `dllmain.dll`, and `minhook.x64.dll` ) should be located in the `x64/Release/` directory.

- **Using Linux (Debian based):**
    * ```bash
      git clone https://github.com/TheOneAndOnlySycorax/Star-Citizen-CVar-Utility.git
      cd Star-Citizen-CVar-Utility
      apt-get update
      apt-get install build-essential cmake gcc-mingw-w64 git ninja-build
      make
      ```

    * **Ensure that `gcc-mingw-w64` is on version 14+**

## Injector Usage
*Note: The Injector may request Administrator privileges for setting global environment variables which are used for bypassing Easy Anti-Cheat. It is unknown how long this method will last. **Therefore, it is highly recommended that Easy Anti-Cheat is bypassed using a secondary method BEFORE using the Injector.***

*   <details>
    <summary><b>Command-Line Interface</b></summary>
    <i>Note: All CLI arguments are optional. Default values will be used for any argument not specified.</i>

    *   **`-h, --help`**
        *   Show the help message and exit.
    
    *   **`-i, --inject <list>`**
        * Specifies a comma separated list of DLL paths to inject (relative or absolute). Paths with spaces might need internal quotes depending on the shell. 
        * If this is not provided then the default DLL path will be used (`./dllmain.dll`)
        * Example: `--inject Test.dll,../MyMod/Mod.dll,C:/Other/Tool.dll`                

    *   **`--gameDir <path>`**
        * Specifies the path to the Star Citizen installation directory.
        
    *   **`--launcherDir <path>`**
        *   Specifies the path to the RSI Launcher installation directory.
    
    *   **`--gameArgs "<arguments>"`** (Use only if you know what you are doing)
        * Specifies Star Citizen's command-line arguments to use when launching the game directly. The entire argument string must be enclosed in double quotes. 
        * If this option is not provided, the Injector will automatically determine the correct game arguments by parsing 'Settings.json' in the game's EastAntiCheat directory. This feature is useful for whenever the game is updated and it's version number changes.
        * If the automatic procedure fails, the Injector will instead use predefined default values.
        * ***You should only use this option if you know what you are doing, or if the automatic procedure fails AND the default values are outdated.***
        
    * **Example:**
            ```
            Injector.exe --gameDir "D:\Games\StarCitizen\LIVE" --inject Test.dll"
            ```
    </details>

*   <details>
    <summary><b>Launch Behavior</b></summary>

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
    <summary><b>Why is `loginData_backup.json` needed?</b></summary>

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