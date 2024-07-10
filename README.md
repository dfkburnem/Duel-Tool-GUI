# Duel Tool GUI

This project provides a GUI for automating duels in DeFi Kingdoms. It allows users to configure duel settings which are saved and queue up multiple teams for dueling, automating matchmaking, entering duel lobby and complete duels transactions. Additionally, the tool allows users to specify a duel limit for each session and can facilitate challenging the champion by optimizing queueing for the minimum win streak.

## Installation

You can install the package directly from the releases.

### Source Code

1. To install the package, run:

```bash
pip install https://github.com/dfkburnem/Duel-Tool-GUI/releases/download/v2.0.0/duel_app_gui-2.0.0.tar.gz
```
2. Run script using:

```bash
duel_app_gui
```

### Executable

Download the executable from the releases page and run it directly:

1. Go to the [releases page](https://github.com/dfkburnem/Duel-Tool-GUI/releases).
2. Download the executable file (Duel App GUI.exe).
3. Run the executable.

## Usage

1. **Select Duel Type**: Choose the type of duel you want to participate in (solo, squad, pack, warr).
2. **Optional: Select Saved Team**: Use the arrow buttons to find previously used teams.
3. **Select Stat and Background**: Select the primary stat and background for the duel.
4. **Specify Hero IDs**: Enter the IDs of the heroes you want to use in the duel.
5. **Select Entry Fee**: Choose the entry fee for the duel.
6. **Select Realm**: Choose the realm (Crystalvale or Serendale).
7. **Set Duel Limit**: Specify the number of duels to be performed.
8. **Enter Password**: Provide the password to decrypt your private key.
9. **Add to Queue**: Click the appropriate button to add selected team to the queue.
10. **Start Queue**: Start the dueling process for listed teams.

## Important Notes

- **Reference Files**: Ensure that the `duel_config.json`, `duel_abi.json` and .key files are located in the same directory from which the script or executable is run.
- **Executable vs Script**: While the executable provides an easier way to run the application, it is not as trustless as running the script directly from the source code. If security and transparency are priorities, consider using the script.

## Tip Address

If you find this tool useful and would like to provide a tip/gift for my efforts, you can send it to the following address:

**Tip Address:** 0xF3b3b68B554817185A01576E775dB4466E42F126

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
