# FlashPrint Proxy

This tool acts as a proxy between FlashPrint software and FlashForge Explorer series 3D printers (e.g., Adventurer 3).

## Purpose

The primary goal of this script is to fix a usability flaw in the native firmware of these printers where files stored on the internal memory are listed in an unsorted order. This proxy intercepts the file list command (`M661`), sorts the filenames alphabetically, and sends the reordered list back to FlashPrint.

It also includes a discovery proxy, allowing FlashPrint to "find" the printer even though it is connecting through this script.

I honestly don't know why the flashprint software did this in the first place.

## Features

- **Alphabetical File Listing:** Automatically sorts `.g`, `.gx`, and other files on the printer's storage.
- **Auto-Discovery:** Can scan the network to find your printer automatically.
- **Transparent Proxying:** Forwards all other commands (temperature, movement, print status) transparently.

## Demonstration

**Before (Native Firmware):**
![Before Sorting](images/before.png)

**After (With Proxy):**
![After Sorting](images/after.png)

## Usage

### 1. Run the Proxy

You can run the script in two modes:

**Automatic Scan:**
Attempts to find the printer on your local network.
```bash
python main.py --scan
```

**Manual IP:**
Specify the printer's IP address directly.
```bash
python main.py --ip 192.168.1.50
```

### 2. Connect FlashPrint

1. Open FlashPrint.
2. Go to **Print** > **Connect Machine**.
3. Instead of the printer's IP, enter the **IP address of the computer running this script**.
   - The script listens on port `8899` (TCP).
4. Connect.

FlashPrint will now communicate through the proxy. When you view the file list on the machine, the files will be sorted alphabetically.