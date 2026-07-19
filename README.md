# FreeTether

Open-source personal hotspot unlocker for jailbroken iOS devices.

## Features

- 🔓 **Hotspot Unlock** — Bypass carrier restrictions on Personal Hotspot
- 🎭 **Traffic Masking** — Hotspot traffic uses data APN (carrier can't distinguish)
- ⚙️ **Settings Panel** — Configure via Settings app
- 📡 **APN Management** — Custom APN configuration
- 🔒 **VPN Sharing** — Share VPN connection through hotspot
- 📶 **Wi-Fi Sharing** — Share Wi-Fi connection through hotspot
- 🎛️ **Control Center** — Quick toggle from Control Center

## Requirements

- iPad 7 (A10) with iPadOS 18.x
- palera1n rootless jailbreak
- [Theos](https://theos.dev/) on macOS (for building)

## Building

```bash
# Set up environment
export THEOS=~/theos
export THEOS_PACKAGE_SCHEME=rootless

# Build
make clean package

# Build probe tool (development only)
cd Probe && make clean package && cd ..
```

## Installing

```bash
# Copy and install
scp packages/*.deb root@<device_ip>:/var/mobile/
ssh root@<device_ip> "dpkg -i /var/mobile/com.freetether.freetether_*.deb && killall SpringBoard"
```

## Usage

### Settings
Open **Settings → FreeTether** to configure:
- Enable/Disable the tweak
- Force hotspot, bypass carrier check, mask traffic
- Custom APN
- VPN/Wi-Fi sharing
- Debug logging

### Command Line
```bash
freetether-cli status    # Show current config
freetether-cli enable    # Enable FreeTether
freetether-cli disable   # Disable (kill switch)
freetether-cli debug on  # Enable debug logs
```

### Control Center
Add the FreeTether toggle in Settings → Control Center.

## Troubleshooting

### Hotspot option doesn't appear
1. Enable debug logging: `freetether-cli debug on`
2. Restart CommCenter: `killall CommCenter`
3. Check logs: `idevicesyslog | grep FreeTether` (from PC) or `log stream --predicate 'eventMessage CONTAINS "FreeTether"'` (on device)
4. Look for `[FreeTether][DBG][Carrier]` entries

### CommCenter crashes
1. Disable immediately: `freetether-cli disable`
2. If unable to SSH, reboot into safe mode (hold volume up during respring)
3. File an issue with crash logs

### Uninstalling
```bash
dpkg -r com.freetether.freetether
killall CommCenter SpringBoard
```

## Development

### Running the Probe Tool
The probe tool dumps CommCenter internals for reverse engineering:
```bash
cd Probe && make clean package && cd ..
# Install probe, restart CommCenter, wait 5s
# Results: /var/mobile/Documents/FTProbe/
```

### Project Structure
- `Tweak/` — Main tweak (hooks CommCenter, wifid, etc.)
- `Preferences/` — Settings panel (PreferenceBundle)
- `CCModule/` — Control Center toggle
- `Probe/` — Development probe tool (not distributed)
- `Tools/` — CLI utility

## License

GPL-3.0. See [LICENSE](LICENSE).
