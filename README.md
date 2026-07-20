# FreeTether

Open-source hotspot sharing tool for jailbroken iOS devices.

## Features

- 🔒 **VPN Sharing** — Share VPN connection through Personal Hotspot
- 📶 **Wi-Fi Sharing** — Share Wi-Fi connection through Personal Hotspot
- 📱 **Hotspot Shortcut** — Quick access to Personal Hotspot settings (useful for Wi-Fi-only iPads)
- ⚙️ **Settings Panel** — Configure via Settings app
- 🎛️ **Control Center** — Quick toggle from Control Center
- 🔧 **CLI Tool** — `freetether-cli` for status and configuration

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
ssh root@<device_ip> "dpkg -i /var/mobile/com.freetether.tweak_*.deb && killall SpringBoard"
```

## Usage

### Settings
Open **Settings → FreeTether** to configure:
- Enable/Disable the tweak
- VPN Sharing
- Wi-Fi Sharing
- Open Personal Hotspot settings
- Debug logging

### Command Line
```bash
freetether-cli status              # Show current config
freetether-cli enable              # Enable FreeTether
freetether-cli disable             # Disable (kill switch)
freetether-cli set vpnSharing on   # Enable VPN sharing
freetether-cli set wifiSharing on  # Enable Wi-Fi sharing
freetether-cli debug on            # Enable debug logs
```

### Control Center
Add the FreeTether toggle in Settings → Control Center.

## Troubleshooting

### Sharing not working
1. Enable debug logging: `freetether-cli debug on`
2. Restart related daemons: `killall CommCenter MobileInternetSharing`
3. Check logs: `idevicesyslog | grep FreeTether` (from PC) or `log stream --predicate 'eventMessage CONTAINS "FreeTether"'` (on device)

### CommCenter crashes
1. Disable immediately: `freetether-cli disable`
2. If unable to SSH, reboot into safe mode (hold volume up during respring)
3. File an issue with crash logs

### Uninstalling
```bash
dpkg -r com.freetether.tweak
killall CommCenter MobileInternetSharing SpringBoard
```

## Development

### Running the Probe Tool
The probe tool dumps CommCenter internals for reverse engineering:
```bash
cd Probe && make clean package && cd ..
# Install probe, restart CommCenter, wait 5s
# Results: /var/tmp/FTProbe/
```

### Project Structure
- `Tweak/` — Main tweak (hooks CommCenter and MobileInternetSharing)
- `Preferences/` — Settings panel (PreferenceBundle)
- `CCModule/` — Control Center toggle
- `Tools/` — CLI utility (`freetether-cli`)
- `Probe/` — Development probe tool (not distributed)

## License

GPL-3.0. See [LICENSE](LICENSE).
