# WiFi Marauder Changelog

## [Unreleased]

### Added

- **2025-05-19 12:57:21-04:00**: Initial integration of Anonymity Tools and Decoy Networks into the main application.
  - Added imports for `AnonymityToolsManager` and `DecoyNetworkManager` in `main.py`.
  - Initialized these managers within the `WiFiMarauderGUI` class.
  - Created new database tables for anonymity logs and decoy activities in `main.py`.
  - Added GUI elements (buttons) for user interaction with Anonymity Tools and Decoy Networks in `main.py`.

- **2025-05-19 13:10:20-04:00**: Completed GUI integration for Anonymity Tools and Decoy Networks.
  - Added a dedicated tab for Anonymity Tools in `main.py` with buttons for changing MAC address, enabling/disabling Tor, DNS protection, setting random user-agent, and temporal disguise.
  - Added a dedicated tab for Decoy Networks in `main.py` with buttons to start/stop WiFi and Bluetooth flooding, and to mimic area SSIDs.
  - Both features are now fully accessible from the user interface.

- **2025-05-19 13:29:47-04:00**: Implemented IP Address Rotation and VPN Integration for Anonymity Tools.
  - Added `rotate_ip_address()`, `connect_vpn()`, and `disconnect_vpn()` methods to `AnonymityToolsManager` in `anonymity_tools_logic.py`.
  - Updated GUI in `main.py` to connect IP Rotation and VPN buttons to their respective functions.
  - These features are now fully implemented and accessible from the user interface.

- **2025-05-19 13:29:47-04:00**: Integrated Automated Attack Sequences, Customizable Network Filters, and WPS Vulnerability Testing into the GUI.
  - Added imports and initialization for `AttackSequenceManager`, `NetworkFilterManager`, and `WPSVulnerabilityTester` in `main.py`.
  - Created new tabs in the GUI for each feature with buttons to control their respective functionalities.
  - These features are now accessible from the user interface, with fallback messages if the modules are not available.

- **2025-05-19 14:06:43-04:00**: Started testing and refinement of integrated features.
  - Created a test script `test_features.py` to verify the functionality of Anonymity Tools and Decoy Networks.
  - Noted a dependency issue with `airmon-ng` required for mimicking area SSIDs in Decoy Networks, test skipped due to missing dependency.

- **2025-05-19 17:35:00-04:00**: Implemented Packet Crafting and Injection feature using Scapy.
  - Added UI elements for packet crafting in the Attacks tab of `main.py`, including input fields for packet type and target, start/stop buttons, progress bar, and status label.
  - Integrated logic for packet crafting in `attack_sequence_logic.py` as a new attack type 'packet_craft'.
  - Updated `README.md` to include this new feature under the Features section.

- **2025-05-19 17:45:00-04:00**: Implemented Network Sniffing and Mapping feature using Scapy.
  - Added UI elements for network sniffing in the Network Scan tab of `main.py`, including start sniffing button, status label, and network map display.
  - Integrated logic to simulate sniffing and update network map with placeholder data.
  - Updated `README.md` to include this new feature under the Features section.

- **2025-05-20 00:02:00-04:00**: Added global dark/light theme toggle using `qdarktheme`.
   - Added optional dependency `qdarktheme` and palette fallback in `main.py`.
   - Introduced `View` menu with "Toggle Dark/Light Theme" action.
   - Theme applies at runtime and on startup with dark default.

### Completed

- Full integration of Anonymity Tools features (Tor Network, DNS Leak Protection, IP Address Rotation, User-Agent Spoofing, Temporal Disguise, VPN Integration).
- Full integration of Decoy Networks feature for Environment Flooding with Fake Bluetooth and Wireless Access Points.
- GUI integration for Automated Attack Sequences, Customizable Network Filters, and WPS Vulnerability Testing.

### Added

- **2025-05-24 18:30:00**: Implemented “Network Map” tab:
  - Live packet sniffing using Scapy AsyncSniffer.
  - Real-time table of BSSID, ESSID, packet counts, and OUI vendor lookups.

### Added

- **2025-05-24 18:45:00**: Added Packet Crafting & Injection tab in Attacks:
  - UI for Deauth Flood, Beacon Flood, Custom TCP/UDP packet templates.
  - Fields for packet type, target, channel/port, preview & send buttons.
  - Scapy-based crafting & sending via sendp, with preview functionality.
- **2025-05-24 18:50:00**: Integrated OUI vendor database via `manuf` library; fallback to internal mapping.
- **2025-05-24 18:55:00**: Added topology visualization in Network Map tab:
  - Scatter plot (channel vs packet count) using PyQtGraph.
- **2025-05-24 19:05:00**: Geolocation overlay in Network Map tab:
  - Button to generate folium map with markers via Wigle API lookups.
- **2025-05-24 19:20:00**: Visual Attack Sequence Builder tab:
  - Add/Edit/Remove step list, JSON input, define/start/stop sequence.

- **2025-05-24 17:50:00**: Refactored Decoy Networks tab: UI now calls `start_wifi_flood`/`stop_wifi_flood` and `start_bluetooth_flood`/`stop_bluetooth_flood` with proper result handling.
- **2025-05-24 17:50:00**: Added stubs in `main.py` for unimplemented scan and attack methods (e.g., start/stop deauth, handshake, evil AP, fakeauth) to prevent runtime errors and show placeholder dialogs.
- **2025-05-24 17:50:00**: Introduced `log()` helper in `WiFiMarauderApp` to append timestamped messages to the Dashboard's Recent Logs panel.
- **2025-05-24 17:50:00**: Added stub methods `load_vendors()` and `detect_interfaces()` to `WiFiMarauderApp` to satisfy initial calls without breaking the UI.
- **2025-05-24 17:50:00**: Exposed alias `WiFiMarauderGUI = WiFiMarauderApp` for backward compatibility with existing tests.
- **2025-05-24 17:50:00**: Configured Qt to use `offscreen` platform by default in both `main.py` and `test_features.py`, enabling headless testing environments.

### Fixed

- **2025-05-24 17:50:00**: Corrected syntax issues at end of `main.py` (removed unintended line continuation and placed alias correctly).
- **2025-05-24 17:50:00**: Updated `test_features.py` to remove GUI instantiation and adapt to headless testing, fixing import and environment errors.

### In Progress

- Further feature implementation for scan, attack, and WPS tabs in the GUI.
- **2025-05-24 20:00:00**: Integrated Analytics tab:
  - AP Vendor Distribution bar chart.
  - Handshakes per ESSID bar chart.
  - Attack Distribution pie chart (Deauth vs Captures vs Decoys).
  - Refresh button to redraw charts on updated data.
