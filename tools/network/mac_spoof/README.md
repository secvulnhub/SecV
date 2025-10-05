# mac_spoof - SecV module

Automated MAC spoofer.

## Summary
- Randomizes last 3 octets of MAC while keeping prefix `02:00:00` (locally-administered).
- Launches one background runner per interface; each runner changes the MAC every 500 ms.
- Saves original MAC per interface to `/tmp/secv_mac_orig_<iface>.orig` and restores it on stop.

## Files
- `mac_spoof.sh` — main executable module (make executable).
- `module.json` — metadata and help for SecV.

## Usage (via SecV)
1. `secV > use mac_spoof`
2. Option 1 (single iface):
   - `secV (mac_spoof) > set iface eth0`
   - `secV (mac_spoof) > run target`
3. Option 2 (multiple ifaces):
   - `secV (mac_spoof) > set iface eth0,wlan0`
   - `secV (mac_spoof) > run target`
4. Option 3 (all currently UP interfaces):
   - `secV (mac_spoof) > set all_up true`
   - `secV (mac_spoof) > run target`
5. Stop:
   - `secV (mac_spoof) > set iface eth0` (or set all_up true)
   - `secV (mac_spoof) > set action stop`
   - `secV (mac_spoof) > run target`
6. Status:
   - `secV (mac_spoof) > set action status`
   - `secV (mac_spoof) > run target`

## Notes & Warnings
- Requires `ip` (iproute2) and root for actual changes.
- Rapid MAC changes will break active network sessions and may destabilize some drivers — test safely.
- Each interface spoofer runs independently; stopping restores the last saved original MAC for that interface.
