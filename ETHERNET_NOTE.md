# Ethernet Connection Notes

## Does Ethernet vs WiFi Matter?

**Short answer: No, it doesn't change device discovery from Pi-hole!**

## How Device Discovery Works

### 1. Pi-hole Device Discovery (Primary Method)
- **Works the same on Ethernet or WiFi**
- Pi-hole tracks ALL DNS queries from ALL devices on your network
- The tool reads from Pi-hole's database (`/etc/pihole/pihole-FTL.db`)
- This works regardless of how your server is connected
- **This is the most reliable method and should find all devices making DNS queries**

### 2. Network Scanning (Secondary Method)
- Uses nmap to scan your network
- Automatically detects your network interface (eth0, enp0s3, wlan0, etc.)
- Works on both Ethernet and WiFi
- May find devices that haven't made DNS queries yet
- **Ethernet connection might actually work better** for network scanning since it's more stable

## Network Interface Detection

The tool automatically detects your network interface:
- **Ethernet**: Usually `eth0`, `enp0s3`, `eno1`, `ens33`, etc.
- **WiFi**: Usually `wlan0`, `wlp2s0`, etc.

The code uses `netifaces` to find the default gateway interface, so it should work automatically.

## Advantages of Ethernet

1. **More stable connection** - Better for continuous monitoring
2. **Lower latency** - Faster network scanning
3. **No WiFi interference** - More reliable packet capture (if not using Pi-hole)
4. **Better for servers** - Ethernet is standard for server deployments

## What You Should See

With Pi-hole, you should see:
- **All devices that have made DNS queries** - This is the main source
- **Devices found by network scan** - Additional devices that might not have queried DNS yet

## If You're Only Seeing 2 Devices

1. **Check Pi-hole logs** - Make sure devices are actually using Pi-hole for DNS
2. **Check service logs**:
   ```bash
   sudo journalctl -u network-monitoring -f | grep -i "sync\|device"
   ```
3. **Verify Pi-hole is seeing queries**:
   ```bash
   sudo sqlite3 /etc/pihole/pihole-FTL.db "SELECT DISTINCT client FROM queries WHERE client != '' LIMIT 20;"
   ```
4. **Try the "Scan Network" button** in the web interface

## Network Configuration

Your server should be on the same network segment as the devices you want to monitor. If your network has VLANs or subnets, you'll only see devices on the same subnet.

## Summary

**Ethernet connection is actually better for this tool!** It doesn't change how Pi-hole device discovery works, and network scanning might work even better. The tool should automatically detect your Ethernet interface and work correctly.

