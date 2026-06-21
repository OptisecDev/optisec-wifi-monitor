"""Static OUI vendor lookup table for key vendors with manuf library fallback."""

_OUI_TABLE = {
    # Apple
    "00:1E:C2": "Apple", "00:23:12": "Apple", "00:25:BC": "Apple",
    "00:17:F2": "Apple", "00:1C:B3": "Apple", "00:21:E9": "Apple",
    "00:26:B9": "Apple", "28:CF:E9": "Apple", "3C:D0:F8": "Apple",
    "40:A6:D9": "Apple", "44:2A:60": "Apple", "58:55:CA": "Apple",
    "60:03:08": "Apple", "6C:40:08": "Apple", "7C:F0:5F": "Apple",
    "90:27:E4": "Apple", "A4:5E:60": "Apple", "AC:CF:5C": "Apple",
    "B8:E8:56": "Apple", "BC:52:B7": "Apple", "CC:08:E0": "Apple",
    "D0:23:DB": "Apple", "F4:F1:5A": "Apple", "00:3E:E1": "Apple",
    "04:52:F3": "Apple", "08:66:98": "Apple", "0C:3E:9F": "Apple",
    "10:41:7F": "Apple", "18:20:32": "Apple", "1C:36:BB": "Apple",
    "20:78:F0": "Apple", "24:AB:81": "Apple", "34:08:BC": "Apple",
    # Samsung
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:13:77": "Samsung",
    "00:15:99": "Samsung", "00:16:32": "Samsung", "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung", "00:21:D2": "Samsung", "00:23:99": "Samsung",
    "00:26:37": "Samsung", "18:22:7E": "Samsung", "30:07:4D": "Samsung",
    "38:AA:3C": "Samsung", "50:01:BB": "Samsung", "50:F5:20": "Samsung",
    "60:6B:BD": "Samsung", "78:1F:DB": "Samsung", "8C:71:F8": "Samsung",
    "A0:07:98": "Samsung", "BC:20:A4": "Samsung", "C8:19:F7": "Samsung",
    "D0:22:BE": "Samsung", "E4:40:E2": "Samsung", "F4:42:8F": "Samsung",
    "08:D4:6A": "Samsung", "20:13:E0": "Samsung", "2C:AE:2B": "Samsung",
    "4C:BC:98": "Samsung", "70:F9:27": "Samsung", "84:25:DB": "Samsung",
    # Huawei
    "00:1E:10": "Huawei", "00:25:9E": "Huawei", "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei", "04:C0:6F": "Huawei", "08:19:A6": "Huawei",
    "10:1B:54": "Huawei", "14:B9:68": "Huawei", "18:C5:8A": "Huawei",
    "20:2B:C1": "Huawei", "24:09:95": "Huawei", "28:31:52": "Huawei",
    "2C:55:D3": "Huawei", "30:D1:7E": "Huawei", "34:6B:D3": "Huawei",
    "38:B1:DB": "Huawei", "3C:47:11": "Huawei", "40:4D:8E": "Huawei",
    "44:6A:2E": "Huawei", "48:00:31": "Huawei", "4C:1F:CC": "Huawei",
    "58:2A:F7": "Huawei", "6C:8D:C1": "Huawei", "70:72:3C": "Huawei",
    "78:1D:BA": "Huawei", "80:38:BC": "Huawei", "8C:0D:76": "Huawei",
    "90:67:1C": "Huawei", "9C:74:1A": "Huawei", "A8:CA:7B": "Huawei",
    "B4:CD:27": "Huawei", "C8:51:95": "Huawei", "D0:7A:B5": "Huawei",
    # Cisco
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:02:17": "Cisco",
    "00:03:6B": "Cisco", "00:04:9A": "Cisco", "00:06:7C": "Cisco",
    "00:0A:42": "Cisco", "00:0B:BE": "Cisco", "00:0C:85": "Cisco",
    "00:0D:29": "Cisco", "00:0E:38": "Cisco", "00:0F:8F": "Cisco",
    "00:13:1A": "Cisco", "00:14:A9": "Cisco", "00:16:47": "Cisco",
    "00:17:5A": "Cisco", "00:18:73": "Cisco", "00:1A:A1": "Cisco",
    "00:1B:54": "Cisco", "00:1C:57": "Cisco", "00:1D:45": "Cisco",
    "00:1E:7A": "Cisco", "00:1F:6C": "Cisco", "00:21:55": "Cisco",
    "00:22:55": "Cisco", "00:23:5E": "Cisco", "00:24:14": "Cisco",
    "00:25:83": "Cisco", "00:26:99": "Cisco", "00:27:0D": "Cisco",
    "2C:31:24": "Cisco", "3C:08:F6": "Cisco", "50:06:04": "Cisco",
    "70:69:5A": "Cisco", "84:B8:02": "Cisco", "A0:EC:F9": "Cisco",
    "B8:38:61": "Cisco", "D0:C7:89": "Cisco", "E4:AA:5D": "Cisco",
    # TP-Link
    "EC:75:0C": "TP-Link",
    "00:14:78": "TP-Link", "00:23:CD": "TP-Link", "04:95:E6": "TP-Link",
    "10:FE:ED": "TP-Link", "14:CF:92": "TP-Link", "18:A6:F7": "TP-Link",
    "1C:FA:68": "TP-Link", "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link",
    "54:E6:FC": "TP-Link", "60:32:B1": "TP-Link", "74:DA:38": "TP-Link",
    "78:A1:06": "TP-Link", "84:16:F9": "TP-Link", "90:F6:52": "TP-Link",
    "98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link", "B0:BE:76": "TP-Link",
    "C0:4A:00": "TP-Link", "D8:0D:17": "TP-Link", "DC:FE:18": "TP-Link",
    "E8:94:F6": "TP-Link", "EC:08:6B": "TP-Link", "F4:EC:38": "TP-Link",
    "00:27:19": "TP-Link", "08:95:2A": "TP-Link", "10:BF:48": "TP-Link",
    "1C:3B:F3": "TP-Link", "28:6C:07": "TP-Link", "2C:4D:54": "TP-Link",
    # Alfa Networks
    "00:C0:CA": "Alfa Networks", "00:02:6F": "Alfa Networks",
    "00:0C:E6": "Alfa Networks",
    # Intel
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:35": "Intel",
    "00:11:11": "Intel", "00:13:02": "Intel", "00:13:20": "Intel",
    "00:13:CE": "Intel", "00:13:E8": "Intel", "00:15:00": "Intel",
    "00:16:EA": "Intel", "00:16:EB": "Intel", "00:17:08": "Intel",
    "00:18:DE": "Intel", "00:19:D1": "Intel", "00:19:D2": "Intel",
    "00:1B:21": "Intel", "00:1C:BF": "Intel", "00:1E:64": "Intel",
    "00:1E:65": "Intel", "00:1F:3B": "Intel", "00:1F:3C": "Intel",
    "00:21:6A": "Intel", "00:21:6B": "Intel", "00:22:FA": "Intel",
    "00:22:FB": "Intel", "00:24:D7": "Intel", "00:26:C6": "Intel",
    "00:26:C7": "Intel", "5C:E0:C5": "Intel", "7C:5C:F8": "Intel",
    "8C:EC:4B": "Intel", "A4:34:D9": "Intel", "AC:FD:CE": "Intel",
    "B4:6B:FC": "Intel", "D4:BE:D9": "Intel", "F4:06:69": "Intel",
    "00:AA:01": "Intel", "00:AA:02": "Intel", "FC:F8:AE": "Intel",
}


def get_vendor_with_fallback(mac: str, manuf_parser=None) -> str:
    """Return vendor name, trying manuf library first then static OUI table."""
    if not mac:
        return "Unknown"

    if manuf_parser:
        try:
            result = manuf_parser.get_manuf(mac)
            if result:
                return result
        except Exception:
            pass

    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac_upper.split(":")
    if len(parts) < 3:
        return "Unknown"

    oui = ":".join(parts[:3])
    return _OUI_TABLE.get(oui, "Unknown")
