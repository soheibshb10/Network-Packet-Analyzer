import wmi

def list_interfaces():
    c = wmi.WMI()
    for interface in c.Win32_NetworkAdapter():
        print(f"Name: {interface.Name}")
        print(f"  GUID: {interface.PNPDeviceID}")

if __name__ == "__main__":
    list_interfaces()
