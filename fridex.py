import os
import subprocess
import urllib.request

# ========= Helper ==========

def run_command(cmd, shell=True):
    """ Helper to run shell commands and print nicely """
    print(f"\n💻 Running: {cmd}")
    result = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print("⚠️", result.stderr.strip())
    return result.returncode == 0

def print_banner():
    print(r"""

      ___           ___                                     ___           ___      
     /\__\         /\  \                     _____         /\__\         /|  |     
    /:/ _/_       /::\  \       ___         /::\  \       /:/ _/_       |:|  |     
   /:/ /\__\     /:/\:\__\     /\__\       /:/\:\  \     /:/ /\__\      |:|  |     
  /:/ /:/  /    /:/ /:/  /    /:/__/      /:/  \:\__\   /:/ /:/ _/_   __|:|__|     
 /:/_/:/  /    /:/_/:/__/___ /::\  \     /:/__/ \:|__| /:/_/:/ /\__\ /::::\__\_____
 \:\/:/  /     \:\/:::::/  / \/\:\  \__  \:\  \ /:/  / \:\/:/ /:/  / ~~~~\::::/___/
  \::/__/       \::/~~/~~~~   ~~\:\/\__\  \:\  /:/  /   \::/_/:/  /      |:|~~|    
   \:\  \        \:\~~\          \::/  /   \:\/:/  /     \:\/:/  /       |:|  |    
    \:\__\        \:\__\         /:/  /     \::/  /       \::/  /        |:|__|    
     \/__/         \/__/         \/__/       \/__/         \/__/         |/__/     

             [💉 Frida Debug Assistant 💉]
    """)

def download_file(url, filename):
    print(f"⬇️ Downloading {filename} from:\n{url}")
    try:
        urllib.request.urlretrieve(url, filename)
        print(f"✅ Downloaded: {filename}")
    except Exception as e:
        print(f"❌ Download failed: {e}")
        exit(1)

# ========= Fix Functions ==========

def ios_no_frida_server():
    device_ip = input("📱 Enter iOS device IP address: ").strip()
    frida_url = "https://github.com/frida/frida/releases/download/16.7.9/frida_16.7.9_iphoneos-arm64.deb"
    frida_deb = frida_url.split("/")[-1]

    download_file(frida_url, frida_deb)

    print(f"\n📤 Uploading {frida_deb} to /tmp on iOS device...")
    run_command(f"scp {frida_deb} mobile@{device_ip}:/tmp/")

    print(f"\n🔐 Installing {frida_deb} remotely via SSH...")
    install_cmd = f"ssh mobile@{device_ip} 'dpkg -i /tmp/{frida_deb}'"
    run_command(install_cmd)

    print("✅ Frida installed successfully on iOS (if no error above).")

def android_ptrace_fix():
    print("\n🔧 Fixing Android ptrace error...")
    run_command("adb wait-for-device")
    run_command("adb shell su -c 'pm uninstall com.google.android.art'")
    print("✅ ptrace fix applied. Reboot device if needed.")

def android_java_bridge_fix():
    print("\n🔧 Fixing Android Java.perform / Java bridge issue...")
    run_command("adb wait-for-device")
    run_command("adb shell su -c 'pm uninstall com.google.android.art'")
    print("✅ Java bridge fix applied. Reboot device if needed.")

# ========= Menu ==========

def main():
    print_banner()
    print("\n🎯 Select an issue to auto-fix:\n")
    print("[1] iOS: No Frida Server")
    print("[2] Android: ptrace error")
    print("[3] Android: Java.perform / Java bridge not working")

    choice = input("\n🔢 Enter option number: ").strip()

    if choice == "1":
        ios_no_frida_server()
    elif choice == "2":
        android_ptrace_fix()
    elif choice == "3":
        android_java_bridge_fix()
    else:
        print("❌ Invalid option.")

if __name__ == "__main__":
    main()
