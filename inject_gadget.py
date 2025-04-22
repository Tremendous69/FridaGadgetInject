import os
import re
import lief
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from adb_shell.auth.keygen import keygen

def get_device(port, host):
    adb_device = AdbDeviceTcp(host, port)
    adbkey = "adbkey"
    if not os.path.isfile(adbkey):
        keygen(adbkey)
    with open(adbkey) as f:
        priv = f.read()
    with open(adbkey + '.pub') as f:
        pub = f.read()
    signer = PythonRSASigner(pub, priv)
    adb_device.connect(rsa_keys=[signer], auth_timeout_s=10)
    try:
        print("attempting to get root access")
        print(f"USER:{adb_device.shell('whoami')}")
    except Exception as e:
        print("failed to get root , run script again ? adb-shell bug??")
        return False
    return adb_device

def get_library_folder(adb_device, package_name):
    command = f'pm dump {package_name} | grep -i legacyNativeLibraryDir | awk -F "legacyNativeLibraryDir=" \'{{print $2}}\''
    result = adb_device.shell(command).strip()
    legacy_native_library_dir = result
    print(f"[*]Lib folder set to {legacy_native_library_dir}")
    command = f'pm dump {package_name} | grep -i primaryCpuAbi | awk -F "=" \'{{print $2}}\''
    result = adb_device.shell(command).strip()
    print(f"[*]arch set to {result}")
    arch = 'arm' if 'armeabi-v7a' in result else 'arm64'
    package_name = f"{legacy_native_library_dir}/{arch}"
    print(f"[*]full path to lib folder set to {package_name}")
    return package_name, arch

def inject_library(adb_device, package_name, gadget_file, target_lib, lib_config):
    lib_folder, arch = get_library_folder(adb_device, package_name)
    script_dir = os.path.dirname(os.path.realpath(__file__))
    pattern = fr'/data/app/.*{re.escape(package_name)}.*'
    if not re.search(pattern, lib_folder):
        print(f"failed to get path for package : {package_name} is it installed??")
        return
    lib_path = gadget_file
    lib_path_name = os.path.basename(lib_path)
    config_path_name = os.path.basename(lib_config)
    injected_lib = os.path.join(script_dir, target_lib)
    if os.path.exists(injected_lib):
        print("removing old lib", injected_lib)
        os.remove(injected_lib)
    print(rf'{lib_folder}/{target_lib}')
    adb_device.pull(rf'{lib_folder}/{target_lib}', injected_lib)
    print("writing", lib_path_name, injected_lib)
    binary = lief.parse(injected_lib)
    binary.add_library(lib_path_name)
    binary.write(injected_lib + package_name)
    injected_lib = injected_lib + package_name
    print(rf'making folder')
    adb_device.shell(f"mkdir /data/local/tmp/{package_name}")
    print(rf'pushing to tmp')
    adb_device.push(rf'{injected_lib}', rf'/data/local/tmp/{package_name}/{target_lib}')
    adb_device.push(lib_path, rf'/data/local/tmp/{package_name}/{lib_path_name}')
    adb_device.push(lib_config, rf'/data/local/tmp/{package_name}/{lib_path_name.replace(".so", ".config.so")}')
    adb_device.shell(f'chmod 777 -R "/data/local/tmp/{package_name}"')
    print('copying files using shell')
    print(adb_device.shell(f"su -c 'cp -rf /data/local/tmp/{package_name}/*.* {lib_folder}/'"))
    print("adb shell", f"""su -c "cp -rf '/data/local/tmp/{package_name}/*.*' '{lib_folder}/'" """)
    print("Done!")

def run_injection():
    package_name = entry_package.get()
    gadget_path = entry_gadget.get()
    target_lib = entry_target.get()
    lib_config = entry_config.get()
    if not os.path.isfile(gadget_path):
        messagebox.showerror("Error", "Gadget .so file not found.")
        return
    if not os.path.isfile(lib_config):
        messagebox.showerror("Error", "Config file not found.")
        return
    device = get_device(62001, '127.0.0.1')
    if device:
        inject_library(device, package_name, gadget_path, target_lib, lib_config)
    else:
        messagebox.showerror("Error", "Failed to connect to device.")

def browse_gadget():
    filename = filedialog.askopenfilename(filetypes=[("Shared Object", "*.so")])
    if filename:
        entry_gadget.delete(0, tk.END)
        entry_gadget.insert(0, filename)
        # Try to auto-fill the config path
        config_guess = filename.replace(".so", ".config.so")
        if os.path.exists(config_guess):
            entry_config.delete(0, tk.END)
            entry_config.insert(0, config_guess)

def browse_config():
    filename = filedialog.askopenfilename(filetypes=[("Config Files", "*.config")])
    if filename:
        entry_config.delete(0, tk.END)
        entry_config.insert(0, filename)

app = tk.Tk()
app.title("Frida Gadget Injector")

tk.Label(app, text="Package Name").grid(row=0, column=0, sticky="e")
entry_package = tk.Entry(app, width=50)
entry_package.grid(row=0, column=1, padx=5, pady=5)

tk.Label(app, text="Gadget .so File").grid(row=1, column=0, sticky="e")
entry_gadget = tk.Entry(app, width=50)
entry_gadget.grid(row=1, column=1, padx=5, pady=5)
tk.Button(app, text="Browse", command=browse_gadget).grid(row=1, column=2, padx=5)

tk.Label(app, text="Target Library").grid(row=2, column=0, sticky="e")
entry_target = tk.Entry(app, width=50)
entry_target.insert(0, "libmain.so")
entry_target.grid(row=2, column=1, padx=5, pady=5)

tk.Label(app, text="Gadget Config").grid(row=3, column=0, sticky="e")
entry_config = tk.Entry(app, width=50)
entry_config.grid(row=3, column=1, padx=5, pady=5)
tk.Button(app, text="Browse", command=browse_config).grid(row=3, column=2, padx=5)

tk.Button(app, text="Inject", command=run_injection).grid(row=4, column=1, pady=10)

app.mainloop()
