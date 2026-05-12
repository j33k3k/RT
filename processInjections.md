# Process injection techniques with SYSMON monitor
What Each Sysmon Event ID Catches:
- Event ID 8 CreateRemoteThread: Fires when a thread is created in another process. Catches: classic CRT, NtCreateThreadEx (sometimes), RtlCreateUserThread. Does NOT fire for APC injection since no thread is created — an existing thread is targeted.
- Event ID 10 ProcessAccess: Fires when a process opens a handle to another process with specific access rights (PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_CREATE_THREAD). This is your broadest net — virtually every injection technique requires a handle to the target process.
- Event ID 25 ProcessTampering: Fires specifically on image replacement or process hollowing — when the mapped image in memory no longer matches the file on disk. Catches: hollowing, module stomping, some reflective DLL variants.
<img width="942" height="712" alt="image" src="https://github.com/user-attachments/assets/65977293-a5d1-43cc-8dab-a8c0f33aa17d" />


