# Process Hollowing
Process Hollowing involves the execution of custom arbitrary code within the memory space of a legitimate process

## How it works
- The target process is created with the suspended flag
- PBI is acquired using NtQueryInformationProcess
- Memory gets allocated for the new image base (RWX gets picked up by defender)
- Original code is unmapped
- Shellcode is written to the allocated memory space
- Image base is rewritten to the new image base at [PBI + 0x10](https://www.nirsoft.net/kernel_struct/vista/PEB.html)
- A new thread is created at entry point
- Execution is resumed so everything is ran in the context of the legit process
- Clean up

## Usage
#### x64
- Clone the repo
- Put your PE shellcode into the shellcode buffer in `hdr/shellcode.h`
- Build in `Release | x64`

#### x86
- Clone the repo and hardcode your shellcode in `hdr/shellcode.h`
- You can get the shellcode using the provided shellcode converter
- If you wish to merge these 2 solutions, go ahead and open a pull request

## Resources
- If you wish to learn more about this technique you should check these out:
    - [What is process hollowing by bmdyy](https://www.youtube.com/watch?v=aQQT-nYoiJo)
    - [Malware Theory - Process Injection by MalwareAnalysisForHedgehogs](https://www.youtube.com/watch?v=tBR1-1J5Jec)

## Need help?
You can find my Discord [here](https://hellokittyfan48.github.io/)

### Note
- Subsystems of both executables should be matching
- ~If you tweak this enough it will bypass most UM anticheats~
- This is for EDUCATIONAL PURPOSES ONLY

#### Leave a 🌟 if you like it <3
