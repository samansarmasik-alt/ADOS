# Third-party components

Runtime uses the unmodified WinDivert 2.2.2-A x64 DLL and driver from the official release:
https://github.com/basil00/WinDivert/releases/tag/v2.2.2

WinDivert is distributed under LGPL v3. Its license is in
`vendor/windivert/LICENSE` and `dist/WinDivert-LICENSE.txt`; corresponding
source and build instructions are available in the linked upstream repository.
The application loads the DLL dynamically. Replacing or debugging the library
for purposes permitted by its license is not prohibited by this project.
After replacement, regenerate the local integrity manifest by rebuilding.

The developer-only compiler is Zig 0.15.2, downloaded from ziglang.org and
verified against the published SHA256. It is not needed to launch protection.
Training-only Python dependencies are listed separately and are not needed
to run the native application.
