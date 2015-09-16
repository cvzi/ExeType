ExeType
=======

Detect whether a Windows executable file is a Console/Terminal application or a GUI application.

If an error occurs or the file is not an executable False is returned.

If the file is an executable, one of the following strings is returned:
 * IMAGE_SUBSYSTEM_NATIVE
 * IMAGE_SUBSYSTEM_WINDOWS_GUI
 * IMAGE_SUBSYSTEM_WINDOWS_CUI
 * IMAGE_SUBSYSTEM_OS2_CUI
 * IMAGE_SUBSYSTEM_POSIX_CUI
 * IMAGE_SUBSYSTEM_NATIVE_WINDOWS
 * IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
 * IMAGE_SUBSYSTEM_EFI_APPLICATION
 * IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
 * IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
 * IMAGE_SUBSYSTEM_EFI_ROM
 * IMAGE_SUBSYSTEM_XBOX
 * IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION

These were taken from [Windows Dev Center - IMAGE_OPTIONAL_HEADER structure](http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx) 


Requires:
 * Python 3

**Usage**: python ExeType.py [--verbose] pathToYourFile.exe
