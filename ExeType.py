#! python3

# 2014, cuzi, https://github.com/cvzi/Python/tree/master/ExeType

def detectExeType(filepath,debug=False):
  # Detect whether a windows executable is a console or GUI application (or something entirely different)
  # Returns a string on success or False if the file is not an executable or an error occurred.
  
  if debug:
    def showbytes(a):
      print("Number: %d, String: %s, Length: %d" % (int.from_bytes(a,"little"),a,len(a)))
    show = print
  else:
    def showbytes(a):
      return
    def show(s):
      return
  
  chunksize = 1024
  l = {
  'IMAGE_DOS_SIGNATURE' : b'MZ', # Expected value
  'e_lfanew_offset' : 60, # Offset from file beginning
  'e_lfanew' : 4, # Length (in bytes) of this value
  'NTSignature' : 2, # Length (in bytes) of this value
  'IMAGE_NT_SIGNATURE' : b'PE', # Expected value
  'IMAGE_OPTIONAL_HEADER_subsystem_offset' : 92, # Offset from e_lfanew
  }
  IMAGE_SUBSYSTEM = {
  1: 'IMAGE_SUBSYSTEM_NATIVE',
  2: 'IMAGE_SUBSYSTEM_WINDOWS_GUI',
  3: 'IMAGE_SUBSYSTEM_WINDOWS_CUI', 
  5: 'IMAGE_SUBSYSTEM_OS2_CUI', 
  7: 'IMAGE_SUBSYSTEM_POSIX_CUI',
  8: 'IMAGE_SUBSYSTEM_NATIVE_WINDOWS',
  9: 'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',
  10: 'IMAGE_SUBSYSTEM_EFI_APPLICATION',
  11: 'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',
  12: 'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',
  13: 'IMAGE_SUBSYSTEM_EFI_ROM',
  14: 'IMAGE_SUBSYSTEM_XBOX',
  16: 'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION'
  }

  def cache(data=False, minimal=False):
    # Read minimal bytes and append to data, return data
    if minimal and minimal > chunksize:
      size = chunksize*(int(minimal/chunksize)+1)
    else:
      size = chunksize
    b = f.read(size)
    if len(b) == 0:
      show("End of file reached")
      return data
    if data:
      data += b
      return data
    return b    

  show("Opening file: %s" % filepath)
  with open(filepath,'rb') as f:
    data = cache()
    if len(data) < l['e_lfanew_offset']+1:
      show("Could not read file i.e. file is too small!")
      return False

    if data[0:2] != l['IMAGE_DOS_SIGNATURE']:
      show("No DOS signature found:") # Probably file is not an executable
      showbytes(data[0:2])
      return False
    show("Found DOS signature!")
    
    show("Looking for lfanew pointer...")
    offset = l['e_lfanew_offset']
    
    e_lfanew_raw = data[offset:offset+l['e_lfanew']]
    e_lfanew = int.from_bytes(e_lfanew_raw,"little")
    show("Found: lfanew = %d" % e_lfanew)
    if e_lfanew == 0: # File is malformed.
      show("Invalid pointer!")
      return False

    offset = e_lfanew
    request = offset+l['NTSignature']
    if request > len(data):
      data = cache(data,request)
      if request > len(data):
        show("Reached End Of File. Requested: %d, Available: %d" % (request,len(data)))
        return False
    
    file_signature = data[offset:offset+l['NTSignature']]
    if file_signature != l['IMAGE_NT_SIGNATURE']:
      show("No NT signature found!")
      return False
    show("Found NT signature!")

    show("Looking for Subsystem...")
    
    offset = e_lfanew + l['IMAGE_OPTIONAL_HEADER_subsystem_offset']
    request = offset + 2
    if request > len(data):
      data = cache(data,request)
      if request > len(data):
        show("Reached End Of File. Requested: %d, Available: %d" % (request,len(data)))
        return False

    subsystem_raw = data[offset:offset+2]
    subsystem = int.from_bytes(subsystem_raw,"little")
    if subsystem in IMAGE_SUBSYSTEM:
      show("Found: subsystem = %d" % subsystem)
      return IMAGE_SUBSYSTEM[subsystem]
    else:
      show("Unkown value for Subsystem in NT_OPTIONAL_HEADER:")
      showbytes(subsystem_raw)
      return False

  
if __name__ == "__main__":
  usage = "Usage: python ExeType.py [--verbose] pathToYourFile.exe"
  import sys
  if len(sys.argv) == 3:
    if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":
      print(detectExeType(sys.argv[2], debug=True))
    else:
      print(usage)
  elif len(sys.argv) == 2:
    print(detectExeType(sys.argv[1]))
  else:
    print(usage)
  
  
