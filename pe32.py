import sys

""" Code is organized in classes so variables of all headers and tables 
    could be accessed in other programs. Example: mz_header.number_of_pages """

class MZ_header:
    """ Class representing MZ (DOS) header of a Win32 PE """
    def __init__(self, path):
        with open(path, "rb") as input_pe:
            self.magic, self.bytes_on_last_page, self.number_of_pages, \
            self.relocations, self.size_in_paragarphs, self.min_extra_paragraphs, \
            self.max_extra_paragraphs, self.initial_ss, self.initial_sp, \
            self.checksum, self.initial_ip, self.initial_cs, self.offset_to_relocation,  \
            self.overlay_number = (input_pe.read(2) for i in range(0, 14))

            input_pe.seek(0x24)
            self.oem_identifier = input_pe.read(2)
            self.oem_information = input_pe.read(2)
            input_pe.seek(0x3C)
            self.offset_to_pe_header = input_pe.read(4)

    def print_data(self):
        print("\nMZ header (DOS): ", end="")
        print("{0:30s}  {1:#06x} ({2:s})".format(
              " Magic:", int.from_bytes(self.magic, byteorder="little"),
              self.magic.decode("ascii")))

        for name, value in {
            "Bytes on last page:" : self.bytes_on_last_page,
            "Number of pages:": self.number_of_pages,
            "Relocations:" : self.relocations,
            "Size of header in paragraphs:" : self.size_in_paragarphs,
            "Minimum extra paragraphs:" : self.min_extra_paragraphs,
            "Maximum extra paragraphs:" : self.max_extra_paragraphs,
            "Initial (relative) SS:" : self.initial_ss,
            "Initial SP:" : self.initial_sp,
            "Checksum:" : self.checksum,
            "Initial IP:" : self.initial_ip,
            "Initial (realtive) CS:" : self.initial_cs,
            "Offset to relocation table:" : self.offset_to_relocation,
            "Overlay number:" : self.overlay_number,
            "OEM idenitificator:" : self.oem_identifier,
            "OEM information:" : self.oem_information }.items():
            print(17*" ", "{0:30s} {1:#06x} ({1:d})".format(name,
            int.from_bytes(value, byteorder="little")))

        print(17*" ", "{0:30s} {1:#010x} ({1:d})".format(
              "Offset to PE (newEXE) header:",
              int.from_bytes(self.offset_to_pe_header, byteorder="little")))

class PE_header:
    """ Class representing PE (new EXE) header of a Win32 PE """
    def __init__(self, path):
        with open(path, "rb") as input_pe:
            input_pe.seek(0x3C)
            self.offset_to_pe_header = input_pe.read(4)
            input_pe.seek(int.from_bytes(self.offset_to_pe_header,
                                         byteorder="little"))
            self.magic = input_pe.read(4)
            self.machine = input_pe.read(2)
            self.number_of_sections = input_pe.read(2)
            input_pe.seek(12, 1)
            self.size_of_optional = input_pe.read(2)
            self.characteristics = input_pe.read(2)
            self.optional_header_offset = input_pe.tell()

    def print_data(self):
        machine_types = {
            0x0000 : "Applicable to any machine type",
            0x8664 : "x64",
            0x01c0 : "ARM little endian",
            0xaa64 : "ARM64 little endian",
            0x01c4 : "ARM Thumb-2 little endian",
            0x0ebc : "EFI byte code",
            0x014c : "Intel 386 or compatible",
            0x0200 : "Intel Itanium processor family",
            0x0366 : "MIPS with FPU",
            0x0466 : "MIPS16 with FPU",
            0x01f0 : "Power PC little endian",
            0x01f1 : "Power PC with floating",
            0x0166 : "MIPS little endian",
            0x5032 : "RISC-V 32-bit address space",
            0x5064 : "RISC-V 64-bit address space",
            0x5128 : "RISC-V 128-bit address space",
            0x01c2 : "Thumb",
            0x0169 : "MIPS little-endian WCE v2"
        }

        characteristics_data = {
            0x0001 : "IMAGE_FILE_RELOCS_STRIPPED",
            0x0002 : "IMAGE_FILE_EXECUTABLE_IMAGE",
            0x0004 : "IMAGE_FILE_LINE_NUMS_STRIPPED",
            0x0008 : "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
            0x0010 : "IMAGE_FILE_AGGRESSIVE_WS_TRIM",
            0x0020 : "IMAGE_FILE_LARGE_ADDRESS_AWARE",
            0x0040 : "RESERVED_FOR_FUTURE_USE",
            0x0080 : "IMAGE_FILE_BYTES_REVERSED_LO",
            0x0100 : "IMAGE_FILE_32BIT_MACHINE",
            0x0200 : "IMAGE_FILE_DEBUG_STRIPPED",
            0x0400 : "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
            0x0800 : "IMAGE_FILE_NET_RUN_FROM_SWAP",
            0x1000 : "IMAGE_FILE_SYSTEM",
            0x2000 : "IMAGE_FILE_DLL",
            0x4000 : "IMAGE_FILE_UP_SYSTEM_ONLY",
            0x8000 : "IMAGE_FILE_BYTES_REVERSED_HI"
        }

        print("\nPE header (COFF): ", end="")
        print("{0:30s} {1:#010x} ({2:s})".format(
              "Magic:", int.from_bytes(self.magic, byteorder="little"),
              self.magic.decode("ascii") + "[NULL, NULL]"))
        print(17*" ", "{0:30s} {1:#06x} ({2:s})".format(
              "Machine type:",
              int.from_bytes(self.machine, byteorder="little"),
              machine_types[int.from_bytes(self.machine, byteorder="little")]))

        for name, value in {
            "Number of sections:" : self.number_of_sections,
            "Size of optional header:": self.size_of_optional}.items():
            print(17*" ", "{0:30s} {1:#06x} ({1:d})".format(name,
            int.from_bytes(value, byteorder="little")))

        print(17*" ","Characteristics: ", 12*" ", "{0:#06x}".format(
              int.from_bytes(self.characteristics, byteorder="little")))

        try:
            for key, value in characteristics_data.items():
                if ((int.from_bytes(self.characteristics, byteorder="little")
                     & key) != 0): print(48*" ", value)
        except: print("CHARACTERISTICS ERROR!", file=sys.stderr)

class Optional_header:
    """ Class representing optional header of a Win32 PE """
    def __init__(self, path, optional_header_offset):
        with open(path, "rb") as input_pe:
            input_pe.seek(optional_header_offset)
            self.magic = input_pe.read(2)
            self.major_linker_version = input_pe.read(1)
            self.minor_linker_version = input_pe.read(1)

            self.size_of_code, self.size_of_initialized_data, self.size_of_unitialized_data, \
            self.entry_point_adress, self.base_of_code, self.base_of_data, self.image_base, \
            self.section_alignment, self.file_alignment = (input_pe.read(4) for i in range(0, 9))

            self.major_os_version, self.minor_os_version, self.major_image_version, \
            self.minor_image_version, self.major_subsystem_version, self.minor_subsystem_version = \
            (input_pe.read(2) for i in range(0, 6))

            self.win32_version, self.size_of_image, self.size_of_headers, self.checksum = \
            (input_pe.read(4) for i in range(0, 4))

            self.subsystem = input_pe.read(2)
            self.dll_characteristics = input_pe.read(2)

            self.size_of_stack_reserve, self.size_of_stack_commit, self.size_of_heap_reserve, \
            self.size_of_heap_commit, self.loader_flags, self.number_of_rva_and_sizes = \
            (input_pe.read(4) for i in range(0, 6))

    def print_data(self):
        subsystem_data = {
            0 :  "IMAGE_SUBSYSTEM_UNKNOWN",
            1 :  "IMAGE_SUBSYSTEM_NATIVE",
            2 :  "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            3 :  "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            5 :  "IMAGE_SUBSYSTEM_OS2_CUI",
            7 :  "IMAGE_SUBSYSTEM_POSIX_CUI",
            9 :  "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            10 : "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            11 : "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            12 : "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            13 : "IMAGE_SUBSYSTEM_EFI_ROM",
            14 : "IMAGE_SUBSYSTEM_XBOX",
            16 : "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
        }

        dll_characteristics_data = {
            0x0040 : "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            0x0080 : "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
            0x0100 : "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            0x0200 : "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            0x0400 : "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            0x0800 : "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            0x2000 : "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
            0x8000 : "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        }

        dll_characteristics_data.update(dict.fromkeys([0x0001, 0x0002, \
            0x0004, 0x0008, 0x1000, 0x4000], "RESERVED"))

        print("\nOptional header:", end="")
        print("  {0:30s} {1:#06x} ({2:s})".format("Magic",
              int.from_bytes(self.magic, byteorder="little"),
              ("32bit" if int.from_bytes(self.magic, byteorder="little") == \
              0x10b else "64bit or ROM")))

        for name, value in {
            "Major linker version:" : self.major_linker_version,
            "Minor linker version:": self.minor_linker_version,
            "Major OS version" : self.major_os_version,
            "Minor OS version:" : self.minor_os_version,
            "Major image version:" : self.major_image_version,
            "Minor image version:" : self.minor_image_version,
            "Major subsystem version:" : self.major_subsystem_version,
            "Minor subsystem version:" : self.minor_subsystem_version}.items():
            print(17*" ", "{0:30s} {1:#06x} ({1:d})".format(name,
            int.from_bytes(value, byteorder="little")))

        for name, value in {
            "Size of code:" : self.size_of_code,
            "Size of initialized data:" : self.size_of_initialized_data,
            "Size of unitialized data:" : self.size_of_unitialized_data,
            "Entry point adress:" : self.entry_point_adress,
            "Base of code:" : self.base_of_code,
            "Base of data:" : self.base_of_data,
            "Image base:" : self.image_base,
            "Section alignment:" : self.section_alignment,
            "File alignment:" : self.file_alignment,
            "Win32 version" : self.win32_version,
            "Size of image:" : self.size_of_image,
            "Size of headers:" : self.size_of_headers,
            "Checksum:" : self.checksum,
            "Size of stack reserve: " : self.size_of_stack_reserve,
            "Size of stack commit:" : self.size_of_stack_commit,
            "Size of heap reserve:" : self.size_of_heap_reserve,
            "Size of heap commit: " : self.size_of_heap_commit,
            "Number of RVAs and sizes:" : self.number_of_rva_and_sizes}.items():
            print(17*" ", "{0:30s} {1:#010x} ({1:d})".format(name,
            int.from_bytes(value, byteorder="little")))

        print(17*" ","Subsystem: ", 18*" ", "{0:#06x}".format(
              int.from_bytes(self.subsystem, byteorder="little")))

        try:
            for key, value in subsystem_data.items():
                if int.from_bytes(self.subsystem, byteorder="little") == key:
                    print(48*" ", value)
        except: print("SUBSYSTEM DATA ERROR!", file=sys.stderr)

        print(17*" ","DLL characteristics: ", 8*" ", "{0:#06x}".format(
              int.from_bytes(self.dll_characteristics, byteorder="little")))

        try:
            for key, value in dll_characteristics_data.items():
                if ((int.from_bytes(self.dll_characteristics,
                    byteorder="little") & key) != 0): print(48*" ", value)
        except: print("DLL CHARACTERISTICS ERROR!", file=sys.stderr)

class Sections_header:
    """ Class representing sections header of a Win32 PE
        Dictionary sections_data contains: name of the section as a key
        and a list as a data about each section:
            #value[0] := Section name
            #value[1] := Virtual size
            #value[2] := Virtual adress
            #value[3] := Size of raw data
            #value[4] := Pointer to raw data
            #value[5] := Pointer to relocations
            #value[6] := Pointer to line numbers
            #value[7] := Number of relocations
            #value[8] := Number of line numbers
            #value[9] := Characteristics """
    def __init__(self, path, optional_header_offset, number_of_sections):
        with open(path, "rb") as input_pe:
            self.sections_header_offset = optional_header_offset + 0xE0
            input_pe.seek(self.sections_header_offset)

            self.sections_data = {}
            for _ in range(0, int.from_bytes(number_of_sections, byteorder="little")):
                self.sections_data.update({input_pe.read(8).decode("ascii") : \
                list(input_pe.read(4) for i in range(0, 6)) + \
                [input_pe.read(2), input_pe.read(2), input_pe.read(4)]})

    def print_data(self):
        characteristics_data = {
            0x00000000 : "RESERVED",
            0x00000001 : "RESERVED",
            0x00000002 : "RESERVED",
            0x00000004 : "RESERVED",
            0x00000008 : "IMAGE_SCN_TYPE_NO_PAD",
            0x00000010 : "RESERVED",
            0x00000020 : "IMAGE_SCN_CNT_CODE",
            0x00000040 : "IMAGE_SCN_CNT_INITIALIZED_DATA",
            0x00000080 : "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            0x00000100 : "IMAGE_SCN_LNK_OTHER",
            0x00000200 : "IMAGE_SCN_LNK_INFO",
            0x00000400 : "RESERVED",
            0x00000800 : "IMAGE_SCN_LNK_REMOVE",
            0x00001000 : "IMAGE_SCN_LNK_COMDAT",
            0x00008000 : "IMAGE_SCN_GPREL",
            0x00020000 : "IMAGE_SCN_MEM_PURGEABLE OR IMAGE_SCN_MEM_16BIT",
            0x00040000 : "IMAGE_SCN_MEM_LOCKED",
            0x00080000 : "IMAGE_SCN_MEM_PRELOAD",
            0x00100000 : "IMAGE_SCN_ALIGN_1BYTES",
            0x00200000 : "IMAGE_SCN_ALIGN_2BYTES",
            0x00300000 : "IMAGE_SCN_ALIGN_4BYTES",
            0x00400000 : "IMAGE_SCN_ALIGN_8BYTES",
            0x00500000 : "IMAGE_SCN_ALIGN_16BYTES",
            0x00600000 : "IMAGE_SCN_ALIGN_32BYTES",
            0x00700000 : "IMAGE_SCN_ALIGN_64BYTES",
            0x00800000 : "IMAGE_SCN_ALIGN_128BYTES",
            0x00900000 : "IMAGE_SCN_ALIGN_256BYTES",
            0x00A00000 : "IMAGE_SCN_ALIGN_512BYTES",
            0x00B00000 : "IMAGE_SCN_ALIGN_1024BYTES",
            0x00C00000 : "IMAGE_SCN_ALIGN_2048BYTES",
            0x00D00000 : "IMAGE_SCN_ALIGN_4096BYTES",
            0x00E00000 : "IMAGE_SCN_ALIGN_8192BYTES",
            0x01000000 : "IMAGE_SCN_LNK_NRELOC_OVFL",
            0x02000000 : "IMAGE_SCN_MEM_DISCARDABLE",
            0x04000000 : "IMAGE_SCN_MEM_NOT_CACHED",
            0x08000000 : "IMAGE_SCN_MEM_NOT_PAGED",
            0x10000000 : "IMAGE_SCN_MEM_SHARED",
            0x20000000 : "IMAGE_SCN_MEM_EXECUTE",
            0x40000000 : "IMAGE_SCN_MEM_READ",
            0x80000000 : "IMAGE_SCN_MEM_WRITE"
        }

        print("\nSections header:")
        for key, value in self.sections_data.items():
            print(17* " ", "{0:26s}".format("Section name:"), 3*" ", key)
            print(21*" ", "{0:26s}".format("Virtual size:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[0], byteorder="little")))
            print(21*" ", "{0:26s}".format("Virtual adress:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[1], byteorder="little")))
            print(21*" ", "{0:26s}".format("Size of raw data:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[2], byteorder="little")))
            print(21*" ", "{0:26s}".format("Pointer to raw data:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[3], byteorder="little")))
            print(21*" ", "{0:26s}".format("Pointer to relocations:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[4], byteorder="little")))
            print(21*" ", "{0:26s}".format("Pointer to line numbers:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[5], byteorder="little")))
            print(21*" ", "{0:26s}".format("Number of relocations:"),
                "{0:#06x}       ({0:d})".format(int.from_bytes(value[6], byteorder="little")))
            print(21*" ", "{0:26s}".format("Number of line numbers:"),
                "{0:#06x}       ({0:d})".format(int.from_bytes(value[7], byteorder="little")))
            print(21*" ", "{0:26s}".format("Characteristics:"),
                "{0:#010x}   ({0:d})".format(int.from_bytes(value[8], byteorder="little")))

            try:
                for flag, desc in characteristics_data.items():
                    if ((int.from_bytes(value[8], byteorder="little") & flag) != 0): 
                        print(48*" ", desc)
            except: print("SECTION CHARACTERISTICS ERROR!", file=sys.stderr)
            print("\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please specify the PE file name", file=sys.stderr)
        sys.exit(0)

    mz_header = MZ_header(sys.argv[1])
    mz_header.print_data()
    pe_header = PE_header(sys.argv[1])
    pe_header.print_data()
    optional_header = Optional_header(sys.argv[1],
                      pe_header.optional_header_offset)

    if (int.from_bytes(optional_header.magic, byteorder="little") != 0x010b):
        print("PE file is not 32-bit! EXITING ANALYSIS!", file=sys.stderr)
        sys.exit(0)

    optional_header.print_data()

    sections_header = Sections_header(sys.argv[1],
                      pe_header.optional_header_offset,
                      pe_header.number_of_sections)
    sections_header.print_data()

