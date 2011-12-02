using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;

namespace NetDisFilter //_3DViewerControls.Data
{

    // Reads in the header information of the Portable Executable format.
    // Provides information such as the date the assembly was compiled.
    public class PeHeaderReader
    {
        #region File Header Structures

        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        public enum OptionalMagic : ushort
        {
            PE32 = 0x10b,
            PE64 = 0x20b,
            ROM = 0x107,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public OptionalMagic Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public OptionalMagic Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public Image_File_Machine Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public Image_File_Characteristics Characteristics;
        }

        [Flags]
        public enum Image_File_Characteristics : ushort
        {
            None = 0,
            RELOCS_STRIPPED = 0x0001,  // Relocation info stripped from file.
            EXECUTABLE_IMAGE = 0x0002,  // File is executable  (i.e. no unresolved externel references).
            LINE_NUMS_STRIPPED = 0x0004,  // Line nunbers stripped from file.
            LOCAL_SYMS_STRIPPED = 0x0008,  // Local symbols stripped from file.
            AGGRESIVE_WS_TRIM = 0x0010,  // Agressively trim working set
            LARGE_ADDRESS_AWARE = 0x0020,  // App can handle >2gb addresses
            BYTES_REVERSED_LO = 0x0080,  // Bytes of machine word are reversed.
            THRITY_TWO_BIT_MACHINE = 0x0100,  // 32 bit word machine.
            DEBUG_STRIPPED = 0x0200,  // Debugging info stripped from file in .DBG file
            REMOVABLE_RUN_FROM_SWAP = 0x0400,  // If Image is on removable media, copy and run from the swap file.
            NET_RUN_FROM_SWAP = 0x0800,  // If Image is on Net, copy and run from the swap file.
            SYSTEM = 0x1000,  // System File.
            DLL = 0x2000,  // File is a DLL.
            UP_SYSTEM_ONLY = 0x4000,  // File should only be run on a UP machine
            BYTES_REVERSED_HI = 0x8000,  // Bytes of machine word are reversed.
        }

        public enum Image_File_Machine : ushort
        {
            UNKNOWN = 0,
            I386 = 0x014c,  // Intel 386.
            R3000 = 0x0162,  // MIPS little-endian, = 0x160 big-endian
            R4000 = 0x0166,  // MIPS little-endian
            R10000 = 0x0168,  // MIPS little-endian
            WCEMIPSV2 = 0x0169,  // MIPS little-endian WCE v2
            ALPHA = 0x0184,  // Alpha_AXP
            SH3 = 0x01a2,  // SH3 little-endian
            SH3DSP = 0x01a3,
            SH3E = 0x01a4,  // SH3E little-endian
            SH4 = 0x01a6,  // SH4 little-endian
            SH5 = 0x01a8,  // SH5
            ARM = 0x01c0,  // ARM Little-Endian
            THUMB = 0x01c2,
            AM33 = 0x01d3,
            POWERPC = 0x01F0,  // IBM PowerPC Little-Endian
            POWERPCFP = 0x01f1,
            IA64 = 0x0200,  // Intel 64
            MIPS16 = 0x0266,  // MIPS
            ALPHA64 = 0x0284,  // ALPHA64
            MIPSFPU = 0x0366,  // MIPS
            MIPSFPU16 = 0x0466,  // MIPS
            AXP64 = ALPHA64,
            TRICORE = 0x0520,  // Infineon
            CEF = 0x0CEF,
            EBC = 0x0EBC,  // EFI Byte Code
            AMD64 = 0x8664,  // AMD64 (K8)
            M32R = 0x9041,  // M32R little-endian
            CEE = 0xC0EE,
        }

        public enum Image_Directory_Entry_Type
        {
            EXPORT = 0,   // Export Directory
            IMPORT = 1,   // Import Directory
            RESOURCE = 2,   // Resource Directory
            EXCEPTION = 3,   // Exception Directory
            SECURITY = 4,   // Security Directory
            BASERELOC = 5,   // Base Relocation Table
            DEBUG = 6,   // Debug Directory
            ARCHITECTURE = 7,   // Architecture Specific Data
            GLOBALPTR = 8,   // RVA of GP
            TLS = 9,   // TLS Directory
            LOAD_CONFIG = 10,   // Load Configuration Directory
            BOUND_IMPORT = 11,   // Bound Import Directory in headers
            IAT = 12,   // Import Address Table
            DELAY_IMPORT = 13,   // Delay Load Import Descriptors
            COM_DESCRIPTOR = 14,   // COM Runtime descriptor
        }

        [Flags]
        public enum SectionCharacteristics : uint
        {
            TYPE_NO_PAD                = 0x00000008,  // Reserved.

            CNT_CODE                   = 0x00000020,  // Section contains code.
            CNT_INITIALIZED_DATA       = 0x00000040,  // Section contains initialized data.
            CNT_UNINITIALIZED_DATA     = 0x00000080,  // Section contains uninitialized data.

            LNK_OTHER                  = 0x00000100,  // Reserved.
            LNK_INFO                   = 0x00000200,  // Section contains comments or some other type of information.
            LNK_REMOVE                 = 0x00000800,  // Section contents will not become part of image.
            LNK_COMDAT                 = 0x00001000,  // Section contents comdat.
            NO_DEFER_SPEC_EXC          = 0x00004000,  // Reset speculative exceptions handling bits in the TLB entries for this section.
            GPREL                      = 0x00008000,  // Section content can be accessed relative to GP
            MEM_FARDATA                = 0x00008000,
            MEM_PURGEABLE              = 0x00020000,
            MEM_16BIT                  = 0x00020000,
            MEM_LOCKED                 = 0x00040000,
            MEM_PRELOAD                = 0x00080000,

            ALIGN_1BYTES               = 0x00100000,  //
            ALIGN_2BYTES               = 0x00200000,  //
            ALIGN_4BYTES               = 0x00300000,  //
            ALIGN_8BYTES               = 0x00400000,  //
            ALIGN_16BYTES              = 0x00500000,  // Default alignment if no others are specified.
            ALIGN_32BYTES              = 0x00600000,  //
            ALIGN_64BYTES              = 0x00700000,  //
            ALIGN_128BYTES             = 0x00800000,  //
            ALIGN_256BYTES             = 0x00900000,  //
            ALIGN_512BYTES             = 0x00A00000,  //
            ALIGN_1024BYTES            = 0x00B00000,  //
            ALIGN_2048BYTES            = 0x00C00000,  //
            ALIGN_4096BYTES            = 0x00D00000,  //
            ALIGN_8192BYTES            = 0x00E00000,  //
            ALIGN_MASK                 = 0x00F00000,

            LNK_NRELOC_OVFL            = 0x01000000,  // Section contains extended relocations.
            MEM_DISCARDABLE            = 0x02000000,  // Section can be discarded.
            MEM_NOT_CACHED             = 0x04000000,  // Section is not cachable.
            MEM_NOT_PAGED              = 0x08000000,  // Section is not pageable.
            MEM_SHARED                 = 0x10000000,  // Section is shareable.
            MEM_EXECUTE                = 0x20000000,  // Section is executable.
            MEM_READ                   = 0x40000000,  // Section is readable.
            MEM_WRITE                  = 0x80000000,  // Section is writeable.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        unsafe public struct IMAGE_SECTION_HEADER
        {
            public fixed byte Name[8];
            public uint PhysicalAddressOrVirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public SectionCharacteristics Characteristics;
        }

        #endregion File Header Structures

        #region Private Fields

        public string FilePath { get; private set; }

        // The DOS header
        private IMAGE_DOS_HEADER dosHeader;
        // The file header
        private IMAGE_FILE_HEADER fileHeader;
        // Optional 32 bit file header
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        // Optional 64 bit file header
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

        private Dictionary<string, IMAGE_SECTION_HEADER> sectionHeaders = new Dictionary<string, IMAGE_SECTION_HEADER>();

        private Dictionary<Image_Directory_Entry_Type, IMAGE_DATA_DIRECTORY> dataDirectories = new Dictionary<Image_Directory_Entry_Type, IMAGE_DATA_DIRECTORY>();

        #endregion Private Fields

        #region Public Methods

        unsafe public PeHeaderReader(string filePath)
        {
            this.FilePath = filePath;

            // Read in the DLL or EXE and get the timestamp
            using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
                if (dosHeader.e_magic != 0x5A4D)
                    throw new Exception("Missing MZ on header.");

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                if (ntHeadersSignature != 0x00004550)
                    throw new Exception("Missing PE magic.");

                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                    if (optionalHeader32.Magic != OptionalMagic.PE32)
                        throw new Exception("Wrong PE magic.");
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                    if (optionalHeader64.Magic != OptionalMagic.PE64)
                        throw new Exception("Wrong PE magic.");
                }

                for (int i = 0; i < 16; i++)
                {
                    var dir = FromBinaryReader<IMAGE_DATA_DIRECTORY>(reader);
                    if (dir.Size != 0 || dir.VirtualAddress != 0)
                    {
                        dataDirectories.Add((Image_Directory_Entry_Type)i, dir);
                    }
                }

                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    var section = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                    byte[] nameBytes = new byte[8];
                    Marshal.Copy(new IntPtr(section.Name), nameBytes, 0, 8);
                    int size = 0;
                    while (size < 8 && nameBytes[size] != 0)
                        size++;
                    var name = Encoding.ASCII.GetString(nameBytes, 0, size);
                    sectionHeaders.Add(name, section);
                }
            }
        }

        // Gets the header of the .NET assembly that called this function
        public static PeHeaderReader GetCallingAssemblyHeader()
        {
            // Get the path to the calling assembly, which is the path to the
            // DLL or EXE that we want the time of
            string filePath = System.Reflection.Assembly.GetCallingAssembly().Location;

            // Get and return the timestamp
            return new PeHeaderReader(filePath);
        }

        // Reads in a block from a file and converts it to the struct
        // type specified by the template parameter
        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public long GetFileOffset(uint rva)
        {
            foreach (var sec in sectionHeaders.Values)
            {
                if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.PhysicalAddressOrVirtualSize))
                {
                    return rva - sec.VirtualAddress + sec.PointerToRawData;
                }
            }
            throw new Exception("Count not find section containing the RVA.");
        }

        #endregion Public Methods

        #region Properties

        // Gets if the file header is 32 bit or not
        public bool Is32BitHeader
        {
            get
            {
                return (FileHeader.Characteristics & Image_File_Characteristics.THRITY_TWO_BIT_MACHINE) != 0;
            }
        }

        // Gets the file header
        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }

        // Gets the optional header
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }

        // Gets the optional header
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }

        public Dictionary<string, IMAGE_SECTION_HEADER> SectionHeaders
        {
            get { return sectionHeaders; }
        }

        public Dictionary<Image_Directory_Entry_Type, IMAGE_DATA_DIRECTORY> DataDirectories
        {
            get { return dataDirectories; }
        }

        // Gets the timestamp from the file header
        public DateTime TimeStamp
        {
            get
            {
                // Timestamp is a date offset from 1970
                DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                // Add in the number of seconds since 1970/1/1
                returnValue = returnValue.AddSeconds(fileHeader.TimeDateStamp);
                // Adjust to local timezone
                returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                return returnValue;
            }
        }

        #endregion Properties
    }
}
