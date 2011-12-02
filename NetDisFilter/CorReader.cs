using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.MemoryMappedFiles;
using System.IO;
using System.Runtime.InteropServices;

namespace NetDisFilter
{
    class CorReader : IDisposable
    {
        private IMAGE_COR20_HEADER mHeader;
        private MetaDataHeaderPart1 mMetaHeader;
        private string mVersionName;
        private uint mMetaDataFlags;

        private Dictionary<string, MetaDataStream> mMetaStreams = new Dictionary<string, MetaDataStream>();
        private TableHeader mTableHeader;

        public CorReader(PeHeaderReader pe)
        {
            var filePath = pe.FilePath;
            using (var mm = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open))
            {
                using (var view = mm.CreateViewAccessor())
                {
                    LoadHeaderAndStreams(pe, view);
                    LoadMetaTable(pe, view);
                }
            }
        }

        private void LoadHeaderAndStreams(PeHeaderReader pe, MemoryMappedViewAccessor mm)
        {
            var clrDataDir = pe.DataDirectories[PeHeaderReader.Image_Directory_Entry_Type.COM_DESCRIPTOR];
            if (Marshal.SizeOf(typeof(IMAGE_COR20_HEADER)) != clrDataDir.Size)
                throw new Exception("Size wrong.");

            mm.Read<IMAGE_COR20_HEADER>(pe.GetFileOffset(clrDataDir.VirtualAddress), out mHeader);
            if (mHeader.cb != clrDataDir.Size)
                throw new Exception("Size wrong.");

            var metaLoc = pe.GetFileOffset(mHeader.MetaData.VirtualAddress);
            mm.Read<MetaDataHeaderPart1>(metaLoc, out mMetaHeader);
            var versionBytes = new byte[mMetaHeader.VersionLength];

            metaLoc += Marshal.SizeOf(typeof(MetaDataHeaderPart1));
            mm.ReadArray<byte>(metaLoc, versionBytes, 0, versionBytes.Length);
            int versionSize = 0;
            while (versionSize < versionBytes.Length && versionBytes[versionSize] != 0)
                versionSize++;
            mVersionName = Encoding.ASCII.GetString(versionBytes, 0, versionSize);

            metaLoc += mMetaHeader.VersionLength;
            mMetaDataFlags = mm.ReadUInt16(metaLoc);
            metaLoc += 2;
            uint numberOfMetaStreams = mm.ReadUInt16(metaLoc);
            metaLoc += 2;

            for (int i = 0; i < numberOfMetaStreams; i++)
            {
                MetaDataStream mds;
                mm.Read<MetaDataStream>(metaLoc, out mds);
                metaLoc += Marshal.SizeOf(typeof(MetaDataStream));
                byte b;
                StringBuilder sb = new StringBuilder();
                while ((b = mm.ReadByte(metaLoc++)) != 0)
                {
                    sb.Append((char)b);
                }
                metaLoc += 3;
                metaLoc &= ~3;
                mMetaStreams.Add(sb.ToString(), mds);
            }
        }

        private void LoadMetaTable(PeHeaderReader pe, MemoryMappedViewAccessor mm)
        {
            long loc = pe.GetFileOffset(mHeader.MetaData.VirtualAddress + mMetaStreams["#~"].Offset);
            mm.Read<TableHeader>(loc, out mTableHeader);
            Console.WriteLine();
        }

        #region NativeThings
        [Flags]
        public enum CorFlags : uint
        {
            ILONLY = 0x00000001,
            THRITY_TWO_BIT_REQUIRED = 0x00000002,
            IL_LIBRARY = 0x00000004,
            STRONGNAMESIGNED = 0x00000008,
            NATIVE_ENTRYPOINT = 0x00000010,
            TRACKDEBUGDATA = 0x00010000,
            ISIBCOPTIMIZED = 0x00020000,    // NEW
        }

        public struct IMAGE_COR20_HEADER
        {
            public uint cb;
            public ushort MajorRuntimeVersion;
            public ushort MinorRuntimeVersion;
            public IMAGE_DATA_DIRECTORY MetaData;
            public CorFlags Flags;
            public uint EntryPointTokenOrRVA;
            public IMAGE_DATA_DIRECTORY Resources;
            public IMAGE_DATA_DIRECTORY StrongNameSignature;
            [Obsolete("Depricated, not used")]
            public IMAGE_DATA_DIRECTORY CodeManagerTable;
            public IMAGE_DATA_DIRECTORY VTableFixups;
            public IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
            public IMAGE_DATA_DIRECTORY ManagedNativeHeader;
        }

        public struct MetaDataHeaderPart1
        {
            public uint Signature;
            public ushort MajorVersion;
            public ushort MinorVersion;
            uint _Reserved;
            public uint VersionLength;
        }

        public struct MetaDataStream
        {
            public uint Offset;
            public uint Size;
        }

        [Flags]
        public enum LargeOffsets : byte
        {
            None = 0,
            Strings = 0x1,
            GUID = 0x2,
            Blob = 0x4,
        }

        public struct TableHeader
        {
            uint Reserved_1;
            public byte MajorVersion;
            public byte MinorVersion;
            public LargeOffsets HeapOffsetSizes;
            byte Reserved_2;
            public ulong MaskValid;
            public ulong MaskSorted;
        }
        #endregion

        public void Dispose()
        {
        }
    }
}
