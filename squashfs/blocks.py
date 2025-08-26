import struct
import math
import os
import zlib
import lzma
import lz4.frame as lz4f
import zstandard as zstd
import hexdump
from dataclasses import dataclass
from typing import Union, List

COMPRESSION_ALGOS = {
    1: 'GZIP',
    2: 'LZMA',  # no compression options
    3: 'LZO',  
    4: 'XZ',
    5: 'LZ4',
    6: 'ZSTD'
}

XATTR_KEY_NAME_PREFIX = {
    0: 'user',
    1: 'trusted',
    2: 'security'
}

FLAGS_UNCOMPRESSED_INODES = 0x0001
FLAGS_UNCOMPRESSED_DATA = 0x0002
FLAGS_CHECK = 0x0004
FLAGS_UNCOMPRESSED_FRAGMENTS = 0x0008
FLAGS_NO_FRAGMENTS = 0x0010
FLAGS_ALWAYS_FRAGMENTS = 0x0020
FLAGS_DUPLICATES = 0x0040
FLAGS_EXPORTABLE = 0x0080
FLAGS_UNCOMPRESSED_XATTRS = 0x0100
FLAGS_NO_XATTRS = 0x0200
FLAGS_COMPRESSOR_OPTIONS = 0x0400
FLAGS_UNCOMPRESSED_IDS = 0x0800

INODE_TYPE_BASIC_DIRECTORY = 1
INODE_TYPE_BASIC_FILE = 2
INODE_TYPE_BASIC_SYMLINK = 3
INODE_TYPE_EXTENDED_DIRECTORY = 8

@dataclass
class SquashFsSuperblock:
    magic: int
    inode_cnt: int
    modification_time: int
    block_size: int
    fragment_entry_cnt: int
    compression_id: int
    block_log: int
    flags: int
    id_count: int
    version_major: int
    version_minor: int
    root_inode_ref: int
    bytes_used: int
    id_tab_start: int
    xattr_id_tab_start: int
    inode_tab_start: int
    dir_tab_start: int
    fragment_tab_start: int
    export_tab_start: int

    @classmethod
    def struct_format(cls):
        return '<IIIIIHHHHHHQQQQQQQQ'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class CompressionOptionGZIP:
    compression_level: int
    window_size: int
    strategies: int

    @classmethod
    def struct_format(cls):
        return '<IHH'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class CompressionOptionXZ:
    dict_size: int
    filters: int

    @classmethod
    def struct_format(cls):
        return '<II'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class CompressionOptionLZ4:
    version: int
    flags: int

    @classmethod
    def struct_format(cls):
        return '<II'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class CompressionOptionZSTD:
    compression_level: int

    @classmethod
    def struct_format(cls):
        return '<I'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class CompressionOptionLZO:
    algorithm: int
    compression_level: int

    @classmethod
    def struct_format(cls):
        return '<II'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class InodeHeader:
    inode_type: int
    permissions: int
    uid: int
    gid: int
    mtime: int
    inode_number: int

    @classmethod
    def struct_format(cls):
        return '<HHHHII'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class BasicSymlinkInode:
    hard_link_count: int
    target_size: int
    target_path: str

    @classmethod
    def struct_format(cls):
        return '<II'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        hard_link_count, target_size = struct.unpack(cls.struct_format(), data[:base_size])

        target_bytes = data[base_size:base_size + target_size]
        target_path = target_bytes.decode('utf-8')

        return cls(hard_link_count, target_size, target_path)

    @property
    def size(self):
        return 8 + self.target_size

@dataclass
class BasicFileInode:
    blocks_start: int
    fragment_block_index: int
    block_offset: int
    file_size: int
    block_sizes: List[int]

    @classmethod
    def struct_format(cls):
        return '<IIII'

    @classmethod
    def from_bytes(cls, data: bytes, block_size: int):
        base_size = struct.calcsize(cls.struct_format())
        blocks_start, fragment_block_index, block_offset, file_size = struct.unpack(cls.struct_format(), data[:base_size])

        full_blocks = file_size // block_size
        remainder = file_size % block_size
        use_frag = (remainder != 0) and (fragment_block_index != 0xFFFFFFFF)

        if use_frag: num_block = full_blocks
        else: num_block = full_blocks + (1 if remainder else 0)

        block_sizes = list(struct.unpack_from(f'<{num_block}I', data, base_size))

        return cls(blocks_start, fragment_block_index, block_offset, file_size, block_sizes)

    @property
    def size(self):
        return 16 + len(self.block_sizes) * 4

@dataclass
class BasicDirectoryInode:
    dir_block_start: int
    hard_link_count: int
    file_size: int
    block_offset: int
    parent_inode_number: int

    @classmethod
    def struct_format(cls):
        return '<IIHHI'

    @classmethod
    def struct_size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.struct_size():
            raise ValueError(f'Not enough data: expected {cls.struct_size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.struct_size()])
        return cls(*fields)

    @property
    def size(self):
        return struct.calcsize(BasicDirectoryInode.struct_format())

@dataclass
class DirectoryIndex:
    index: int
    start: int
    name_size: int
    name: str

    @classmethod
    def struct_format(cls):
        return '<III'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        index, start, name_size = struct.unpack(cls.struct_format(), data[:base_size])

        name_len = name_size + 1
        name_bytes = data[base_size: base_size + name_len]
        name = name_bytes.decode('utf-8')

        return cls(index, start, name_size, name)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + len(self.name) + 1

@dataclass
class ExtendedDirectoryInode:
    hard_link_count: int
    file_size: int
    dir_block_start: int
    parent_inode_number: int
    index_count: int
    block_offset: int
    xattr_idx: int
    index: List[DirectoryIndex]

    @classmethod
    def struct_format(cls):
        return '<IIIIHHI'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        hard_link_count, file_size, dir_block_start, parent_inode_number, index_count, block_offset, xattr_idx \
                                                                = struct.unpack(cls.struct_format(), data[:base_size])

        offset = base_size
        indices = []
        for _ in range(index_count):
            entry = DirectoryIndex.from_bytes(data[offset:])
            indices.append(entry)
            offset += entry.size

        return cls(hard_link_count, file_size, dir_block_start, parent_inode_number, index_count, block_offset, xattr_idx, indices)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + sum(index.size for index in self.index)

@dataclass
class Inode:
    inode_header: InodeHeader
    inode_entry: Union[BasicSymlinkInode, BasicFileInode, BasicDirectoryInode, ExtendedDirectoryInode]

@dataclass
class DirectoryHeader:
    count: int
    start: int
    inode_number: int

    @classmethod
    def struct_format(cls):
        return '<III'

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

@dataclass
class DirectoryEntry:
    offset: int
    inode_offset: int
    inode_type: int
    name_size: int
    name: str

    @classmethod
    def struct_format(cls):
        return '<HhHH'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        offset, inode_offset, inode_type, name_size = struct.unpack(cls.struct_format(), data[:base_size])

        name_len = name_size + 1
        name_bytes = data[base_size: base_size + name_len]
        name = name_bytes.decode('utf-8')

        return cls(offset, inode_offset, inode_type, name_size, name)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + len(self.name)

@dataclass
class Directory:
    dir_header: DirectoryHeader
    dir_entries: List[DirectoryEntry]

    @property
    def size(self):
        return self.dir_header.size() + sum(entry.size for entry in self.dir_entries)

@dataclass
class FragmentEntry:
    start: int
    _size: int
    _unused: int

    @classmethod
    def struct_format(cls):
        return '<QII'
    
    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class XattrKey:
    key_type: int
    name_size: int
    name: str

    @classmethod
    def struct_format(cls):
        return '<HH'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        key_type, name_size = struct.unpack(cls.struct_format(), data[:base_size])
        
        name_byte = data[base_size:base_size + name_size]
        name = name_byte.decode('utf-8')

        return cls(key_type, name_size, name)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + len(self.name)

@dataclass
class XattrValue:
    value_size: int
    value: bytes

    @classmethod
    def struct_format(cls):
        return '<I'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        value_size = struct.unpack(cls.struct_format()[0], data[:base_size])

        value = data[base_size:base_size + value_size]
        return cls(value_size, value)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + len(self.value)

@dataclass
class XattrLookUpTable:
    xattr_ref: int
    count: int
    size: int

    @classmethod
    def struct_format(cls):
        return '<QII'

    @classmethod
    def size(cls):
        return struct.calcsize(cls.struct_format())

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls.size():
            raise ValueError(f'Not enough data: expected {cls.size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.size()])
        return cls(*fields)

@dataclass
class XattrIdTable:
    xattr_table_start: int
    xattr_ids: int
    _unused: int
    table: List[int]

    @classmethod
    def struct_format(cls):
        return '<QII'

    @classmethod
    def from_bytes(cls, data: bytes):
        base_size = struct.calcsize(cls.struct_format())
        xattr_table_start, xattr_ids, _unused = struct.unpack(cls.struct_format(), data[:base_size])

        loc_count = math.ceil(xattr_ids / 512) if xattr_ids > 0 else 0
        table = list(struct.unpack(f'<{loc_count}Q', data[base_size:base_size + loc_count * 8]))

        return cls(xattr_table_start, xattr_ids, _unused, table)

    @property
    def size(self):
        return struct.calcsize(self.struct_format()) + len(self.table) * 8

class SquashFsImage:
    def __init__(self, path_img: str, path_out: str):
        self.path_img = path_img
        self.path_out = path_out
        self.superblock = None
        self.compression_options = None
        self.inode_table = None
        self.inode_dict = {}
        self.dir_table = None
        self.frag_table = None
        self.export_table = None
        self.id_table = None
        self.xattr_table = None

    def _parse_compression_options(self, f):
        if self.superblock.flags & 0x0400:
                if self.superblock.compression_id == 1:
                    self.compression_options = CompressionOptionGZIP.from_bytes(f.read(CompressionOptionGZIP.size()))
                elif self.superblock.compression_id == 3:
                    self.compression_options = CompressionOptionLZO.from_bytes(f.read(CompressionOptionLZO.size()))
                elif self.superblock.compression_id == 4:
                    self.compression_options = CompressionOptionXZ.from_bytes(f.read(CompressionOptionXZ.size()))
                elif self.superblock.compression_id == 5:
                    self.compression_options = CompressionOptionLZ4.from_bytes(f.read(CompressionOptionLZ4.size()))
                elif self.superblock.compression_id == 6:
                    self.compression_options = CompressionOptionZSTD.from_bytes(f.read(CompressionOptionZSTD.size()))

    def __decompress_block(self, data):
        if self.superblock.compression_id == 1:  # GZIP
            return zlib.decompress(data)
        elif self.superblock.compression_id == 2:  # LZMA
            return lzma.decompress(data)
        elif self.superblock.compression_id == 3:   # LZO
            raise ValueError('LZO decompression not implemented')
        elif self.superblock.compression_id == 4:  # XZ
            return lzma.decompress(data)
        elif self.superblock.compression_id == 5:  # LZ4
            return lz4f.decompress(data)
        elif self.superblock.compression_id == 6:  # ZSTD
            return zstd.ZstdDecompressor().decompress(data)
        else:
            raise ValueError(f'Unknown compression ID: {self.superblock.compression_id}')

    def __decompress_metadata_block(self, f):
        header = struct.unpack('<H', f.read(2))[0]
        data_size = header & 0x7FFF

        if data_size > 8192:
            raise ValueError(f'Metadata payload too large: {data_size} > 8192')

        is_compressed = (header & 0x8000) == 0
        data = f.read(data_size)

        if is_compressed: 
            data = self.__decompress_block(data)

            if len(data) > 8192:
                raise ValueError(f'Decompressed metadata payload too large: {len(data)} > 8192')
        
        return data

    def __parse_basic_symlink_inode(self, payload):
        symlink_inode = BasicSymlinkInode.from_bytes(payload)
        return symlink_inode

    def __parse_basic_file_inode(self, payload):
        basicfile_inode = BasicFileInode.from_bytes(payload, self.superblock.block_size)
        return basicfile_inode

    def __parse_basic_directory_inode(self, payload):
        basic_directory_inode = BasicDirectoryInode.from_bytes(payload)
        return basic_directory_inode

    def __parse_extended_directory_inode(self, payload):
        extended_directory_inode = ExtendedDirectoryInode.from_bytes(payload)
        return extended_directory_inode

    def __parse_compressed_inode_table(self, f):
        inodes = []
        buf = b''
        
        while len(inodes) < self.superblock.inode_cnt:
            try:
                payload = buf + self.__decompress_metadata_block(f)

                offset = 0
                while offset + InodeHeader.size() <= len(payload):
                    inode_header = InodeHeader.from_bytes(payload[offset:offset + InodeHeader.size()])
                    
                    offset += InodeHeader.size()

                    if inode_header.inode_type == INODE_TYPE_BASIC_DIRECTORY:
                        inode_entry = self.__parse_basic_directory_inode(payload[offset:])
                    elif inode_header.inode_type == INODE_TYPE_BASIC_FILE:
                        inode_entry = self.__parse_basic_file_inode(payload[offset:])
                    elif inode_header.inode_type == INODE_TYPE_BASIC_SYMLINK:
                        inode_entry = self.__parse_basic_symlink_inode(payload[offset:])
                    elif inode_header.inode_type == INODE_TYPE_EXTENDED_DIRECTORY:
                        inode_entry = self.__parse_extended_directory_inode(payload[offset:])
                    else:
                        raise ValueError(f'Unknown inode type: {inode_header.inode_type}')

                    offset += inode_entry.size
                    inode = Inode(inode_header, inode_entry)
                    inodes.append(inode)

                buf = payload[offset:]
            except struct.error as e:
                buf = payload[offset - InodeHeader.size():]
            except Exception as e:
                print(f'Unexpected exception occurred: {e}')
                exit(0)

        return inodes

    def _parse_inode_table(self, f):
        f.seek(self.superblock.inode_tab_start)

        if self.superblock.flags & FLAGS_UNCOMPRESSED_INODES == 0:  # compressed inode table
            self.inode_table = self.__parse_compressed_inode_table(f)
            for inode in self.inode_table:
                self.inode_dict[inode.inode_header.inode_number] = inode
        else:  # uncompressed inode table
            raise ValueError('Parsing uncompressed inode table is not supported.')

    def _parse_directory_table(self, f):
        dir_inodes = [inode for inode in self.inode_table if isinstance(inode.inode_entry, (BasicDirectoryInode, ExtendedDirectoryInode))]
        dir_table = {}
        
        for dir_inode in dir_inodes:
            dir_items = []

            if dir_inode.inode_entry.file_size - 3 == 0: 
                dir_table[dir_inode.inode_header.inode_number] = dir_items
                continue

            f.seek(self.superblock.dir_tab_start + dir_inode.inode_entry.dir_block_start)

            payload = b''
            while True:
                payload += self.__decompress_metadata_block(f)
                offset = dir_inode.inode_entry.block_offset
                file_size = dir_inode.inode_entry.file_size

                if offset + file_size <= len(payload): break
            
            sz = 0
            while True:
                dir_header = DirectoryHeader.from_bytes(payload[offset:offset+DirectoryHeader.size()])
                offset += DirectoryHeader.size()

                dir_entries = []
                for _ in range(dir_header.count + 1):
                    dir_entry = DirectoryEntry.from_bytes(payload[offset:])
                    offset += dir_entry.size
                    dir_entries.append(dir_entry)

                dir_item = Directory(dir_header, dir_entries)
                dir_items.append(dir_item)
                sz += dir_item.size

                if sz + 3 == dir_inode.inode_entry.file_size: break
            
            dir_table[dir_inode.inode_header.inode_number] = dir_items

        self.dir_table = dir_table

        for no, d in dir_table.items():
            if len(d) > 1:
                print(no, d)
                exit(0)

    def _parse_fragment_table(self, f): # incomplete implementation
        is_frag = self.superblock.flags & FLAGS_NO_FRAGMENTS == 0

        if is_frag:
            f.seek(self.superblock.fragment_tab_start)
            cnt_metadatablock = math.ceil(self.superblock.fragment_entry_cnt / 512)
            metadata_locs = [struct.unpack('<Q', f.read(8))[0] for _ in range(cnt_metadatablock)]

            frag_table = []
            for mloc in metadata_locs:
                f.seek(mloc)

                payload = self.__decompress_metadata_block(f)
                offset = 0
                for _ in range(self.superblock.fragment_entry_cnt):
                    frag_entry = FragmentEntry.from_bytes(payload[offset:offset + FragmentEntry.size()])
                    offset += FragmentEntry.size()
                    frag_table.append(frag_entry)
                
            self.frag_table = frag_table
        else:
            raise ValueError('Parsing fragment table is not supported.')

    def _parse_id_table(self, f):   # incomplete implementation
        f.seek(self.superblock.id_tab_start)

        cnt_ids = math.ceil(self.superblock.id_count / 2048)
        metadata_locs = [struct.unpack('<Q', f.read(8))[0] for _ in range(cnt_ids)]
        
        id_table = []
        for mloc in metadata_locs:
            f.seek(mloc)

            payload = self.__decompress_metadata_block(f)
            offset = 0
            for _ in range(self.superblock.id_count):
                id = struct.unpack('<I', payload[offset:offset+4])[0]
                offset += 4
                id_table.append(id)
        self.id_table = id_table

    def _parse_export_table(self, f):   # fragment/id table must be implemented like this.
        is_exportable = (self.superblock.flags & FLAGS_EXPORTABLE) != 0

        export_table = []

        if is_exportable:
            f.seek(self.superblock.export_tab_start)
            
            cnt_export = math.ceil(self.superblock.inode_cnt / 1024)
            metadata_locs = [struct.unpack('<Q', f.read(8))[0] for _ in range(cnt_export)]
            remain = self.superblock.inode_cnt

            for mloc in metadata_locs:
                f.seek(mloc)

                payload = self.__decompress_metadata_block(f)
                take = min(1024, remain)
                offset = 0
                for _ in range(take):
                    ref = struct.unpack('<Q', payload[offset:offset + 8])[0]
                    export_table.append(ref)
                    offset += 8
                remain -= take

        self.export_table = export_table

    def _parse_xattr_table(self, f):
        has_xattrs = self.superblock.flags & FLAGS_NO_XATTRS == 0

        xattr_table = []
        if has_xattrs:
            raise ValueError('Parsing xattr table is not supported.')
        
        self.xattr_table = xattr_table
    
    def __find_root_inode(self):
        dir_set = set(self.dir_table.keys())
        child_set = set()

        for parent_no, dir_items in self.dir_table.items():
            for d in dir_items:
                base = d.dir_header.inode_number

                for e in d.dir_entries:
                    name = e.name

                    if name in ('.', '..'): continue

                    child_set.add(base + e.inode_offset)

        roots = list(dir_set - child_set)
        if len(roots) != 1:
            raise RuntimeError(f'The number of root candidates is {len(roots)}: {roots}')
        return self.inode_dict[roots[0]]

    def __find_children(self, inode):
        children = []
        for d in self.dir_table[inode.inode_header.inode_number]:
            base_ino = d.dir_header.inode_number
            
            for e in d.dir_entries:
                name = e.name
                if name in ('.', '..'): continue

                child_ino = base_ino + e.inode_offset
                
                children.append((name, self.inode_dict[child_ino]))

        return children

    def __extract_directory(self, inode, out_path: str):
        os.makedirs(out_path, exist_ok=True)
        os.chmod(out_path, inode.inode_header.permissions & 0o7777)

        uid = self.id_table[inode.inode_header.uid]
        gid = self.id_table[inode.inode_header.gid]

        os.chown(out_path, uid, gid)

    def __extract_basic_file(self, f, inode, out_path: str):
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with open(out_path, 'wb') as file:
            written = 0
            pos = inode.inode_entry.blocks_start

            for sz in inode.inode_entry.block_sizes:
                remain = inode.inode_entry.file_size - written
                if remain <= 0: break

                is_compressed = sz & 0x80000000 == 0
                sz = sz & 0x7FFFFFFF
                
                if is_compressed:
                    f.seek(pos)
                    data = f.read(sz)
                    
                    payload = self.__decompress_block(data)
                    pos += sz

                    if len(payload) > remain:
                        payload = payload[:remain]

                    file.write(payload)
                    written += len(payload)

                else:
                    raise ValueError('Unsupported block format.')

            if written < inode.inode_entry.file_size and inode.inode_entry.fragment_block_index != 0xFFFFFFFF:
                fragment = self.frag_table[inode.inode_entry.fragment_block_index]
                f.seek(fragment.start)

                data = f.read(fragment._size)
                try: payload = self.__decompress_block(data)
                except: payload = data

                remain = inode.inode_entry.file_size - written
                payload = payload[inode.inode_entry.block_offset:inode.inode_entry.block_offset + remain]
                file.write(payload)

            os.chmod(out_path, inode.inode_header.permissions & 0o7777)

            uid = self.id_table[inode.inode_header.uid]
            gid = self.id_table[inode.inode_header.gid]

            os.chown(out_path, uid, gid)

    def __extract_symlink(self, inode, out_path: str):
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        target = inode.inode_entry.target_path

        if os.path.lexists(out_path):
            os.remove(out_path)
        os.symlink(target, out_path)

    def _parse_datablocks_fragments(self, f):
        root_inode = self.__find_root_inode()

        def walk(cur_inode, cur_out):
            inode_ty = cur_inode.inode_header.inode_type
            
            if inode_ty in (INODE_TYPE_BASIC_DIRECTORY, INODE_TYPE_EXTENDED_DIRECTORY):
                self.__extract_directory(cur_inode, cur_out)

                children = self.__find_children(cur_inode)
                for name, child_inode in children:
                    name = name.replace('/', '_')
                    walk(child_inode, os.path.join(cur_out, name))

            elif inode_ty in (INODE_TYPE_BASIC_FILE, ):
                self.__extract_basic_file(f, cur_inode, cur_out)
            elif inode_ty in (INODE_TYPE_BASIC_SYMLINK, ):
                self.__extract_symlink(cur_inode, cur_out)
            else:
                raise ValueError(f'Unknown inode type: {inode_ty}')

        walk(root_inode, self.path_out)


    def parse(self):
        with open(self.path_img, 'rb') as f:
            data_superblock = f.read(SquashFsSuperblock.size())
            self.superblock = SquashFsSuperblock.from_bytes(data_superblock)

            # parsing compression options if required
            self._parse_compression_options(f)

            # parsing inode table
            self._parse_inode_table(f)

            # parsing directory table
            self._parse_directory_table(f)

            # parsing fragment table
            self._parse_fragment_table(f)

            # parsing export table
            self._parse_export_table(f)

            # parsing uid/gid table
            self._parse_id_table(f)

            # parsing xattr table
            self._parse_xattr_table(f)

            # parsing datablocks and fragments
            self._parse_datablocks_fragments(f)

            print(f'Parsing {self.path_img} completed successfully.')

    def print(self):
        print(f'Superblock: {self.superblock}')

        # if self.compression_options:
        #     print(f'Compression Options: {self.compression_options}')
        # else:
        #     print('No compression options available.')
