import struct
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
    inode_spec: Union[BasicSymlinkInode, BasicFileInode]

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
        if len(data) < cls.struct_size():
            raise ValueError(f'Not enough data: expected {cls.struct_size()} bytes, but got {len(data)} bytes.')

        fields = struct.unpack(cls.struct_format(), data[:cls.struct_size()])
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
        return struct.calcsize(self.struct_format()) + len(self.name) + 1

class SquashFsImage:
    def __init__(self, path_img: str):
        self.path_img = path_img
        self.superblock = None
        self.compression_options = None
        self.inode_table = None
        self.dir_table = None

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

    def __parse_metadata_block(self, f):
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
                payload = buf + self.__parse_metadata_block(f)

                offset = 0
                while offset + InodeHeader.size() <= len(payload):
                    inode_header = InodeHeader.from_bytes(payload[offset:offset + InodeHeader.size()])
                    
                    offset += InodeHeader.size()

                    if inode_header.inode_type == 1:
                        inode = self.__parse_basic_directory_inode(payload[offset:])
                    elif inode_header.inode_type == 2:
                        inode = self.__parse_basic_file_inode(payload[offset:])
                    elif inode_header.inode_type == 3:
                        inode = self.__parse_basic_symlink_inode(payload[offset:])
                    elif inode_header.inode_type == 8:
                        inode = self.__parse_extended_directory_inode(payload[offset:])
                    else:
                        raise ValueError(f'Unknown inode type: {inode_header.inode_type}')

                    offset += inode.size
                    inodes.append(inode)
                    i += 1

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
        else:  # uncompressed inode table
            raise ValueError('Parsing uncompressed inode table is not supported.')

    def _parse_directory_table(self, f):
        f.seek(self.superblock.dir_tab_start)

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


    def print(self):
        print(f'Superblock: {self.superblock}')
        if self.compression_options:
            print(f'Compression Options: {self.compression_options}')
        else:
            print('No compression options available.')