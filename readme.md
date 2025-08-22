
# SquashFS Parser

**Status: This project is under development and not yet complete.**

SquashFS Parser is a Python tool for parsing SquashFS filesystem images and extracting their file and directory structures.

## Features

- Parse SquashFS image files and extract files/directories
- Supports multiple compression algorithms (GZIP, LZMA, LZ4, ZSTD, etc.)
- Restores extracted files to a specified directory



## Installation

Before using this project, you must install the squashfs-parser package itself and its dependencies:

```bash
pip install .
```
This will install squashfs-parser and all required dependencies (lz4, zstandard, hexdump).

## Usage

1. Install the dependencies as described above.
2. Prepare your SquashFS image file (e.g., `squashfs.img`).
3. Run the parser with arguments:
	```bash
	python3 main.py <image_path> <output_root>
	```
	- `<image_path>`: Path to your SquashFS image file
	- `<output_root>`: Path to the directory where files will be extracted

## Project Structure

- `main.py`: Entry point, command-line interface
- `squashfs/blocks.py`: SquashFS parsing logic
- `output-root/`: Directory for extracted files

## License

MIT License
