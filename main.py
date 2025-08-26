import argparse
from squashfs.blocks import SquashFsImage

def parse_args():
    parser = argparse.ArgumentParser(description='Process a SquashFS image.')
    parser.add_argument('image_path', type=str, help='Path to the SquashFS image file')
    parser.add_argument('output_root', type=str, help='Path to the output directory')
    return parser.parse_args()

def main():
    args = parse_args()
    squashfs_image = SquashFsImage(args.image_path, args.output_root)
    squashfs_image.parse()

if __name__ == '__main__':
    main()
