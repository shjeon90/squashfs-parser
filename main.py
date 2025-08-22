from squashfs.blocks import SquashFsImage

def main():
    squashfs_image = SquashFsImage('../squashfs.img')
    squashfs_image.parse()
    # squashfs_image.print()

if __name__ == '__main__':
    main()
