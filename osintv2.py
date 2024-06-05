import argparse
import exifread
import hashlib
from PIL import Image
import io
from google_images_download import google_images_download
import cv2
import json
import subprocess
import sys 

def reverse_image_search(image_path):
    response = google_images_download.googleimagesdownload()
    arguments = {
        "keywords": "",
        "image_url": image_path, 
        "limit": 10,
        "print_urls": True,
        "no_download": True,
        "silent_mode": True,
    }

    try:
        search_keyword = arguments.get('keywords', '') 
        paths = response.download(arguments)
        for path in paths[0].values():
            for url in path:
                print(f"\033[92mHasil reverse image search:\033[0m {url}")

    except UnboundLocalError:
        print(f"\033[91mKesalahan: Terjadi masalah internal dalam library google_images_download. Periksa kembali instalasi atau coba library lain.\033[0m")


def reverse_image_metadata(image_path):
    with open(image_path, "rb") as f:
        tags = exifread.process_file(f)
        if tags:
            print("\nMetadata EXIF:")
            for tag in tags.keys():
                if tag not in ("JPEGThumbnail", "TIFFThumbnail", "Filename", "EXIF MakerNote"):
                    print(f"\033[92m{tag}: {tags[tag]}\033[0m")

    with Image.open(image_path) as img:
        print("\nMetadata Gambar Lainnya:")
        print(f"\033[92mFormat: {img.format}\033[0m")
        print(f"\033[92mUkuran: {img.size}\033[0m")
        print(f"\033[92mMode: {img.mode}\033[0m")
        print(f"\033[92mPalette: {img.palette}\033[0m") 
        print(f"\033[92mInfo: {img.info}\033[0m") 

        try:
            iptc_data = {k: v for k, v in img.info.items() if k.startswith('IPTC')}
            if iptc_data:
                print("\nMetadata IPTC:")
                for key, value in iptc_data.items():
                    print(f"\033[92m{key}: {value}\033[0m")
        except Exception as e:
            print(f"\033[93mPeringatan: Gagal mengekstrak metadata IPTC: {e}\033[0m")

    with open(image_path, "rb") as f:
        img_data = f.read()
        hashes = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
            "Blake2b": hashlib.blake2b,
            "Blake2s": hashlib.blake2s,
        }

        print("\nHash Gambar:")
        for algo, func in hashes.items():
            hash_value = func(img_data).hexdigest()
            print(f"\033[92m{algo}: {hash_value}\033[0m")

    reverse_image_search(image_path) 


def reverse_video_metadata(video_path):
    """Mengekstrak dan menganalisis metadata video."""

    cmd = f"ffprobe -v quiet -print_format json -show_format -show_streams {video_path}"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        metadata = json.loads(result.stdout)
        print("\nMetadata Video:")
        if "streams" in metadata:
            for stream in metadata["streams"]:
                print(f"\033[92mCodec: {stream.get('codec_name', 'Tidak diketahui')}\033[0m")
                if 'width' in stream and 'height' in stream:
                    print(f"\033[92mResolusi: {stream['width']}x{stream['height']}\033[0m")
                if 'duration' in stream:
                    print(f"\033[92mDurasi: {stream['duration']} detik\033[0m")
                if "tags" in stream and "language" in stream["tags"]:
                    print(f"\033[92mBahasa: {stream['tags']['language']}\033[0m")

        if "format" in metadata:
            print(f"\033[92mFormat: {metadata['format']['format_name']}\033[0m")
            if "tags" in metadata["format"]:
                for tag, value in metadata["format"]["tags"].items():
                    print(f"\033[92m{tag}: {value}\033[0m")

    reverse_video_search(video_path)


def reverse_video_metadata(video_path):
    cmd = f"ffprobe -v quiet -print_format json -show_format -show_streams {video_path}"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        metadata = json.loads(result.stdout)
        print("\nMetadata Video:")
        if "streams" in metadata:
            for stream in metadata["streams"]:
                print(f"\033[92mCodec: {stream.get('codec_name', 'Tidak diketahui')}\033[0m")
                if 'width' in stream and 'height' in stream:
                    print(f"\033[92mResolusi: {stream['width']}x{stream['height']}\033[0m")
                if 'duration' in stream:
                    print(f"\033[92mDurasi: {stream['duration']} detik\033[0m")
                if "tags" in stream and "language" in stream["tags"]:
                    print(f"\033[92mBahasa: {stream['tags']['language']}\033[0m")

        if "format" in metadata:
            print(f"\033[92mFormat: {metadata['format']['format_name']}\033[0m")
            if "tags" in metadata["format"]:
                for tag, value in metadata["format"]["tags"].items():
                    print(f"\033[92m{tag}: {value}\033[0m")

    reverse_video_search(video_path)

def main():
    parser = argparse.ArgumentParser(description="Alat Investigasi OSINT Reverse Metadata")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--image", help="Path ke file gambar")
    group.add_argument("-v", "--video", help="Path ke file video")
    args = parser.parse_args()

    if args.image:
        reverse_image_metadata(args.image)
    elif args.video:
        reverse_video_metadata(args.video)

if __name__ == "__main__":
    main()
