import os
import requests
from pathlib import Path
import time


def download_rfc(rfc_number: int, output_dir: str = "RFC"):
    """
    Download an RFC document by its number.

    Args:
        rfc_number (int): The RFC number to download.
        output_dir (str): The directory to save the downloaded RFC.

    Returns:
        str: The path to the downloaded RFC file.
    """

    base_url = "https://www.rfc-editor.org/rfc"
    rfc_filename = f"rfc{rfc_number}.txt"
    url = f"{base_url}/{rfc_filename}"

    os.makedirs(output_dir, exist_ok=True)
    output_path = Path(output_dir) / rfc_filename

    # Skip download if the file already exists
    if output_path.exists():
        print(f"RFC {rfc_number} already exists, skipping download")
        return str(output_path)

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(response.text)

        print(f"Downloaded RFC {rfc_number} to {output_path}")

        return str(output_path)

    except requests.RequestException as e:
        print(f"Failed to download RFC {rfc_number}: {e}")
        return ""


def download_rfc_range(start: int, end: int, output_dir: str = "RFC"):
    """
    Download a range of RFC documents.

    Args:
        start (int): The starting RFC number.
        end (int): The ending RFC number.
        output_dir (str): The directory to save the downloaded RFCs.
    """

    print(f"Downloading RFCs from {start} to {end}")

    success = 0
    failed = 0

    for rfc_number in range(start, end + 1):

        path = download_rfc(rfc_number, output_dir)

        if path:
            success += 1
        else:
            failed += 1

        # Small delay to avoid stressing the RFC server
        time.sleep(0.3)

    print("Download completed")
    print(f"Successful: {success}")
    print(f"Failed: {failed}")
