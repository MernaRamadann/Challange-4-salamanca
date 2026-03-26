import os
import sys
import json
import math
import subprocess
from contextlib import contextmanager

SLEUTHKIT_BIN = r"C:\Users\WinLab\Desktop\sleuthkit-4.14.0-win32\bin"
PHOTOREC_EXE = r"C:\Users\WinLab\Desktop\testdisk-7.3-WIP\photorec_win.exe"

def function_tool(func):
    def wrapper(*args, **kwargs):
        print(f"[TOOL] Running {func.__name__}")
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"[WARNING] {func.__name__} failed: {e}")
            return None
    return wrapper

def get_image_type_flag(image_path):
    """Return the SleuthKit -i image type flag based on file extension."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext in (".e01", ".e02", ".ex01"):
        return ["-i", "ewf"]
    elif ext in (".aff",):
        return ["-i", "aff"]
    elif ext in (".vmdk",):
        return ["-i", "vmdk"]
    return []  # raw/dd: no flag needed

def detect_partition_offset(image_path):
    """
    Use mmls to detect the first data partition offset (in sectors).
    Returns the offset as a string, or None if no partition table is found
    (single-partition / no-partition image).
    """
    mmls_exe = os.path.join(SLEUTHKIT_BIN, "mmls.exe")
    if not os.path.exists(mmls_exe) or not os.path.exists(image_path):
        return None
    image_flags = get_image_type_flag(image_path)
    cmd = [mmls_exe] + image_flags + [image_path]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        line_lower = line.lower()
        # Skip header, meta, and unallocated rows
        if "meta" in line_lower or "unallocated" in line_lower or "-------" in line_lower:
            continue
        if "start" in line_lower and "end" in line_lower:
            continue  # header row
        parts = line.split()
        # Look for rows like: 002:  000:000  0000000051  0000060799  0000060749  DOS FAT16 (0x04)
        # The slot starts with digits followed by ':'
        if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
            # parts[0] = slot (e.g. "002:"), parts[1] = address (e.g. "000:000"),
            # parts[2] = start sector, parts[3] = end sector, parts[4] = length
            start_sector = parts[2]
            try:
                sector_val = int(start_sector)
                if sector_val > 0:
                    return start_sector
            except ValueError:
                continue
    return None

def get_offset_flags(image_path):
    """Return -o <offset> flags if the image has a partition table, else []."""
    offset = detect_partition_offset(image_path)
    if offset and int(offset) > 0:
        return ["-o", offset]
    return []

def detect_os_from_image(image_path):
    """
    Detect the OS / filesystem type in a disk image using fsstat.
    Returns a dict with 'os' and 'filesystem' keys.
    """
    fsstat_exe = os.path.join(SLEUTHKIT_BIN, "fsstat.exe")
    image_flags = get_image_type_flag(image_path)
    offset_flags = get_offset_flags(image_path)

    if not os.path.exists(image_path):
        return {"os": "unknown", "filesystem": "unknown", "note": "image not found"}

    if not os.path.exists(fsstat_exe):
        return {"os": "unknown", "filesystem": "unknown", "note": "fsstat.exe not found"}

    cmd = [fsstat_exe] + image_flags + offset_flags + [image_path]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = result.stdout.lower()

    # Extract File System Type line
    fs_type = "unknown"
    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("file system type:"):
            fs_type = line.split(":", 1)[1].strip()
            break

    # Extract OEM / Volume Label for extra context
    oem_name = ""
    vol_label = ""
    for line in result.stdout.splitlines():
        ll = line.strip().lower()
        if ll.startswith("oem name:"):
            oem_name = line.split(":", 1)[1].strip()
        if ll.startswith("volume label (boot sector):"):
            vol_label = line.split(":", 1)[1].strip()

    # Determine OS
    if "ntfs" in out:
        detected_os = "windows"
    elif "ext2" in out or "ext3" in out or "ext4" in out:
        detected_os = "linux"
    elif "hfs" in out or "apfs" in out:
        detected_os = "macos"
    elif "fat12" in out or "fat16" in out or "fat32" in out or "exfat" in out:
        # FAT can be camera, USB, or Windows — check OEM/label for clues
        if any(cam in oem_name.lower() for cam in ["canon", "nikon", "sony", "fuji", "olymp", "panason", "pentax", "pwrshot"]):
            detected_os = "camera/embedded (FAT)"
        elif any(cam in vol_label.lower() for cam in ["canon", "nikon", "sony", "dcim", "eos"]):
            detected_os = "camera/embedded (FAT)"
        else:
            detected_os = "windows/portable (FAT)"
    else:
        detected_os = "unknown"

    return {"os": detected_os, "filesystem": fs_type, "oem": oem_name, "volume_label": vol_label}

@contextmanager
def forensic_session(image_path):
    print("[INFO] Starting forensic session")
    os_info = detect_os_from_image(image_path)
    offset = detect_partition_offset(image_path)
    print(f"[INFO] Detected OS: {os_info['os']}")
    print(f"[INFO] Filesystem: {os_info['filesystem']}")
    if offset:
        print(f"[INFO] Partition offset: {offset} sectors")
    try:
        yield os_info
    finally:
        print("[INFO] Forensic session ended.")

def count_files(directory):
    return sum(len(files) for _, _, files in os.walk(directory))

def is_real_error(stderr_text):
    """
    Determine if SleuthKit stderr output is a real error or just a warning.
    High entropy warnings from compressed/encrypted E01 images are expected
    and should NOT block processing.
    """
    if not stderr_text:
        return False
    # Known non-fatal warnings to ignore
    non_fatal_patterns = [
        "high entropy",
        "possible encryption detected",
        "entropy (",
    ]
    lower = stderr_text.lower()
    for pattern in non_fatal_patterns:
        if pattern in lower:
            return False
    return True

@function_tool
def run_tsk_mft(image_path, output_dir):
    fls_exe = os.path.join(SLEUTHKIT_BIN, "fls.exe")
    bodyfile_path = os.path.join(output_dir, "bodyfile.txt")
    if not os.path.exists(fls_exe):
        print(f"[ERROR] fls.exe not found at {fls_exe}")
        return None
    if not os.path.exists(image_path):
        print(f"[ERROR] Image not found: {image_path}")
        return None
    image_flags = get_image_type_flag(image_path)
    offset_flags = get_offset_flags(image_path)
    cmd = [fls_exe] + image_flags + offset_flags + ["-r", "-m", "/", image_path]
    with open(bodyfile_path, "w", encoding="utf-8") as f:
        result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, check=False)
    stderr_out = result.stderr.decode(errors="ignore").strip()
    if stderr_out:
        if is_real_error(stderr_out):
            print(f"[ERROR] fls (MFT) stderr: {stderr_out}")
        else:
            print(f"[WARNING] fls (MFT): {stderr_out}")
    return bodyfile_path if os.path.exists(bodyfile_path) and os.path.getsize(bodyfile_path) > 0 else None

@function_tool
def analyze_deleted_files(image_path, output_dir):
    fls_exe = os.path.join(SLEUTHKIT_BIN, "fls.exe")
    listing_path = os.path.join(output_dir, "deleted_files.txt")
    if not os.path.exists(fls_exe):
        return {"deleted_count": 0, "listing_path": listing_path, "error": "fls.exe not found"}
    if not os.path.exists(image_path):
        return {"deleted_count": 0, "listing_path": listing_path, "error": f"Image not found: {image_path}"}
    image_flags = get_image_type_flag(image_path)
    offset_flags = get_offset_flags(image_path)
    cmd = [fls_exe] + image_flags + offset_flags + ["-r", "-d", image_path]
    with open(listing_path, "w", encoding="utf-8") as f:
        result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, check=False)
    stderr_out = result.stderr.decode(errors="ignore").strip()
    if stderr_out:
        if is_real_error(stderr_out):
            print(f"[ERROR] Failed to list deleted files: {stderr_out}")
        else:
            print(f"[WARNING] fls (deleted): {stderr_out}")
    # fls -d only outputs deleted entries, so count all non-empty lines
    deleted_count = 0
    if os.path.exists(listing_path):
        with open(listing_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    deleted_count += 1
    real_error = stderr_out if (stderr_out and is_real_error(stderr_out)) else None
    return {"deleted_count": deleted_count, "listing_path": listing_path, "error": real_error}

@function_tool
def recover_deleted_files(image_path, output_dir):
    tsk_recover_exe = os.path.join(SLEUTHKIT_BIN, "tsk_recover.exe")
    recovery_dir = os.path.join(output_dir, "Recovered_Deleted_Files")
    os.makedirs(recovery_dir, exist_ok=True)
    if not os.path.exists(tsk_recover_exe):
        return {"recovered_count": 0, "recovery_dir": recovery_dir, "error": "tsk_recover.exe not found"}
    if not os.path.exists(image_path):
        return {"recovered_count": 0, "recovery_dir": recovery_dir, "error": f"Image not found: {image_path}"}
    image_flags = get_image_type_flag(image_path)
    offset_flags = get_offset_flags(image_path)
    # -e: recover deleted/unallocated files only
    cmd = [tsk_recover_exe] + image_flags + offset_flags + ["-e", image_path, recovery_dir]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stderr_out = result.stderr.decode(errors="ignore").strip()
    if stderr_out:
        if is_real_error(stderr_out):
            print(f"[ERROR] Failed to recover deleted files: {stderr_out}")
        else:
            print(f"[WARNING] tsk_recover: {stderr_out}")
    recovered_count = count_files(recovery_dir)
    real_error = stderr_out if (stderr_out and is_real_error(stderr_out)) else None
    return {"recovered_count": recovered_count, "recovery_dir": recovery_dir, "error": real_error}

@function_tool
def run_plaso(image_path, output_dir):
    csv_file = os.path.join(output_dir, "timeline.csv")
    plaso_file = os.path.join(output_dir, "timeline.plaso")
    try:
        if os.path.exists(csv_file):
            os.remove(csv_file)
        subprocess.run([sys.executable, "-m", "plaso.scripts.log2timeline", "--storage_file", plaso_file, image_path], check=False)
        subprocess.run([sys.executable, "-m", "plaso.scripts.psort", "-o", "dynamic", "-w", csv_file, plaso_file], check=False)
        return csv_file if os.path.exists(csv_file) else None
    except Exception as e:
        print(f"[WARNING] Plaso failed: {e}")
        return None

@function_tool
def run_raw_carving(image_path, output_dir):
    recovery_dir = os.path.join(output_dir, "Recovered_Raw_Files")
    os.makedirs(recovery_dir, exist_ok=True)
    if not os.path.exists(PHOTOREC_EXE):
        return {"recovered_count": 0, "recovery_dir": recovery_dir, "error": "photorec_win.exe not found"}
    if not os.path.exists(image_path):
        return {"recovered_count": 0, "recovery_dir": recovery_dir, "error": f"Image not found: {image_path}"}
    cmd = [PHOTOREC_EXE, "/d", recovery_dir, "/cmd", image_path, "options,search"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        stderr_out = result.stderr.decode(errors="ignore").strip()
        if stderr_out and is_real_error(stderr_out):
            print(f"[ERROR] PhotoRec: {stderr_out}")
    except OSError as e:
        error_msg = str(e)
        if "740" in error_msg or "elevation" in error_msg.lower():
            print("[WARNING] PhotoRec requires administrator/elevated privileges. Skipping raw carving.")
            return {"recovered_count": 0, "recovery_dir": recovery_dir, "error": "Requires administrator privileges (run as admin)"}
        raise
    recovered_count = count_files(recovery_dir)
    print(f"[INFO] Raw carved files recovered: {recovered_count}")
    return {"recovered_count": recovered_count, "recovery_dir": recovery_dir, "error": None}

def main():
    if len(sys.argv) < 2:
        print("Usage: python DISC.py <disk_image>")
        sys.exit(1)

    image_file = sys.argv[1]
    output_dir = os.path.join(os.path.dirname(image_file), "Forensics_Output")
    os.makedirs(output_dir, exist_ok=True)

    with forensic_session(image_file) as os_info:
        results = {}
        results["Detected_OS"] = os_info
        results["MFT_Bodyfile"] = run_tsk_mft(image_file, output_dir)
        results["Deleted_Files"] = analyze_deleted_files(image_file, output_dir)
        results["Recovered_Deleted_Files"] = recover_deleted_files(image_file, output_dir)
        results["Timeline_CSV"] = run_plaso(image_file, output_dir) is not None
        results["Raw_Carved_Files"] = run_raw_carving(image_file, output_dir)

    summary_file = os.path.join(output_dir, "summary_results.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("[SUMMARY]")
    print(json.dumps(results, indent=2))
    print(f"[DONE] Output in: {output_dir}")

if __name__ == "__main__":
    main()