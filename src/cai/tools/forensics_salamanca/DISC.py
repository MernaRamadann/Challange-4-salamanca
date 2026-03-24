import os
import sys
import json
import subprocess
from contextlib import contextmanager

# مسار fls.exe من Sleuth Kit
FLS_EXE = r"C:\Users\WinLab\Desktop\sleuthkit-4.14.0-win32\bin\fls.exe"

def function_tool(func):
    def wrapper(*args, **kwargs):
        print(f"[TOOL] Running {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

@contextmanager
def forensic_session(image_path):
    os_type = detect_os(image_path)
    print(f"[INFO] Detected OS: {os_type}")
    try:
        yield os_type
    finally:
        print("[INFO] Forensic session ended.")

def detect_os(image_path):
    # نفترض Windows بشكل افتراضي
    return 'windows'

@function_tool
def run_tsk_mft(image_path, output_dir):
    if not os.path.exists(FLS_EXE):
        print("[ERROR] fls.exe not found! Check FLS_EXE path.")
        return None

    bodyfile_path = os.path.join(output_dir, "bodyfile.txt")
    fls_cmd = [
        FLS_EXE,
        "-r",
        image_path
    ]
    try:
        with open(bodyfile_path, "w", encoding="utf-8") as f:
            subprocess.run(fls_cmd, stdout=f, check=False)
        return bodyfile_path if os.path.exists(bodyfile_path) else None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

@function_tool
def run_plaso(image_path, output_dir):
    try:
        import plaso
    except ImportError:
        print("[WARNING] Plaso not installed, skipping timeline generation.")
        return None

    plaso_file = os.path.join(output_dir, "timeline.plaso")
    csv_file = os.path.join(output_dir, "timeline.csv")

    if os.path.exists(csv_file):
        os.remove(csv_file)

    cmd_log2timeline = [
        sys.executable, "-m", "plaso.scripts.log2timeline",
        "--storage_file", plaso_file,
        image_path
    ]
    subprocess.run(cmd_log2timeline, check=False)

    cmd_psort = [
        sys.executable, "-m", "plaso.scripts.psort",
        "-o", "dynamic",
        "-w", csv_file,
        plaso_file
    ]
    subprocess.run(cmd_psort, check=False)

    return csv_file if os.path.exists(csv_file) else None

def main():
    if len(sys.argv) < 2:
        print("Usage: python DISC.py <disk_image>")
        sys.exit(1)

    image_file = sys.argv[1]
    output_dir = os.path.join(os.path.dirname(image_file), "Forensics_Output")
    os.makedirs(output_dir, exist_ok=True)

    with forensic_session(image_file) as os_type:
        results = {}

        if os_type == "windows":
            results["MFT_Bodyfile"] = run_tsk_mft(image_file, output_dir)
        else:
            print("[INFO] Skipping MFT analysis (non-Windows)")

        csv_path = run_plaso(image_file, output_dir)
        results["Timeline_CSV"] = csv_path is not None
        if csv_path:
            print(f"[INFO] Timeline CSV generated: {csv_path}")

    summary_file = os.path.join(output_dir, "summary_results.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("[SUMMARY]")
    print(json.dumps(results, indent=2))
    print(f"[DONE] Output in: {output_dir}")

if __name__ == "__main__":
    main()