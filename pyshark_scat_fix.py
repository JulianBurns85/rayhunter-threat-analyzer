"""
pyshark + SCAT Fix for Python 3.14 on Windows

PROBLEM 1 — pyshark "no running event loop":
  Python 3.14 removed implicit event loop creation from asyncio.get_event_loop().
  pyshark internally calls this deprecated function, causing RuntimeError.

FIX: Patch the event loop BEFORE importing pyshark. Add this to the very top
of main.py (before any pyshark imports).

PROBLEM 2 — "SCAT not found":
  SCAT (signalcat) needs to be installed for full QMDL decoding.

FIX: pip install "signalcat[fastcrc]"

Usage:
  python pyshark_scat_fix.py --install    # Install dependencies
  python pyshark_scat_fix.py --test       # Test both work
  python pyshark_scat_fix.py --patch      # Show what to add to main.py
"""

import sys
import subprocess
import os


def install_dependencies():
    """Install pyshark, nest_asyncio, and signalcat."""
    print("=" * 60)
    print("  Installing dependencies for Python 3.14")
    print("=" * 60)
    
    packages = [
        ("nest_asyncio", "nest_asyncio"),
        ("pyshark", "pyshark"),
        ("signalcat[fastcrc]", "signalcat with fast CRC"),
    ]
    
    for pkg, desc in packages:
        print(f"\n  Installing {desc}...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "--break-system-packages"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"    ✅ {desc} installed successfully")
        else:
            # Try without --break-system-packages (Windows doesn't need it)
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"    ✅ {desc} installed successfully")
            else:
                print(f"    ❌ Failed: {result.stderr[:200]}")


def test_pyshark():
    """Test that pyshark works with the event loop fix."""
    print("\n  Testing pyshark...")
    
    # Apply the fix FIRST
    apply_event_loop_fix()
    
    try:
        import pyshark
        print(f"    ✅ pyshark {pyshark.__version__} imported successfully")
        
        # Try opening a test capture if one exists
        test_files = [
            f for f in os.listdir('.') if f.endswith('.pcapng')
        ]
        if test_files:
            cap = pyshark.FileCapture(test_files[0], keep_packets=False)
            pkt_count = 0
            for pkt in cap:
                pkt_count += 1
                if pkt_count >= 3:
                    break
            cap.close()
            print(f"    ✅ Successfully read {pkt_count} packets from {test_files[0]}")
        else:
            print("    ℹ️  No .pcapng files in current directory to test with")
        
        return True
    except Exception as e:
        print(f"    ❌ pyshark test failed: {e}")
        return False


def test_scat():
    """Test that SCAT/signalcat is available."""
    print("\n  Testing SCAT (signalcat)...")
    
    try:
        import scat
        print(f"    ✅ SCAT imported successfully")
        return True
    except ImportError:
        # Try the module directly
        result = subprocess.run(
            [sys.executable, "-m", "scat", "--help"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"    ✅ SCAT available via 'python -m scat'")
            return True
        else:
            print(f"    ❌ SCAT not found. Install with:")
            print(f'       pip install "signalcat[fastcrc]"')
            return False


def apply_event_loop_fix():
    """
    Apply the Python 3.14 event loop fix.
    Call this BEFORE importing pyshark.
    """
    import asyncio
    
    # Method 1: nest_asyncio (preferred — handles nested loops too)
    try:
        import nest_asyncio
        
        # Create and set a new event loop if none exists
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        nest_asyncio.apply(loop)
        return True
    except ImportError:
        pass
    
    # Method 2: Manual event loop creation (fallback)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return True


def show_patch():
    """Show the exact code to add to main.py."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  ADD THIS TO THE VERY TOP OF main.py (before other imports) ║
╚══════════════════════════════════════════════════════════════╝

# --- Python 3.14 asyncio fix for pyshark ---
# Python 3.14 removed implicit event loop creation (PEP 719).
# pyshark requires an event loop to exist before import.
import asyncio
try:
    import nest_asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    nest_asyncio.apply(loop)
except ImportError:
    # Fallback: just create the event loop
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
# --- End asyncio fix ---


╔══════════════════════════════════════════════════════════════╗
║  ALSO: If your pcap_parser.py imports pyshark, add the      ║
║  same block to the top of pcap_parser.py as well.           ║
╚══════════════════════════════════════════════════════════════╝

The fix must execute BEFORE any `import pyshark` statement.
If pyshark is imported in multiple files, add the fix to each one,
OR put it in __init__.py so it runs on package import.

╔══════════════════════════════════════════════════════════════╗
║  FOR SCAT: Run this in PowerShell                           ║
╚══════════════════════════════════════════════════════════════╝

pip install "signalcat[fastcrc]"

Then to decode a QMDL file to PCAPNG:

python -m scat -t qc --qmdl-dir "C:\\path\\to\\qmdl\\files" --pcap output.pcapng

Or for a single file:

python -m scat -t qc --qmdl "C:\\path\\to\\file.qmdl" --pcap output.pcapng
""")


# ============================================================
# Reusable patch function — import this from other modules
# ============================================================

def ensure_event_loop():
    """
    Ensure an asyncio event loop exists. Call before any pyshark usage.
    Safe to call multiple times.
    
    Usage in your code:
        from pyshark_scat_fix import ensure_event_loop
        ensure_event_loop()
        import pyshark  # Now safe on Python 3.14
    """
    import asyncio
    
    try:
        import nest_asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        nest_asyncio.apply(loop)
    except ImportError:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="pyshark + SCAT fix for Python 3.14")
    parser.add_argument("--install", action="store_true", help="Install dependencies")
    parser.add_argument("--test", action="store_true", help="Test pyshark and SCAT")
    parser.add_argument("--patch", action="store_true", help="Show code to add to main.py")
    
    args = parser.parse_args()
    
    print(f"  Python version: {sys.version}")
    print(f"  Python path: {sys.executable}")
    
    if args.install:
        install_dependencies()
    
    if args.test:
        apply_event_loop_fix()
        test_pyshark()
        test_scat()
    
    if args.patch:
        show_patch()
    
    if not (args.install or args.test or args.patch):
        parser.print_help()
