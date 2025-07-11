#!/usr/bin/env python3

"""
Vuln Scanner - Advanced Web Security Scanner
A comprehensive web security scanning tool with a dark mode web interface.

Usage:
    python3 start.py [port]         # Run web interface (default port: 8080)
    python3 start.py --help         # Show this help message
"""

import sys
import argparse
from web_app import start_server

def show_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗    ║
    ║   ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝    ║
    ║   ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║         ║
    ║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║         ║
    ║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗    ║
    ║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝    ║
    ║                                                               ║
    ║           Advanced Web Security Scanner                       ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='Vuln Scanner - Advanced Web Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        'port',
        nargs='?',
        default=8080,
        type=int,
        help='Port to run web interface on (default: 8080)'
    )
    
    args = parser.parse_args()
    
    print(f"🌐 Starting web interface on port {args.port}...")
    print(f"🔗 Open your browser and go to: http://localhost:{args.port}")
    print("📱 The interface features a dark mode minimalistic design")
    print("⚡ Real-time scanning progress and advanced results display\n")
    start_server(args.port)

if __name__ == "__main__":
    main()