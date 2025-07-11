#!/usr/bin/env python3

"""
Vuln Scanner - Advanced Web Security Scanner
A comprehensive web security scanning tool with a dark mode web interface.

Usage:
    python3 start.py --cli                # Run in CLI mode
    python3 start.py --web [port]         # Run web interface (default port: 8080)
    python3 start.py --help               # Show this help message
"""

import sys
import argparse
from scan import main as cli_main
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
        '--cli',
        action='store_true',
        help='Run in CLI mode (interactive command line)'
    )
    
    parser.add_argument(
        '--web',
        nargs='?',
        const=8080,
        type=int,
        metavar='PORT',
        help='Run web interface on specified port (default: 8080)'
    )
    
    args = parser.parse_args()
    
    if args.cli:
        print("🔍 Starting CLI mode...\n")
        cli_main()
    elif args.web is not None:
        print(f"🌐 Starting web interface on port {args.web}...")
        print(f"🔗 Open your browser and go to: http://localhost:{args.web}")
        print("📱 The interface features a dark mode minimalistic design")
        print("⚡ Real-time scanning progress and advanced results display\n")
        start_server(args.web)
    else:
        print("❓ Please specify either --cli or --web mode")
        print("   Example: python3 start.py --web")
        print("   Example: python3 start.py --cli")
        print("   Use --help for more information")

if __name__ == "__main__":
    main()