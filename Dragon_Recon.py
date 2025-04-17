#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import socket
import curses
import time
import os
import sys

# --- Configuration ---
SHODAN_API_KEY = "ip7ZvXbD7k8W28Tk8dTIjYZOkHosPv3w" # Hardcoded API key. Hope you like sharing your quota with the world!
WORDLIST_FILE = "subdomains.txt"
OUTPUT_TXT = "output.txt"
OUTPUT_JSON = "output.json"
REQUESTS_TIMEOUT = 15

# --- Curses Color Constants ---
# Define color pair numbers for easy reference
COLOR_PAIR_HEADER = 1        # For ASCII Art / Table Titles
COLOR_PAIR_INFO = 2          # For Domain Status / Table Info
COLOR_PAIR_PROMPT = 3        # For Input Prompt ([?])
COLOR_PAIR_STATUS = 4        # For Status Bar at the Bottom
COLOR_PAIR_MENU_NUMBER = 5   # For Menu Numbers ([01])
COLOR_PAIR_MENU_TEXT = 6     # For Menu Text & Table Items

# --- Core OSINT Functions ---
# (crtsh_enum, brute_subdomains, shodan_lookup, save_results functions
#  DO NOT CHANGE structurally from the previous version, only internal messages)
def crtsh_enum(domain, screen=None):
    """Search for subdomains via crt.sh."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subs = set()
    try:
        response = requests.get(url, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        if "application/json" not in response.headers.get("Content-Type", ""): return []
        data = response.json()
        for entry in data:
            names = entry.get("name_value", "").split("\n"); common_name = entry.get("common_name", "")
            if common_name: names.append(common_name)
            for name in names:
                name = name.strip().lower()
                if name.endswith(f".{domain}") and name != domain:
                    if name.startswith("*."): name = name[2:]
                    if name not in subs and "*" not in name: subs.add(name)
        return sorted(list(subs))
    except requests.exceptions.Timeout:
        if screen: update_status(screen, "[-] Error [crt.sh]: Request timed out.")
        return []
    except requests.exceptions.RequestException as e:
        if screen: update_status(screen, f"[-] Error [crt.sh]: {e}")
        return []
    except json.JSONDecodeError:
        if screen: update_status(screen, "[-] Error [crt.sh]: Failed to parse JSON.")
        return []
    except Exception as e:
        if screen: update_status(screen, f"[-] Error [crt.sh]: An unexpected error occurred: {e}")
        return []

def brute_subdomains(domain, wordlist, screen=None):
    """Perform subdomain brute-forcing."""
    found = []
    total = len(wordlist)
    if screen: update_status(screen, f"[*] Starting brute-force for {total} subdomains for {domain}...")
    for i, sub in enumerate(wordlist):
        target = f"{sub}.{domain}"
        if screen and (i % 20 == 0 or i == total - 1): update_status(screen, f"[*] Trying: {target} [{i+1}/{total}]")
        try:
            socket.setdefaulttimeout(0.8)  # At least you set/reset timeouts. Not bad!
            results = socket.getaddrinfo(target, None)
            ip = next((res[4][0] for res in results if res[0] == socket.AF_INET), None)
            if not ip and results: ip = results[0][4][0]
            if ip: found.append((target, ip))
        except (socket.gaierror, socket.timeout): continue
        except Exception: pass
        finally: socket.setdefaulttimeout(None)  # You remembered to clean up. Gold star!
    return sorted(found)

def shodan_lookup(ip, screen=None):
    """Look up IP information on Shodan."""
    if not SHODAN_API_KEY or SHODAN_API_KEY == "ip7ZvXbD7k8W28Tk8dTIjYZOkHosPv3w": return None # Placeholder check, but the key is still public!
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        if screen: update_status(screen, f"[-] Error [Shodan]: Timeout for {ip}.")
        return {}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404: pass # Not found is not necessarily an error state for the tool
        elif e.response.status_code == 401:
             if screen: update_status(screen, "[-] Error [Shodan]: Invalid API Key.")  # This will happen a lot if you don't change the key!
        else:
             if screen: update_status(screen, f"[-] Error [Shodan]: HTTP Error {e.response.status_code} for {ip}.")
        return {}
    except requests.exceptions.RequestException as e:
        if screen: update_status(screen, f"[-] Error [Shodan]: Connection failed for {ip}: {e}")
        return {}
    except json.JSONDecodeError:
        if screen: update_status(screen, f"[-] Error [Shodan]: Failed to parse JSON for {ip}.")
        return {}
    except Exception as e:
        if screen: update_status(screen, f"[-] Error [Shodan]: Unexpected error for {ip}: {e}")
        return {}

def save_results(domain, subdomains_crt, bruteforce_results, shodan_data, screen=None):
    """Save results to TXT and JSON files."""
    if not domain: return False
    output_data = { "domain": domain, "subdomains_crtsh": subdomains_crt or [],
                    "bruteforce_subdomains": bruteforce_results or [],
                    "shodan_info": shodan_data or {} }
    try:
        with open(OUTPUT_TXT, "w", encoding="utf-8") as txt_file:
            txt_file.write(f"===== OSINT Report for Domain: {domain} =====\n\n")
            txt_file.write("[+] Subdomains from crt.sh:\n");
            if subdomains_crt: [txt_file.write(f" - {s}\n") for s in subdomains_crt]
            else: txt_file.write("   (No data / not run yet)\n")
            txt_file.write("\n[+] Subdomains from Brute-force:\n")
            if bruteforce_results: [txt_file.write(f" - {s} -> {ip}\n") for s,ip in bruteforce_results]
            else: txt_file.write("   (No data / not run yet)\n")
            txt_file.write("\n[+] Shodan Information (based on Brute-force IPs):\n")
            if shodan_data:
                for ip, data in shodan_data.items():
                    txt_file.write(f"\n--- IP: {ip} ---\n")
                    try: txt_file.write(json.dumps(data, indent=2, ensure_ascii=False))
                    except Exception: txt_file.write(str(data)) # Fallback for non-serializable data
                    txt_file.write("\n")
            else: txt_file.write("   (No data / not run yet)\n")
        with open(OUTPUT_JSON, "w", encoding="utf-8") as json_file: json.dump(output_data, json_file, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        if screen: update_status(screen, f"[-] Failed to save file: {e}")
        return False
    except Exception as e:
        if screen: update_status(screen, f"[-] Unexpected error during saving: {e}")
        return False

# --- Curses Display Functions ---
def display_table(screen, data, title):
    """Display data in a paginated table (with red item text)."""
    screen.clear()
    max_y, max_x = screen.getmaxyx(); page_size = max(1, max_y - 6) # Reserve lines for header, info, footer, spacing
    current_page = 0; total_items = len(data)
    total_pages = (total_items + page_size - 1) // page_size if page_size > 0 else 1
    while True:
        screen.clear(); start_index = current_page * page_size
        end_index = min(start_index + page_size, total_items)
        try:
            # Table Title (Red)
            screen.addstr(0, 0, f"--- {title} ---", curses.A_BOLD | curses.color_pair(COLOR_PAIR_HEADER))
            # Page Info (Red)
            if total_items > 0:
                screen.addstr(1, 0, f"Displaying items {start_index + 1}-{end_index} of {total_items}. Page {current_page + 1}/{total_pages}", curses.color_pair(COLOR_PAIR_INFO))
            else: screen.addstr(1, 0, "No data to display.", curses.color_pair(COLOR_PAIR_INFO))
        except curses.error: pass # Handle potential error if screen is too small
        line_num = 3 # Start listing items from line 3
        for i in range(start_index, end_index):
            if line_num < max_y - 2: # Leave space for footer and status bar
                 item_text = str(data[i])
                 if len(item_text) >= max_x: item_text = item_text[: max_x - 1] # Truncate if too long
                 try:
                     # Table Item Text (Red using COLOR_PAIR_MENU_TEXT)
                     screen.addstr(line_num, 0, f"{i + 1}. {item_text}", curses.color_pair(COLOR_PAIR_MENU_TEXT))
                     line_num += 1
                 except curses.error: break # Stop if error (e.g., screen too small)
            else: break # Stop if no more space on screen
        # Table Footer (Red, default background, reverse)
        footer_y = max_y - 1
        footer_text = "[<-] Prev Page | [->] Next Page | [Q] Back to Menu"
        try: screen.addstr(footer_y, 0, footer_text[:max_x-1], curses.A_REVERSE | curses.color_pair(COLOR_PAIR_STATUS))
        except curses.error: pass
        screen.refresh(); key = screen.getch()
        if key == curses.KEY_RIGHT and current_page < total_pages - 1: current_page += 1
        elif key == curses.KEY_LEFT and current_page > 0: current_page -= 1
        elif key in [ord("q"), ord("Q"), 27]: break # 27 is the Escape key

# MODIFICATION update_status: Prefix only, color from COLOR_PAIR_STATUS
def update_status(screen, message):
    """Display a status message on the bottom line with a prefix."""
    prefix = "[*] "; msg_lower = message.lower()
    # Determine prefix based on keywords or explicit prefixes
    if msg_lower.startswith("[-]"): prefix = "[-] "; message = message[3:].strip()
    elif msg_lower.startswith("[+]"): prefix = "[+] "; message = message[3:].strip()
    elif msg_lower.startswith("[!]"): prefix = "[!] "; message = message[3:].strip()
    elif msg_lower.startswith("[*]"): prefix = "[*] "; message = message[3:].strip()
    elif "error" in msg_lower or "failed" in msg_lower or "❌" in message: prefix = "[-] "
    elif "warning" in msg_lower or "⚠️" in message: prefix = "[!] "
    elif "found" in msg_lower or "✅" in message or "success" in msg_lower or "finished" in msg_lower or "completed" in msg_lower: prefix = "[+] "
    elif "starting" in msg_lower or "searching" in msg_lower or "loading" in msg_lower or "⏳" in message or "🔍" in message or "📡" in message or "trying" in msg_lower: prefix = "[*] "

    full_message = f"{prefix}{message}"
    max_y, max_x = screen.getmaxyx(); status_y = max_y - 1
    try:
        screen.move(status_y, 0); screen.clrtoeol() # Clear the line first
        # Use COLOR_PAIR_STATUS (red, default bg) + A_REVERSE
        screen.addstr(status_y, 0, full_message[: max_x - 1], curses.A_REVERSE | curses.color_pair(COLOR_PAIR_STATUS))
    except curses.error: pass # Ignore errors if screen is too small
    screen.refresh()

def get_input(screen, prompt):
    """Get string input from the user (red prompt)."""
    max_y, max_x = screen.getmaxyx(); input_y = max_y - 2 # Line above the status bar
    prompt_text = f"[?] {prompt} : "
    input_str = ""
    try:
        screen.move(input_y, 0); screen.clrtoeol() # Clear the input line
        # Use COLOR_PAIR_PROMPT (red)
        screen.addstr(input_y, 0, prompt_text, curses.color_pair(COLOR_PAIR_PROMPT))
        screen.refresh(); curses.echo(); screen.keypad(False) # Enable echo for typing, disable special keys
        # Get input, limiting length to available space
        input_str = screen.getstr(input_y, len(prompt_text), max_x - len(prompt_text) - 1).decode("utf-8", "ignore")
    finally:
        curses.noecho(); screen.keypad(True) # Disable echo, re-enable special keys
        try: screen.move(input_y, 0); screen.clrtoeol(); screen.refresh() # Clear the input line after getting input
        except curses.error: pass
    return input_str.strip()

def draw_main_menu(screen, domain, results_summary):
    """Draw the main menu display (all text red)."""
    screen.clear()
    max_y, max_x = screen.getmaxyx()
    MIN_MENU_AREA_HEIGHT = 10 # Minimum rows for menu + bottom status

    # --- ASCII Art --- (String art unchanged)
    ascii_art_str = """
____________  ___  _____ _____ _   _       ______ _____ _____ _____ _   _
|  _  \ ___ \/ _ \|  __ \  _  | \ | |      | ___ \  ___/  __ \  _  | \ | |
| | | | |_/ / /_\ \ |  \/ | | |  \| |______| |_/ / |__ | /  \/ | | |  \| |
| | | |    /|  _  | | __| | | | . ` |______|    /|  __|| |   | | | | . ` |
| |/ /| |\ \| | | | |_\ \ \_/ / |\  |      | |\ \| |___| \__/\ \_/ / |\  |
|___/ \_| \_\_| |_/\____/\___/\_| \_/      \_| \_\____/ \____/\___/\_| \_/

 ========================================
 DRAGON-RECON
 author   : PYSCODES
 support  : https://linktr.ee/pyscodes
 contact  : https://instagram.com/pyscodes
 ========================================
 OSINT RECON TOOL / BRUTEFORCE
 ========================================
    """
    all_ascii_lines = [line for line in ascii_art_str.strip("\n").split("\n")]
    total_art_lines = len(all_ascii_lines)
    # Calculate available height for art, ensuring non-negative
    available_art_height = max(0, max_y - MIN_MENU_AREA_HEIGHT)
    lines_to_draw = min(total_art_lines, available_art_height)
    start_y_art = 0; drawn_art_height = 0
    for i in range(lines_to_draw): # Draw Art (Red)
        line = all_ascii_lines[i].rstrip(); start_x = max(0, (max_x - len(line)) // 2) # Center align
        try:
            screen.addstr(start_y_art + i, start_x, line, curses.A_BOLD | curses.color_pair(COLOR_PAIR_HEADER))
            drawn_art_height += 1
        except curses.error:
            # Try drawing truncated line if full line fails (small terminal)
            try:
                screen.addstr(start_y_art + i, start_x, line[: max_x - 1], curses.A_BOLD | curses.color_pair(COLOR_PAIR_HEADER))
                drawn_art_height += 1
            except curses.error: pass # Skip if even truncated fails
    # Calculate where the menu starts
    menu_start_y = start_y_art + drawn_art_height
    if drawn_art_height > 0 and menu_start_y < max_y - MIN_MENU_AREA_HEIGHT + 1: menu_start_y += 1 # Add a blank line if art was drawn
    elif drawn_art_height == 0: menu_start_y = 1 # Start menu near top if no art
    current_y = menu_start_y
    # Domain Status (Red)
    domain_status = f"[*] Target Domain : {domain if domain else '[Not Set]'}"
    # Ensure there's enough space below for domain status, menu, prompt, status bar
    required_lines_below = 1 + 1 + 6 + 1 + 1 # Domain line + space + menu items + space + prompt
    if current_y < max_y - required_lines_below:
        try: screen.addstr(current_y, 1, domain_status[:max_x-2], curses.color_pair(COLOR_PAIR_INFO)); current_y += 2 # Add space after domain
        except curses.error: pass

    # Menu Items (Number & Text Red)
    menu_items = [ ("Set/Change Target Domain", None),
                   ("Search Subdomains (crt.sh)", "crtsh"),
                   ("Brute-force Subdomains", "brute"),
                   ("Scan Shodan (from Brute results)", "shodan"),
                   ("Save All Results", "saved"),
                   ("Exit", None) ]
    for i, (text, summary_key) in enumerate(menu_items):
        if current_y < max_y - 2: # Ensure space for prompt and status bar
            status = ""
            if summary_key:
                count = results_summary.get(summary_key)
                if isinstance(count, int) and count > 0: status = f" ({count} found)"
                elif summary_key == "saved" and count: status = " (Ready to save)" # 'count' here is boolean from results_summary
            menu_number_str = f"[{i+1:02d}]"; menu_text_line = f" {text}{status}"
            try:
                # Draw menu number (bold red)
                screen.addstr(current_y, 1, menu_number_str, curses.color_pair(COLOR_PAIR_MENU_NUMBER) | curses.A_BOLD)
                # Draw menu text (red), truncated if needed
                screen.addstr(current_y, 1 + len(menu_number_str), menu_text_line[:max_x - 2 - len(menu_number_str)], curses.color_pair(COLOR_PAIR_MENU_TEXT))
                current_y += 1
            except curses.error: break # Stop drawing menu if screen too small
        else: break
    prompt_y = current_y + 1 # Position prompt below menu
    if prompt_y < max_y -1: # Ensure space for status bar
         try: screen.addstr(prompt_y, 1, "[?] Enter Choice : ", curses.color_pair(COLOR_PAIR_PROMPT))
         except curses.error: pass
    screen.refresh()

# --- Main Curses Application Function ---
def run_osint_app(screen):
    """Main function to run the OSINT application in curses mode."""
    # Initialize Curses
    curses.curs_set(0); screen.keypad(True); curses.start_color()
    curses.use_default_colors() # Important for background -1 to work (use default terminal background)

    # --- MODIFICATION Initialize Color Pairs ---
    # All foregrounds set to RED, background set to default terminal (-1)
    curses.init_pair(COLOR_PAIR_HEADER, curses.COLOR_RED, -1) # Everything is red. If you want to simulate a fire alarm, this is perfect.
    curses.init_pair(COLOR_PAIR_INFO, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_PAIR_PROMPT, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_PAIR_MENU_NUMBER, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_PAIR_MENU_TEXT, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_PAIR_STATUS, curses.COLOR_RED, -1)

    # Application State
    domain = None; subdomains_crt = []; bruteforce_results = []; shodan_data = {}
    wordlist = []; wordlist_loaded = False

    curses_error_message = None # To store error if curses fails during runtime

    # Main Loop
    while True:
        update_status(screen, "Waiting for command...") # Default status (Red)
        results_summary = { "crtsh": len(subdomains_crt), "brute": len(bruteforce_results),
                            "shodan": len(shodan_data),
                            "saved": bool(domain and (subdomains_crt or bruteforce_results or shodan_data)) }

        # Draw menu (now all its elements are red)
        draw_main_menu(screen, domain, results_summary)
        key = screen.getch() # Get input

        # Process Action
        try:
            if key == ord('1'): # Set Domain
                new_domain = get_input(screen, "Enter target domain (e.g., example.com)") # Red Prompt
                if new_domain:
                    if new_domain != domain:
                        update_status(screen, f"[+] Domain changed to {new_domain}. Results reset.") # Red Status
                        domain = new_domain; subdomains_crt = []; bruteforce_results = []; shodan_data = {}; wordlist_loaded = False
                        time.sleep(1.5)
                    else: update_status(screen, f"[*] Target domain is already {domain}."); time.sleep(1) # Red Status
                else: update_status(screen, "[!] Domain input cancelled."); time.sleep(1) # Red Status

            elif key == ord('2'): # crt.sh
                if not domain: update_status(screen, "[-] Target domain not set."); time.sleep(2); continue # Red Status
                update_status(screen, f"[*] Searching for {domain} subdomains via crt.sh...") # Red Status
                subdomains_crt = crtsh_enum(domain, screen) # OSINT function will update status if error (red)
                if subdomains_crt:
                    update_status(screen, f"[+] Found {len(subdomains_crt)} subdomains. Displaying...") # Red Status
                    time.sleep(0.5)
                    display_table(screen, subdomains_crt, f"crt.sh Subdomains ({len(subdomains_crt)})") # Red Table
                else:
                    # Check if the last status was *not* an error message from crtsh_enum
                    try: current_status = screen.instr(curses.LINES - 1, 0).decode("utf-8", "ignore").strip()
                    except curses.error: current_status = ""
                    if not current_status.startswith("[-] Error [crt.sh]"): update_status(screen, f"[*] No results from crt.sh for {domain}."); time.sleep(2) # Red Status
                    else: time.sleep(2) # Keep the error message visible

            elif key == ord('3'): # Brute-force
                if not domain: update_status(screen, "[-] Target domain not set."); time.sleep(2); continue # Red Status
                if not wordlist_loaded: # Load Wordlist (red status messages)
                    update_status(screen, f"[*] Loading wordlist '{WORDLIST_FILE}'...")
                    try:
                        if not os.path.exists(WORDLIST_FILE): update_status(screen, f"[-] Error: File '{WORDLIST_FILE}' not found."); time.sleep(3); continue
                        with open(WORDLIST_FILE, 'r', encoding="utf-8", errors='ignore') as f: wordlist = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
                        if not wordlist: update_status(screen, f"[-] Error: File '{WORDLIST_FILE}' is empty."); time.sleep(3); continue
                        wordlist_loaded = True; update_status(screen, f"[+] Wordlist loaded ({len(wordlist)} entries)."); time.sleep(1)
                    except Exception as e: update_status(screen, f"[-] Failed to load wordlist: {e}"); time.sleep(3); continue
                bruteforce_results = brute_subdomains(domain, wordlist, screen) # Progress updates are red
                if bruteforce_results:
                    update_status(screen, f"[+] Found {len(bruteforce_results)} valid subdomains. Displaying...") # Red Status
                    time.sleep(0.5)
                    display_data = [f"{sub} -> {ip}" for sub, ip in bruteforce_results]
                    display_table(screen, display_data, f"Brute-force Results ({len(display_data)})") # Red Table
                else: update_status(screen, "[*] No valid subdomains found via brute-force."); time.sleep(2) # Red Status

            elif key == ord('4'): # Shodan
                if not bruteforce_results: update_status(screen, "[-] Run Brute-force [03] first."); time.sleep(2); continue # Red Status
                # Check actual placeholder value too, in case user didn't change it
                if not SHODAN_API_KEY or SHODAN_API_KEY == "ip7ZvXbD7k8W28Tk8dTIjYZOkHosPv3w": update_status(screen, "[-] Shodan API Key not configured or is placeholder."); time.sleep(3); continue # This will trigger for everyone who clones your repo and doesn't read the comments.
                shodan_data = {}; ips_to_scan = list(set([ip for _, ip in bruteforce_results])); total_ips = len(ips_to_scan)
                if total_ips == 0: update_status(screen, "[*] No unique IPs to scan from brute-force results."); time.sleep(2); continue # Red Status
                update_status(screen, f"[*] Starting Shodan scan for {total_ips} unique IPs..."); time.sleep(1) # Red Status
                results_found_count = 0; api_key_valid = True
                for i, ip in enumerate(ips_to_scan): # Red progress updates
                    if not api_key_valid: break # Stop if API key proves invalid
                    update_status(screen, f"[*] Checking IP: {ip} [{i+1}/{total_ips}]...")
                    info = shodan_lookup(ip, screen) # Handles errors internally (red status)
                    if info is None: # This happens if API key is literally None
                         update_status(screen, "[-] Error [Shodan]: API Key is not set in config?"); api_key_valid = False; time.sleep(2); break
                    elif info: shodan_data[ip] = info; results_found_count += 1
                    # Check if shodan_lookup posted an invalid key error
                    try: current_status = screen.instr(curses.LINES - 1, 0).decode("utf-8", "ignore").strip()
                    except curses.error: current_status = ""
                    if "Invalid API Key" in current_status: api_key_valid = False; time.sleep(2) # No need to continue loop
                    time.sleep(0.6) # "Rate limiting courtesy delay" - Shodan's actual limits may differ. This is wishful thinking, but at least you tried!
                if results_found_count > 0:
                    update_status(screen, f"[+] Shodan scan finished ({results_found_count}/{total_ips} IPs had info). Displaying summary...") # Red Status
                    time.sleep(0.5)
                    display_data = [] # Red Table data prep
                    for ip, data in shodan_data.items():
                        os_info=data.get('os','N/A'); ports=", ".join(map(str,data.get('ports',[]))); org=data.get('org','N/A')
                        summary=f"OS:{os_info} | Ports:[{ports if ports else 'N/A'}] | Org:{org}"
                        display_data.append(f"{ip}: {summary}")
                    display_table(screen, display_data, f"Shodan Scan Summary ({results_found_count} IPs)")
                elif api_key_valid: update_status(screen, f"[*] Shodan scan finished. No info found for {total_ips} IPs checked."); time.sleep(2) # Red Status

            elif key == ord('5'): # Save
                if not domain: update_status(screen, "[-] No domain processed yet."); time.sleep(2) # Red Status
                elif not subdomains_crt and not bruteforce_results and not shodan_data: update_status(screen, "[!] No results to save yet."); time.sleep(2) # Red Status
                else:
                    update_status(screen, f"[*] Saving results for {domain} to {OUTPUT_TXT} and {OUTPUT_JSON}...") # Red Status
                    success = save_results(domain, subdomains_crt, bruteforce_results, shodan_data, screen) # Red error status if fails
                    if success: update_status(screen, f"[+] Results saved successfully.") # Red Status
                    time.sleep(2)

            elif key in [ord('6'), ord('q'), ord('Q'), 27]: # Exit
                break

        except curses.error as e:
             # Try to capture the error message before exiting curses mode
             curses_error_message = f"Curses error during action processing: {e}"
             break # Exit the main loop on curses error

# --- Program Entry Point ---
if __name__ == "__main__":
    curses_error_message_main = None # To store potential error from wrapper
    # Initial checks (outside curses)
    api_key_ok = True; wordlist_ok = True
    # Check actual placeholder value too
    if not SHODAN_API_KEY or SHODAN_API_KEY == "ip7ZvXbD7k8W28Tk8dTIjYZOkHosPv3w": print("WARNING: SHODAN_API_KEY is not set or is the default placeholder!"); api_key_ok = False
    if not os.path.exists(WORDLIST_FILE): print(f"WARNING: Wordlist '{WORDLIST_FILE}' not found!"); wordlist_ok = False
    if not api_key_ok or not wordlist_ok: print("Continuing in 3 seconds..."); time.sleep(3)

    try:
        # curses.wrapper handles setup and cleanup (restoring terminal)
        curses.wrapper(run_osint_app)
        print("\n[+] Thank you for using Dragon Recon!")  # The branding is strong with this one.
    except curses.error as e:
        # Capture error if wrapper itself fails or if passed from run_osint_app
        if not curses_error_message_main: curses_error_message_main = str(e)
        print(f"\n[-] A Curses error occurred: {curses_error_message_main}")
        print("    Ensure the terminal supports curses and has adequate dimensions (width/height).")
    except KeyboardInterrupt:
        print("\n[!] Process interrupted (Ctrl+C).")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"\n[-] An unexpected error occurred: {e}")

    sys.exit(0)
