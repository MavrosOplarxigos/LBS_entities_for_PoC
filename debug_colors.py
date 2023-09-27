from colorama import init, Fore
# Colors for debugging
#RESET = '\033[0m'
RESET = Fore.RESET
#RED = '\033[91m'
RED = Fore.RED
#GREEN = '\033[92m'
GREEN = Fore.GREEN
#YELLOW = '\033[93m'
YELLOW = Fore.YELLOW
ORANGE = '\033[91m'

CLEAR_SCREEN = '\033[2J'
MOVE_CURSOR_TOP_LEFT = '\033[H'

def clear_screen_and_reset_pointer():
    print(f"{CLEAR_SCREEN}{MOVE_CURSOR_TOP_LEFT}")
