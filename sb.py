from core.cli import SnakeBite


def banner():
    print("""
 _______ __    _ _______ ___   _ _______   _______ ___ _______ _______ 
|       |  |  | |   _   |   | | |       | |  _    |   |       |       |
|  _____|   |_| |  |_|  |   |_| |    ___| | |_|   |   |_     _|    ___|
| |_____|       |       |      _|   |___  |       |   | |   | |   |___ 
|_____  |  _    |       |     |_|    ___| |  _   ||   | |   | |    ___|
 _____| | | |   |   _   |    _  |   |___  | |_|   |   | |   | |   |___ 
|_______|_|  |__|__| |__|___| |_|_______| |_______|___| |___| |_______|
    """)


if __name__ == "__main__":
    banner()
    rainmaker = SnakeBite()
    rainmaker.cmdloop()
