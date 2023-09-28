# snake-bite

An experimental tool for analyzing batches of Android APK(s) in order
to discover misconfigurations, vulnerabilities and interesting code patterns.

## Run
```commandline
python3 sb.py 

 _______ __    _ _______ ___   _ _______   _______ ___ _______ _______ 
|       |  |  | |   _   |   | | |       | |  _    |   |       |       |
|  _____|   |_| |  |_|  |   |_| |    ___| | |_|   |   |_     _|    ___|
| |_____|       |       |      _|   |___  |       |   | |   | |   |___ 
|_____  |  _    |       |     |_|    ___| |  _   ||   | |   | |    ___|
 _____| | | |   |   _   |    _  |   |___  | |_|   |   | |   | |   |___ 
|_______|_|  |__|__| |__|___| |_|_______| |_______|___| |___| |_______|
    
(snakebite) > 
```

## Commands

`scan`
+ Scan a directory of APK(s)
+ Scan a single APK

`scan --batch -p /path/to/directory`

`scan -p /path/to/APK`

## TODO
+ Add switch for number of processes to `scan` command
