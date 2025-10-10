# AWP - Android Widevine Proxy
ADB Proxy for Widevine challenges/licenses between the Android MediaDrm API and an App 

## Requirements
An Android Phone with the following:
+ USB debugging
+ ADB 
+ frida-server running

## Installation
+ Install the `requirements.txt` file

## Usage
AWP is run per app, which should already be running when attempting to launch the program. \
Keys are printed the specified format as soon as a challenge and license were received.

```
usage: main.py [-h] [--key-format {default,mp4decrypt,shaka-packager}] [--token-only] <APP_NAME> <WVD>

AWP - Android Widevine Proxy

positional arguments:
  <APP_NAME>            The name of the app to intercept
  <WVD>                 Path of the widevine device

options:
  -h, --help            show this help message and exit
  --key-format {default,mp4decrypt,shaka-packager}
                        Format of printed keys
  --token-only          Only replace the token in the challenge (only if privacy mode is off)
```

## Agent Compilation
Run `npm run compile` to properly compile the frida script if you need to make any changes.

## Demo
[demo.webm](https://github.com/user-attachments/assets/e50abd4b-c252-4927-b9cd-974e40d353d1)