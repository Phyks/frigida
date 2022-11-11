Frigida
=======

Inject frida-gadget into an existing APK file.


## Requirements

* Java
* Android SDK tools in `$PATH` (`aapt`, `keytool`, etc.).
* [`apktool`](https://github.com/iBotPeaches/Apktool)
* `openssl` / `xxd` / `tr` commands


## Installation

```
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```


## Usage

```
./.venv/bin/python -m frigida $PATH_TO_APK_FILE $TARGET_ARCHITECTURE
```

Current working directory will be used for extracting APK. At the end of the
process:

* `frida-gadget-script.js` in the working directory contains a base Frida Gadget
    script to load.
* `$APK_NAME/dist/$APK_NAME-aligned-debugSigned.apk` in the working directory
    contains the APK with frida-gadget injected and ready to be installed.


## License

Released under an MIT license.
