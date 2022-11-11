import logging
import lzma
import os
import re
import subprocess
import tempfile
from pathlib import Path

import apksigcopier
import jinja2
import lief
import requests


GADGET_SCRIPT_TEMPLATE = """
Java.perform(function () {
    /**
     * Convert an hex-string to an array of int.
     *
     * Based on an implementation from crypto-js.
     * Taken from https://stackoverflow.com/a/34356351
     */
    function hexToBytes(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }
        return bytes;
    }

    /*
     * Bypass package certificate hash.
     *
     * Altering the APK (embedding frida-gadget + resigning) does change the
     * SHA-1 of the signing certificate.
     *
     * GCM/Firebase sends this to the server to check the APK is authorized in
     * developer account (they have to declare their signing certificate for
     * distributed APK embedding GCM/Firebase).
     *
     * Hence, GCM/Firebase is no longer working in altered APKs, often
     * materializing through an "Play Store / Play Services are not available"
     * error message.
     *
     * See https://github.com/firebase/firebase-android-sdk/blob/dcf82a5296b86f04c0b8ce162e0437c7aeb42734/firebase-installations/src/main/java/com/google/firebase/installations/remote/FirebaseInstallationServiceClient.java
     * and https://github.com/firebase/firebase-android-sdk/blob/dcf82a5296b86f04c0b8ce162e0437c7aeb42734/firebase-installations/src/main/java/com/google/firebase/installations/FirebaseInstallations.java.
     *
     * This hook bypasses the certificate check by force-returning the original one.
     */
    // Output of:
    //      keytool -printcert -jarfile "ORIGINAL_UNALTERED_APK.apk" | grep "SHA 1:"
    var INITIAL_CERTIFICATE_HASH = "{{ initial_certificate_hash }}";
    // Output of:
    //      mkdir sigs && apksigcopier extract base.apk sigs
    //      openssl pkcs7 -in sigs/BNDLTOOL.RSA -inform DER -print_certs | openssl x509 -outform DER | xxd -p | tr -d \\n
    var RAW_SIGNING_CERTIFICATE = "{{ raw_signing_certificate }}";

    // Bypass through GMS API
    var AndroidUtilsLight = Java.use('com.google.android.gms.common.util.AndroidUtilsLight');
    AndroidUtilsLight.getPackageCertificateHashBytes.implementation = function (context, packageName) {
        var value = Java.array("byte", hexToBytes(INITIAL_CERTIFICATE_HASH.replaceAll(':', '')))
        return value;
    }

    // Bypass accessing certs through Android package manager API
    var Signature = Java.use('android.content.pm.Signature');
    Java.use('android.app.ApplicationPackageManager').getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
        // See https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES
        // Android API level >= 28
        if (packageName == '{{ package_name }}' && flags == 134217728) {
            var value = this.getPackageInfo(packageName, flags);
            // Overload the returned signatures
            value.signingInfo.value.getApkContentsSigners.implementation = function () {
                // TODO: Handle multiple signers / history
                return Java.array(
                    'android.content.pm.Signature',
                    [Signature.$new(RAW_SIGNING_CERTIFICATE)]
                );
            };

            value.signingInfo.value.getSigningCertificateHistory.implementation = function () {
                return Java.array(
                    'android.content.pm.Signature',
                    [Signature.$new(RAW_SIGNING_CERTIFICATE)]
                );
            };

            return value;
        }
        return this.getPackageInfo(packageName, flags);
    };

    // Also unblock FCM requests.
    var d = Java.use('com.google.firebase.installations.remote.RequestLimiter');
    d.isRequestAllowed.implementation = function () {
        var ret = this.isRequestAllowed();
        return true;
    };


    /*
     * Log SSL/TLS keys.
     *
     * See https://github.com/PiRogueToolSuite/pirogue-cli/blob/main/pirogue_cli/frida-scripts/log_ssl_keys.js
     */
    function _log_ssl_keys(SSL_CTX_new, SSL_CTX_set_keylog_callback) {
        function log_key(ssl, line) {
            const s_line = new NativePointer(line).readCString();
            console.log(s_line);
        }
        const keylogCallback = new NativeCallback(log_key, 'void', ['pointer', 'pointer'])

        Interceptor.attach(SSL_CTX_new, {
            onLeave: function(retval) {
                const ssl = new NativePointer(retval);
                if (!ssl.isNull()) {
                    const SSL_CTX_set_keylog_callbackFn = new NativeFunction(SSL_CTX_set_keylog_callback, 'void', ['pointer', 'pointer']);
                    SSL_CTX_set_keylog_callbackFn(ssl, keylogCallback);
                }
            }
        });
    }
    _log_ssl_keys(
        Module.findExportByName('libssl.so', 'SSL_CTX_new'),
        Module.findExportByName('libssl.so', 'SSL_CTX_set_keylog_callback')
    );
});
"""

def get_package_name(apk_path):
    """
    Get the package name (com.example) from an APK.

    :param apk_path: Path to the APK file.
    :returns: Package name.
    """
    aapt_dump_out = subprocess.check_output(
        ['aapt', 'dump', 'badging', apk_path]
    ).decode()
    return re.search(r"name='(.*?)'", aapt_dump_out).group(1)


def decompress_apk(
    apk_path,
    should_not_decode_res=False, should_not_decode_src=True
):
    """
    Decompress APK file using apktool

    APK is uncompressed in a folder named without the .apk extension in the
    working directory.

    :param apk_path: Path to the APK file.
    :param should_not_decode_res: Do not decode resources. (default False)
    :param should_not_decode_src: Do not decode sources. Speeds up
        unpacking/repacking. (default True)
    """
    logging.info('Uncompressing apk with apktool...')
    optional_args = []
    if should_not_decode_res:
        optional_args.append('-r')
    if should_not_decode_src:
        optional_args.append('-s')

    return subprocess.run(
        ['apktool', 'd'] + optional_args + [apk_path]
    )


def inject_frida_gadget(uncompressed_apk_path, target_architecture):
    """
    Inject frida gadget in the libs from the APK.

    See https://fadeevab.com/frida-gadget-injection-on-android-no-root-2-methods/.

    :param uncompressed_apk_path: Folder of the output from apktool.
    :param target_architecture: Architecture to target for injection.
    """
    libs_path = Path(uncompressed_apk_path) / 'lib'
    for dir in os.listdir(libs_path):
        # Find correct subdirectory based on target architecture
        if dir.startswith(target_architecture):
            libs_path = libs_path / dir
            break
    libfridagadget_name = 'libgadget.so'

    if not os.path.isfile(libs_path / libfridagadget_name):
        logging.info('Download Frida-gadget into apk libs...')
        latest_release = requests.get(
            'https://api.github.com/repos/frida/frida/releases/latest'
        ).json()
        download_url = next(
            asset['browser_download_url']
            for asset in latest_release['assets']
            if (
                asset['name'].startswith('frida-gadget-')
                and asset['name'].endswith(f'-android-{target_architecture}.so.xz')
            )
        )
        req = requests.get(
            download_url
        )
        with open(libs_path / libfridagadget_name, 'wb') as fh:
            fh.write(lzma.LZMADecompressor().decompress(req.content))

    logging.info('Injecting Frida-gadget lib in apk libs...')
    apk_libs = [item for item in os.listdir(libs_path)]
    if not apk_libs:
        logging.error('APK does not have any lib for injection!')
        raise Exception('APK does not have any lib for injection!')
    for lib in apk_libs:
        libnative = lief.parse(str(libs_path / lib))
        libnative.add_library(libfridagadget_name)  # Injection!
        libnative.write(str(libs_path / lib))


def rebuild_apk(uncompressed_apk_path, optional_args=['--use-aapt2']):
    """
    Rebuild APK

    New (rebuilt) APK is generated in ``dist/`` folder under the unpacked APK
    tree.

    :param uncompressed_apk_path: Path to the apk ressources.
    :param optional_args: Extra arguments to pass to apktool.
    """
    logging.info('Ensure android:extractNativeLibs is true in the AndroidManifest.xml...')
    # https://stackoverflow.com/questions/42998083/setting-androidextractnativelibs-false-to-reduce-app-size
    with open(Path(uncompressed_apk_path) / 'AndroidManifest.xml', 'r') as fh:
        android_manifest = fh.read()
    if 'android:extractNativeLibs="false"' in android_manifest:
        with open(Path(uncompressed_apk_path) / 'AndroidManifest.xml', 'w') as fh:
            fh.write(
                android_manifest.replace(
                    'android:extractNativeLibs="false"',
                    'android:extractNativeLibs="true"',
                )
            )

    logging.info('Rebuilding APK...')
    return subprocess.run(
        ['apktool', 'b'] + optional_args + [uncompressed_apk_path]
    )


def resign_apk(apk_path):
    """
    Resign the APK with uber apk signer.

    APK is generated beside the source APK file with a ``-aligned-debugSigned``
    suffix.

    :param apk_path: Path to the APK to sign.
    """
    latest_release = requests.get(
        'https://api.github.com/repos/patrickfav/uber-apk-signer/releases/latest'
    ).json()
    download_url, jar_name = next(
        (asset['browser_download_url'], asset['name'])
        for asset in latest_release['assets']
        if asset['name'].endswith('.jar')
    )
    if not os.path.isfile(jar_name):
        with open(jar_name, 'wb') as fh:
            fh.write(
                requests.get(download_url).content
            )
    return subprocess.run(
        [
            'java', '-jar', jar_name,
            '-a', apk_path
        ]
    )


def prepare_gadget_script(apk_path, package_name):
    """
    Prepare the Frida Gadget script to be loaded upon APK loading to ensure
    correct behavior of the APK:
        * Masking re-signing by overloading Android APIs and presenting
        original certificate hash.
        * ...

    Script is generated as ``frida-gadget-script.js`` in the working directory.

    :param apk_path: Path to the original APK.
    :param package_name: Name of the package (e.g. `com.example`).
    """
    # Get certificate hash (SHA-1) from the initial APK
    initial_certificate_hash = (
        next(
            line
            for line in subprocess.check_output(
                ['keytool', '-printcert', '-jarfile', apk_path]
            ).decode().splitlines()
            if line.strip().startswith('SHA 1')
        ).strip().replace('SHA 1: ', '')
    )

    # Get the signing certificate from the original APK
    with tempfile.TemporaryDirectory() as tmp_sig_out_path:
        # Get certificates from original APK
        apksigcopier.do_extract(apk_path, tmp_sig_out_path)
        # Get the hexdump of the certificate
        cert_file = os.path.join(
            tmp_sig_out_path,
            next(
                file for file in os.listdir(tmp_sig_out_path) if file.endswith('.RSA')
            )
        )
        raw_signing_certificate = subprocess.check_output(
            f'openssl pkcs7 -in {cert_file} -inform DER -print_certs | openssl x509 -outform DER | xxd -p | tr -d \\n',
            shell=True
        ).decode()

    with open('./frida-gadget-script.js', 'w') as fh:
        template = jinja2.Environment(
            loader=jinja2.BaseLoader
        ).from_string(GADGET_SCRIPT_TEMPLATE)
        fh.write(
            template.render(
                initial_certificate_hash=initial_certificate_hash,
                raw_signing_certificate=raw_signing_certificate,
                package_name=package_name,
            )
        )
