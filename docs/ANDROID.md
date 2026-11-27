# Running on Android (Termux)

The Android build is the CPU-only command-line node (no GPU on phones). It runs
in [Termux](https://termux.dev), a terminal app, and serves the same web
dashboard you get on a desktop. It was written against a **Pixel 8 Pro**
(Google Tensor G3, `arm64-v8a`, Android 14) but works on any 64-bit ARM phone
running Android 10 (API 29) or newer.

A phone finds keys far slower than a desktop CPU and much slower than a GPU.
Run it because you want to take part, not to win.

## What is in the package

`bitcrack-distributed-v<version>-android-arm64-cli.tar.gz` contains:

| File | Purpose |
|---|---|
| `bitcrack-distributed` | the node: a static `arm64` binary with no other dependencies |
| `cacert.pem` | Mozilla CA bundle; the node uses it to verify Electrum TLS servers. Keep it next to the binary. |
| `RUN.txt` | the short version of this page |
| `ANDROID.md` | this page |
| `README.md`, `LICENSE` | project readme and license |

## 1. Install Termux

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[Termux GitHub releases](https://github.com/termux/termux-app/releases). Open it
once and let it finish setting up, then update packages:

```sh
pkg update && pkg upgrade
```

## 2. Get the package onto the phone

**Download in Termux** (when you have a URL for the package):

```sh
cd ~
curl -LO <package URL>
```

**Or copy it from a computer with adb** (USB debugging on: Settings > About
phone > tap *Build number* seven times, then Settings > System > Developer
options > *USB debugging*):

```sh
adb push bitcrack-distributed-v1.1.2-android-arm64-cli.tar.gz /sdcard/Download/
```

Then in Termux, allow storage access once and copy the file into Termux's
home. Android does not let programs run from `/sdcard`, so it has to be in
`~`:

```sh
termux-setup-storage          # tap Allow
cp ~/storage/downloads/bitcrack-distributed-v1.1.2-android-arm64-cli.tar.gz ~
```

## 3. Unpack and check it

```sh
cd ~
tar -xzf bitcrack-distributed-v1.1.2-android-arm64-cli.tar.gz
cd bitcrack-distributed-v1.1.2-android-arm64-cli
chmod +x bitcrack-distributed
./bitcrack-distributed --version
./bitcrack-distributed --bench 10      # 10 s CPU benchmark, optional
```

## 4. Run it

```sh
termux-wake-lock                      # keeps the CPU awake with the screen off
./bitcrack-distributed --cpu --dashboard --reward <your bitcoin address>
```

- `--cpu` searches on the CPU only (there is no GPU path on Android).
- `--reward` is the address paid if your node finds a key. Use an address
  from a wallet you control; never put a private key on the command line.
- `--dashboard` serves the dashboard. Open **http://127.0.0.1:3339** in the
  phone's browser (Chrome) while the node runs. It listens only on the phone
  itself; leave `api_allow_remote` off.

Stop the node with **Ctrl+C** (on the Termux extra-keys row, *CTRL* then *c*)
and release the wake lock with `termux-wake-unlock`.

Files: the config is `~/.config/BitCrackDistributed/config.json` and progress
is kept in `~/.local/share/BitCrackDistributed/`, so the node picks up where it
left off. A `config.json` in the current directory takes precedence.

### Running from `adb shell` instead of Termux

The binary also runs from a computer over adb, with no app installed:

```sh
adb push bitcrack-distributed cacert.pem /data/local/tmp/bcd/
adb shell
cd /data/local/tmp/bcd && chmod +x bitcrack-distributed
./bitcrack-distributed --cpu --reward <your bitcoin address>
```

`adb shell` has no usable `HOME`, so the node keeps its config and data under
the binary's directory (`/data/local/tmp/bcd/.config/...` and
`.local/share/...`). The session ends when the cable is unplugged, so this is
for testing; use Termux to run it for longer.

## Battery, heat and how many cores to use

Searching keeps every core it uses at 100 %. On a phone that means heat, a
drained battery and, once hot, the system slowing the CPU down (thermal
throttling), which loses more speed than running fewer threads would.

The Pixel 8 Pro's Tensor G3 has 9 cores: 1 fast (Cortex-X3), 4 medium
(Cortex-A715) and 4 efficiency (Cortex-A510). By default the node starts one
search thread per core (9). To run cooler, set `cpu_thread_count` in
`~/.config/BitCrackDistributed/config.json` (start the node once to create the
file, stop it, edit, start again):

```json
"cpu_thread_count": 4
```

| Threads | When |
|---|---|
| 2-3 | phone in use, or not on a charger |
| 4 | a good default on a charger, overnight |
| 9 (or 0 = all cores) | on a charger, case off, somewhere cool; watch the temperature |

(`--power` and `resources.cpu_usage_limit` do not throttle the CPU search;
`cpu_thread_count` is the setting that does.)

Recommendations:

- **Charge while it runs.** Unplugged, a full search drains the battery in a
  few hours. Use the Pixel's *Adaptive Charging*/*charging optimization*
  (Settings > Battery) so the battery does not sit at 100 % and hot all night.
- **Keep it cool.** Take the case off, lay the phone on a hard surface (not a
  bed or pillow), out of the sun. If the phone feels hot to the touch or warns
  about temperature, stop the node or drop to 2-3 threads. A 15-W wireless
  charger adds heat; a cable charger is cooler.
- **Use Wi-Fi.** The node talks to peers and Electrum servers all the time.
  Traffic is small but constant, so prefer Wi-Fi over mobile data. On mobile
  data, check the usage under Settings > Network & internet > SIMs > App data
  usage.
- **Battery setting.** Settings > Apps > Termux > App battery usage >
  **Unrestricted**, or Android may stop it in the background.
- **Android 12+ background limits.** Android stops background processes that
  use a lot of CPU ("phantom process killer"); Termux shows
  `[Process completed (signal 9)]`. On Android 14, turn on Settings > System >
  Developer options > **Disable child process restrictions**. Keep Termux's
  notification (with the wake lock held) and, if possible, the Termux window in
  the foreground.

## Electrum TLS certificates

The node checks a found key's balance and broadcasts payouts through Electrum
servers over TLS (port 50002) and verifies their certificates. The Android
binary carries its own OpenSSL, which has no system CA store, so it loads a CA
bundle instead, in this order:

1. `"tls_ca_file": "/path/to/bundle.pem"` in `config.json`, if set;
2. OpenSSL's `SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables, if set;
3. `cacert.pem` next to the binary (shipped in the package);
4. Termux's `$PREFIX/etc/tls/cert.pem` (from the `ca-certificates` package).

If none is found the node logs `No CA certificates found` at startup and TLS
Electrum servers fail verification. Desktop Linux, macOS and Windows builds
use their system store as before.

## Building it yourself

On a Linux host with the [Android NDK](https://developer.android.com/ndk/downloads)
(r26 or newer; tested with r28c), CMake, Ninja, Perl and make:

```sh
ANDROID_NDK_ROOT=/path/to/android-ndk-r28c PACKAGE=1 scripts/build_android.sh build-android
```

This downloads and checks OpenSSL 3.4.1, builds it as a static library,
cross-compiles the node for `arm64-v8a` (API 29, runs on Android 14), and with
`PACKAGE=1` writes `build-android/dist/bitcrack-distributed-v<version>-android-arm64-cli.tar.gz`.
See the comments at the top of the script for the other options
(`ANDROID_ABI=x86_64` for the emulator, `ANDROID_API`, `LINK_STATIC=0`).

The static binary also runs on an x86-64 Linux host under
`qemu-aarch64-static`, which is a quick way to check a build:

```sh
qemu-aarch64-static build-android/bitcrack-distributed --version
```
