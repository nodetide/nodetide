# Adding a device (a phone) by QR

The wallet that holds the master key shows a QR code; the new device scans it; the owner confirms; the master authorizes the device on the identity's chain. The node only relays two small messages.

## Steps

1. **Web client**, My Identity > Devices & recovery > **Add a device** (wallet unlocked): makes a random 10-character code from `ABCDEFGHJKMNPQRSTUVWXYZ23456789` and shows the invite as a QR code and as text:

       nodetide://pair?c=<code>&n=<node origin>&i=<identity hash>

2. **Phone**, Add device > Scan QR (or paste the invite): the app shows which identity, which node and **its own key fingerprint**. On *Add this phone* it makes its own signing and encryption keys and leaves only the PUBLIC keys and a label in a slot on the node
   (`POST /api/pairing`, the slot named by `sha256("nodetide-pairing:" + code)`, kept in memory for ten minutes).
3. **Web client** sees the slot and shows the device's label and the same fingerprint. After *Add the device* it appends an `add_device` event signed by the master key (capabilities `sign_messages, encrypt, authenticate, manage_claims`; it commits to the
   claims so far, as every control event does) and leaves a sealed answer in the slot (NaCl box from the web wallet's device key to the new device's key: the chain, no claim values, since the phone has no claim screens yet).
4. **Phone** does not trust any message for this: it polls the identity's chain on the node, verifies it, and becomes a device only when the chain itself lists its key with `authenticate`. It then saves the account (device keys only, no master key) and, if it had no
   relay, the node.

## What this protects against

* Whoever has the invite can open the slot and ask to be added, but nothing happens until the owner has compared the fingerprint on the web page with the one on the phone and confirmed. The code is single-purpose and expires with the slot.
* The phone only accepts an invite whose node address is `https`, or plain `http` on the local network (`Lan.cleartextAllowed`); no credentials or paths in the address. The invite names the identity, so a phone pointed at a rogue node can at worst be added to *that* identity,
  and it shows the identity and node before sending anything.
* The node cannot add a device (it has no master key), and cannot forge the authorization: the phone checks the signed chain.

## Scanning the other QR

An identity's **Share** QR (JSON `{"v":1,"id":..,"dp":[..],"pk":..}`, or the older `nodetide:identity:<hash>:<pubkey>`) adds the identity to the phone for *watching*: no keys. The phone's own *Show QR* now produces the same JSON.

## Tested

`tests/test_web_pairing_browser.py` plays the phone in Python against a real node and the web page: slot name, fingerprint, the authorization on the chain (capabilities, claim commitment), the sealed answer opened with the phone's key. The Kotlin rules (code, slot,
fingerprint, invite and share parsing) are tested on the JVM against values computed in Python (`PairingTest`). The camera scan and the screen have been compiled and installed on a phone but not driven by a person yet.
