# Derivation standards and the PR #1090 (Validate derivations) test group

SeedSigner's **Validate derivations** setting (on by default, SettingsQR key
`val_deriv`) signs a psbt only when every input of the loaded seed's is at a standard
full path: a registry base path, then branch `0` or `1`, then a non-hardened address
index. With the setting off the parser gets no validator and behaves exactly as `dev`.
The test group is `pr: "1090"` (SeedSigner PR #1090) in `common/scenarios.py`; its builders are
`PR1090_CASES` in `common/attack_psbt.py`.

## The registry

| Wallet | Standard base paths |
|---|---|
| Legacy (P2PKH) | `m/44h/{coin}/{account}` |
| Nested segwit (P2SH-P2WPKH) | `m/49h/{coin}/{account}` |
| Native segwit (P2WPKH) | `m/84h/{coin}/{account}`, plus the Whirlpool accounts `2147483644h`–`2147483646h` |
| Taproot (P2TR) | `m/86h/{coin}/{account}` |
| Legacy multisig (P2SH) | `m/45h`; `m/45h/{coin}/{account}` (Caravan); `m/45h/0/0/{vault}` (Unchained) |
| Nested segwit multisig (P2SH-P2WSH) | `m/48h/{coin}/{account}/1h` |
| Native segwit multisig (P2WSH) | `m/48h/{coin}/{account}/2h`; `m/45h/0/0/{vault}` (Unchained) |

`coin` is `0h` on mainnet and `1h` on every test network, `account` is `0h` through
`9h`, and Unchained's `vault` is `0` through `9` (not hardened). The account limit is
SeedSigner's own line, drawn where wallets commonly stop scanning when they restore a
seed.

A path that is not standard is graded, in this order:

1. **Network Mismatch**: an exact standard path for the input's script type at the
   other coin type ("Path is for Testnet"). Bare `m/45h` has no coin type level, so it
   can never be a network mismatch.
2. **Script Type Mismatch**: an exact standard path for exactly one other policy type
   ("Path is for …", naming the path's script type, even when only single sig versus
   multisig differs).
3. **Nonstandard Path**: anything else, including a path with a second problem, and the
   Unchained layout on nested segwit multisig, which is standard for two other types.

The screen shows the first refused input's path, by input index, shortened around the
offending level by `get_display_derivation_path()`: one line on the two mismatch
screens, up to two on Nonstandard Path.

## Layouts the group uses, and where each was confirmed

Third-party sources were shallow-cloned on 2026-11-22 and read with grep only.

- **Caravan**, legacy multisig at `m/45'/{coin}'/0'`: confirmed in Caravan's
  `packages/caravan-bitcoin/src/paths.ts`, `multisigBIP32Root()`, which returns
  `m/45'/${coinPath}/0'` for P2SH (and `m/48'/…/1'` for P2SH-P2WSH). Caravan's test
  fixtures also use account `100'`, which the setting refuses.
- **Unchained**, `m/45'/0/0/{vault}`: built to SeedSigner's registry. Caravan's sources
  don't show this layout: its fixtures hold `m/45'/0/0` nodes and Unchained test keys at
  `m/45'/{coin}'/100'`. It is not confirmed from a primary source here.
- **Electrum**, segwit seeds at `m/0'` and multisig at `m/1'`: confirmed in Electrum's
  `electrum/keystore.py`, `from_seed()`: `der = "m/1'/" if for_multisig else "m/0'/"`.
  The scenario is a BIP-39 seed at that path, which the validator judges the same way as
  an Electrum seed.
- **Whirlpool**: the three accounts are standard for native segwit only, as in Sparrow.

The Caravan and Unchained scenarios sign, so the device needs each wallet's descriptor
to verify the change. Their fixture wallets, `2of3_p2sh_caravan` and
`2of3_p2wsh_unchained`, are marked `test_only`, which keeps them out of the site's
address verification list.

## Refused on purpose

These honest psbts are refused while the setting is on, and sign with it off:

- Electrum seeds (`m/0h`, multisig `m/1h`);
- accounts above 9;
- custom derivations, including true BIP-45 with a cosigner index level;
- a purpose that doesn't match the script type, such as legacy coins at `m/86'/0'/0'`
  (SeedSigner issue #1055);
- branch 2 or higher, or a hardened address index;
- BIP-352 silent payment paths.

## Not caught

- Dust sent to another standard account (account 7, say) with the change there signs
  with no warning, setting on or off. Every path is standard, so a wallet that scans
  accounts 0–9 on restore finds the change. The overview shows one more input.
- A test network legacy multisig psbt at bare `m/45h` parses on a mainnet device as it
  does on `dev`, since there is no coin type to check.
- Only this seed's own input paths are judged. Other cosigners' paths and other
  parties' inputs are left alone, and change paths are left to the change path rules.

## Building a scenario for this check

The check runs last in `PSBTParser.parse()`, so any other finding wins. A scenario meant
for it must trip nothing else:

- Single sig segwit v0 inputs at more than one base path must each carry their previous
  transaction (`non_witness_utxo`), or the mixed base path rule refuses the psbt first.
  The builders attach one to every input wherever they mix base paths.
- Change has to stay under a base path one of this seed's inputs spends from, on branch
  0 or 1, or the change path rule refuses it first.
- Multisig change against a loaded descriptor is checked after the parse, so a
  standardness refusal comes before Address Verification Failed.
