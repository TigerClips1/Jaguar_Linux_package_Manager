ps4-keys(5)

# NAME

*/etc/ps4/keys* - cryptographic keys trusted by ps4

# DESCRIPTION

The */etc/ps4/keys* directory stores RSA public keys which are trusted by ps4
to verify cryptographic signatures for packages. To trust a new key, simply add
the armored public key to this directory. See *abuild-keygen*(1) for
information on generating new keys, *abuild-sign*(1) for using these keys to
sign files, and *ps4-verify*(8) for verifying keys against the ps4 trust store.
