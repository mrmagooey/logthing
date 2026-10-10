#!/bin/sh
# Obtain the machine-account TGT when a client keytab is provided, then run the emulator.
#   KRB5_CLIENT_KEYTAB     keytab path (default /keytabs/clients.keytab when set to a non-path)
#   KRB5_CLIENT_PRINCIPAL  default 'WIN10$@EXAMPLE.COM'
set -e
if [ -n "$KRB5_CLIENT_KEYTAB" ]; then
    case "$KRB5_CLIENT_KEYTAB" in
        /*) keytab="$KRB5_CLIENT_KEYTAB" ;;
        *) keytab=/keytabs/clients.keytab ;;
    esac
    kinit -k -t "$keytab" "${KRB5_CLIENT_PRINCIPAL:-WIN10\$@EXAMPLE.COM}"
fi
exec python -m wefemu "$@"
