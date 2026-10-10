#!/bin/sh
# Provision the test realm on first start, then run krb5kdc in the foreground.
# Keytabs are 0644: this is throwaway test-only key material, and the consuming
# containers/tests run as other users.
set -eu
REALM=EXAMPLE.COM
KT=/keytabs
ENCTYPES="aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal"
DB=/var/lib/krb5kdc/principal

if [ ! -f "$KT/.provisioned" ] || [ ! -f "$DB" ]; then
    echo "provisioning realm $REALM"
    rm -f "$KT"/*.keytab "$KT/.provisioned" "$DB" "$DB".* /var/lib/krb5kdc/principal.* 2>/dev/null || true
    mkdir -p /etc/krb5kdc /var/lib/krb5kdc "$KT"
    cat > /etc/krb5kdc/kdc.conf <<KDC
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    $REALM = {
        database_name = $DB
        key_stash_file = /etc/krb5kdc/stash
        supported_enctypes = $ENCTYPES
        master_key_type = aes256-cts-hmac-sha1-96
    }
KDC
    kdb5_util create -s -r "$REALM" -P "$(head -c 24 /dev/urandom | base64)"
    kadmin.local -q "addprinc -randkey HTTP/logthing.example.com"
    kadmin.local -q "addprinc -randkey HTTP/other.example.com"
    kadmin.local -q "addprinc -randkey WIN10\$"
    kadmin.local -q "addprinc -randkey WIN11\$"
    kadmin.local -q "addprinc -pw testpass alice"
    kadmin.local -q "ktadd -k $KT/logthing.keytab HTTP/logthing.example.com"
    kadmin.local -q "ktadd -k $KT/other.keytab HTTP/other.example.com"
    kadmin.local -q "ktadd -k $KT/clients.keytab WIN10\$ WIN11\$"
    chmod 644 "$KT"/*.keytab
    touch "$KT/.provisioned"
    echo "provisioning done"
fi
exec krb5kdc -n
