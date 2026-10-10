#!/bin/sh
# Provision a Samba AD DC for realm EXAMPLE.COM on first start, export the same keytabs the
# MIT kdc service produces (logthing.keytab, other.keytab, clients.keytab), then run samba
# in the foreground. Keytabs are 0644: throwaway test-only key material.
set -eu
REALM=EXAMPLE.COM
KT=/keytabs

if [ ! -f "$KT/.provisioned" ]; then
    echo "provisioning AD realm $REALM"
    rm -f "$KT"/*.keytab "$KT/.provisioned"
    rm -f /etc/samba/smb.conf
    rm -rf /var/lib/samba/private/* /var/lib/samba/sysvol/* 2>/dev/null || true
    samba-tool domain provision --realm="$REALM" --domain=EXAMPLE --server-role=dc \
        --dns-backend=SAMBA_INTERNAL --host-name=kdc \
        --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
        --adminpass="Aa1-$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
    # security.NTACL xattrs need CAP_SYS_ADMIN; keep NT ACLs in a tdb so the container runs
    # unprivileged (sysvol ACLs are irrelevant to the Kerberos tests).
    sed -i '/^\[global\]/a\	vfs objects = dfs_samba4 acl_xattr xattr_tdb' /etc/samba/smb.conf
    # The test keytabs hold long random keys; password-quality rules would reject testpass.
    samba-tool domain passwordsettings set --complexity=off --min-pwd-length=0 \
        --min-pwd-age=0 --history-length=0
    samba-tool user create logthing-svc --random-password
    samba-tool user create other-svc --random-password
    samba-tool spn add HTTP/logthing.example.com logthing-svc
    samba-tool spn add HTTP/other.example.com other-svc
    samba-tool computer create WIN10
    samba-tool computer create WIN11
    samba-tool user create alice testpass
    # `computer create` leaves the account disabled with no password (no keys to export);
    # give it a random one and enable it, as a domain join would.
    for m in WIN10 WIN11; do
        samba-tool user setpassword "$m\$" --newpassword="Zz9-$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
        samba-tool user enable "$m\$"
    done
    # Accounts without msDS-SupportedEncryptionTypes only get RC4 keys exported; advertise
    # AES128+AES256 (24) like a current Windows domain, so tickets are AES-encrypted.
    for acct in logthing-svc other-svc alice; do
        dn=$(ldbsearch -H /var/lib/samba/private/sam.ldb "(sAMAccountName=$acct)" dn \
            | sed -n 's/^dn: //p')
        printf 'dn: %s\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n' \
            "$dn" | ldbmodify -H /var/lib/samba/private/sam.ldb
    done
    # exportkeytab truncates its target, so export each principal to its own file and merge.
    exp() { samba-tool domain exportkeytab "/tmp/kt.$1" --principal="$2"; }
    exp logthing "HTTP/logthing.example.com@$REALM"
    exp other "HTTP/other.example.com@$REALM"
    exp win10 "WIN10\$@$REALM"
    exp win11 "WIN11\$@$REALM"
    exp alice "alice@$REALM"
    cp /tmp/kt.logthing "$KT/logthing.keytab"
    cp /tmp/kt.other "$KT/other.keytab"
    printf 'rkt /tmp/kt.win10\nrkt /tmp/kt.win11\nrkt /tmp/kt.alice\nwkt %s/clients.keytab\nq\n' "$KT" \
        | ktutil
    echo "keytab contents:"
    for f in logthing other clients; do klist -k -e "$KT/$f.keytab" || true; done
    chmod 644 "$KT"/*.keytab
    touch "$KT/.provisioned"
    echo "provisioning done"
fi
exec samba -i --debug-stdout
