#!/bin/bash
# Prepares docker-mailserver for the sigchain responder, then starts it like the image would.
# One mailbox (MAIL_ADDRESS), TLS with a self-signed certificate that the node pins (/mail-ca/cert.pem), and the DKIM
# key that Terraform published the public half of (/dkim/private.pem, absent = mail goes out unsigned).
set -eu
: "${MAIL_HOST:?}" "${MAIL_DOMAIN:?}" "${MAIL_ADDRESS:?}" "${MAIL_PASSWORD:?}"
cfg=/tmp/docker-mailserver
tls=/etc/mail-tls
mkdir -p "$cfg/opendkim" "$tls" /mail-ca

if [ ! -s "$tls/key.pem" ]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -keyout "$tls/key.pem" -out "$tls/cert.pem" \
        -subj "/CN=$MAIL_HOST" -addext "subjectAltName=DNS:$MAIL_HOST,DNS:mail"
    chmod 600 "$tls/key.pem"
fi
cp "$tls/cert.pem" /mail-ca/cert.pem   # the public half, for the node to trust

printf '%s|%s\n' "$MAIL_ADDRESS" "$(doveadm pw -s SHA512-CRYPT -p "$MAIL_PASSWORD")" > "$cfg/postfix-accounts.cf"

if [ -s /dkim/private.pem ]; then
    keys="$cfg/opendkim/keys/$MAIL_DOMAIN"
    mkdir -p "$keys"
    cp /dkim/private.pem "$keys/mail.private"
    echo "mail._domainkey.$MAIL_DOMAIN $MAIL_DOMAIN:mail:/etc/opendkim/keys/$MAIL_DOMAIN/mail.private" > "$cfg/opendkim/KeyTable"
    echo "*@$MAIL_DOMAIN mail._domainkey.$MAIL_DOMAIN" > "$cfg/opendkim/SigningTable"
    printf '127.0.0.1\nlocalhost\n' > "$cfg/opendkim/TrustedHosts"
else
    echo "mail-init: no DKIM key: outgoing mail will not be signed" >&2
fi

exec /usr/bin/dumb-init -- supervisord -c /etc/supervisor/supervisord.conf
