#!/bin/bash
# Generates the DER test vectors used by test.Asn1VectorsTest (OpenSSL 3.x is required).
#
# Usage: copy this script to an empty directory, run it, and copy the files in out/ to
# this directory. The keys, serial numbers and times are random, so each run produces
# different (but equivalent) files.
#
# Note: "openssl cmp -use_mock_srv" may crash (segfault) after the messages have been
# written; such errors are ignored.
set -e
O=out; rm -rf $O work; mkdir -p $O work; cd work
OSSL=openssl

# ---------- keys ----------
$OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
$OSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ee-rsa.key 2>/dev/null
$OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ee-ec.key 2>/dev/null
$OSSL genpkey -algorithm ED25519 -out ee-ed.key 2>/dev/null

cat > ca.cnf <<'C'
[req]
distinguished_name = dn
prompt = no
[dn]
C = DE
O = xipki test
OU = asn1
CN = Test CA
[ca_ext]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer:always
issuerAltName = URI:http://ca.example.com, email:ca@example.com
crlDistributionPoints = crldp_full, crldp_reasons
certificatePolicies = critical, ia5org, @pol1, 1.2.3.4.5
policyConstraints = requireExplicitPolicy:0
inhibitAnyPolicy = 2
nameConstraints = critical, permitted;DNS:.example.com, permitted;IP:10.0.0.0/255.0.0.0, excluded;email:.bad.example.com
policyMappings = 1.2.3.4.5:1.2.3.4.6
authorityInfoAccess = OCSP;URI:http://ocsp.example.com, caIssuers;URI:http://ca.example.com/ca.crt
# privateKeyUsagePeriod with only notAfter: SEQUENCE { [1] 20301231235959Z }
2.5.29.16 = DER:3011810F32303330313233313233353935395A
[crldp_full]
fullname = URI:http://crl.example.com/ca.crl
[crldp_reasons]
fullname = URI:ldap://ldap.example.com/cn=Test%20CA
reasons = keyCompromise, CACompromise, superseded
CRLissuer = dirName:crl_issuer_dn
[crl_issuer_dn]
C = DE
CN = CRL Issuer
[pol1]
policyIdentifier = 1.2.3.4.5.6
CPS.1 = "http://cps.example.com"
userNotice.1 = @notice_utf8
[notice_utf8]
explicitText = "UTF8:UTF8 explicit text äöü"
organization = "Example Org"
noticeNumbers = 1, 2, 3
C
$OSSL req -new -x509 -config ca.cnf -extensions ca_ext -key ca.key -days 3650 -set_serial 0x0123456789abcdef \
  -outform DER -out ../$O/cert-ca-ec.der

# OpenSSL's default: noticeRef.organization and explicitText as VisibleString
cat > vis.cnf <<'C'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = VisibleString notice
[ext]
certificatePolicies = @pol
[pol]
policyIdentifier = 1.2.3.4.5.6
userNotice.1 = @notice
[notice]
explicitText = "VISIBLE:VisibleString explicit text"
organization = "Example Org"
noticeNumbers = 1
C
$OSSL req -new -x509 -config vis.cnf -extensions ext -key ca.key -days 365 -outform DER \
  -out ../$O/cert-notice-visiblestring.der

cat > ee.cnf <<'C'
[req]
distinguished_name = dn
prompt = no
string_mask = default
[dn]
C = DE
ST = Berlin
L = Berlin
O = xipki test
OU = asn1
CN = ee.example.com
emailAddress = ee@example.com
[ee_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth, 1.3.6.1.5.5.7.3.9
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = @san
crlDistributionPoints = URI:http://crl.example.com/ca.crl
certificatePolicies = 1.2.3.4.5.6
tlsfeature = status_request
ct_precert_poison = critical, DER:0500
[san]
DNS.1 = ee.example.com
DNS.2 = *.ee.example.com
IP.1 = 192.168.1.1
IP.2 = 2001:db8::1
email.1 = ee@example.com
URI.1 = https://ee.example.com/
RID.1 = 1.2.3.4
dirName.1 = san_dn
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:ee@example.com
[san_dn]
CN = SAN dir name
[csr_ext]
subjectAltName = DNS:ee.example.com
keyUsage = digitalSignature
[csr_attrs]
challengePassword = secret123
unstructuredName = unstructured name
C
mkca() { # $1 key, $2 out, $3 extra args
  $OSSL req -new -config ee.cnf -key $1 -out tmp.csr
  $OSSL x509 -req -in tmp.csr -CA ../$O/cert-ca-ec.der -CAform DER -CAkey ca.key -extfile ee.cnf -extensions ee_ext \
    -days 365 -set_serial $RANDOM$RANDOM $3 -outform DER -out ../$O/$2 2>/dev/null
}
mkca ee-rsa.key cert-ee-rsa.der ""
mkca ee-ec.key cert-ee-ec-sha384.der "-sha384"
mkca ee-ed.key cert-ee-ed25519.der ""
# RSASSA-PSS signed by an RSA CA: self-signed PSS cert
$OSSL req -new -x509 -config ee.cnf -extensions ee_ext -key ee-rsa.key -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 -sha256 -days 365 -outform DER -out ../$O/cert-ee-rsapss.der

# ---------- CSR with attributes ----------
cat > csr.cnf <<'C'
[req]
distinguished_name = dn
attributes = attrs
req_extensions = csr_ext
prompt = no
[dn]
CN = csr.example.com
O = xipki test
[attrs]
challengePassword = secret123
unstructuredName = unstructured name
[csr_ext]
subjectAltName = DNS:csr.example.com
keyUsage = critical, digitalSignature
C
$OSSL req -new -config csr.cnf -key ee-ec.key -outform DER -out ../$O/csr-ec.der
$OSSL req -new -config csr.cnf -key ee-rsa.key -outform DER -out ../$O/csr-rsa.der

# ---------- CRLs ----------
mkdir -p db; : > db/index.txt; echo 1000 > db/crlnumber
cat > crl.cnf <<'C'
[ca]
default_ca = myca
[myca]
database = db/index.txt
crlnumber = db/crlnumber
default_md = sha256
default_crl_days = 7
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical, @idp
[idp]
fullname = URI:http://crl.example.com/ca.crl
onlysomereasons = keyCompromise, CACompromise
C
$OSSL x509 -inform DER -in ../$O/cert-ca-ec.der -out ca.pem
# empty CRL
$OSSL ca -config crl.cnf -gencrl -keyfile ca.key -cert ca.pem -out empty.pem 2>/dev/null
$OSSL crl -in empty.pem -outform DER -out ../$O/crl-empty.der
# CRL with entries and entry extensions
NOW=$(date -u +%y%m%d%H%M%SZ)
printf "R\t301231235959Z\t%s,keyCompromise\t0A\tunknown\t/CN=a\n" $NOW >> db/index.txt
printf "R\t301231235959Z\t%s,superseded\t0B\tunknown\t/CN=b\n" $NOW >> db/index.txt
printf "R\t301231235959Z\t%s,certificateHold\t0C\tunknown\t/CN=c\n" $NOW >> db/index.txt
printf "R\t301231235959Z\t%s,keyTime,20240101000000Z\t0D\tunknown\t/CN=d\n" $NOW >> db/index.txt
printf "R\t301231235959Z\t%s\t0E\tunknown\t/CN=e\n" $NOW >> db/index.txt
printf "V\t301231235959Z\t\t0F\tunknown\t/CN=f\n" >> db/index.txt
$OSSL ca -config crl.cnf -gencrl -keyfile ca.key -cert ca.pem -out full.pem 2>/dev/null
$OSSL crl -in full.pem -outform DER -out ../$O/crl-entries.der

# ---------- OCSP ----------
$OSSL x509 -inform DER -in ../$O/cert-ee-ec-sha384.der -out ee.pem
$OSSL x509 -inform DER -in ../$O/cert-ee-rsa.der -out ee-rsa.pem
$OSSL ocsp -issuer ca.pem -cert ee.pem -reqout ../$O/ocsp-req-nonce.der
$OSSL ocsp -issuer ca.pem -cert ee.pem -no_nonce -reqout ../$O/ocsp-req-nononce.der
$OSSL ocsp -issuer ca.pem -cert ee.pem -signer ee-rsa.pem -signkey ee-rsa.key -sign_other ca.pem -reqout ../$O/ocsp-req-signed.der
SER_EC=$($OSSL x509 -in ee.pem -noout -serial | cut -d= -f2)
SER_RSA=$($OSSL x509 -in ee-rsa.pem -noout -serial | cut -d= -f2)
mkdir -p odb; printf "V\t301231235959Z\t\t%s\tunknown\t/CN=ee\n" $SER_EC > odb/index.txt
printf "R\t301231235959Z\t%s,keyCompromise\t%s\tunknown\t/CN=ee\n" $NOW $SER_RSA >> odb/index.txt
$OSSL ocsp -issuer ca.pem -cert ee.pem -cert ee-rsa.pem -reqout ocsp2.req
$OSSL ocsp -index odb/index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem -reqin ocsp2.req -respout ../$O/ocsp-resp-good-revoked.der -ndays 1 >/dev/null 2>&1
$OSSL ocsp -index odb/index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem -reqin ocsp2.req -resp_key_id -resp_no_certs -respout ../$O/ocsp-resp-keyid.der >/dev/null 2>&1
# malformedRequest-like status response (no responseBytes): OCSPResponse { responseStatus 1 }
printf '\x30\x03\x0a\x01\x01' > ../$O/ocsp-resp-malformed.der

# ---------- CMS ----------
echo "hello cms" > data.txt
$OSSL x509 -inform DER -in ../$O/cert-ee-ec-sha384.der -out ee-ec.pem
$OSSL cms -sign -in data.txt -signer ee-rsa.pem -inkey ee-rsa.key -certfile ca.pem -outform DER -binary -nodetach -out ../$O/cms-signed-rsa.der
$OSSL cms -sign -in data.txt -signer ee-ec.pem -inkey ee-ec.key -outform DER -binary -keyid -out ../$O/cms-signed-ec-detached-keyid.der
$OSSL cms -sign -in data.txt -signer ee-rsa.pem -inkey ee-rsa.key -outform DER -binary -nodetach -keyopt rsa_padding_mode:pss -noattr -out ../$O/cms-signed-pss-noattr.der
$OSSL crl -in full.pem -out crl.pem
$OSSL crl2pkcs7 -in full.pem -certfile ca.pem -outform DER -out ../$O/cms-signed-degenerate-crl.der
$OSSL cms -encrypt -in data.txt -aes-128-cbc -recip ee-rsa.pem -outform DER -binary -out ../$O/cms-enveloped-ktri.der
$OSSL cms -encrypt -in data.txt -aes-128-cbc -recip ee-rsa.pem -keyopt rsa_padding_mode:oaep -outform DER -binary -out ../$O/cms-enveloped-ktri-oaep.der
$OSSL cms -encrypt -in data.txt -aes-256-cbc -recip ee-ec.pem -outform DER -binary -out ../$O/cms-enveloped-kari.der
$OSSL cms -encrypt -in data.txt -aes-256-cbc -pwri_password secret -outform DER -binary -out ../$O/cms-enveloped-pwri.der
$OSSL cms -encrypt -in data.txt -aes-128-cbc -secretkey 000102030405060708090a0b0c0d0e0f -secretkeyid 0102 -outform DER -binary -out ../$O/cms-enveloped-kekri.der
$OSSL cms -encrypt -in data.txt -aes-256-gcm -recip ee-rsa.pem -outform DER -binary -out ../$O/cms-authenveloped.der
$OSSL cms -EncryptedData_encrypt -in data.txt -aes-128-cbc -secretkey 000102030405060708090a0b0c0d0e0f -outform DER -binary -out ../$O/cms-encrypted.der
$OSSL cms -digest_create -in data.txt -outform DER -binary -out ../$O/cms-digested.der

# ---------- TSP ----------
cat > tsa.cnf <<'C'
[tsa]
default_tsa = tsa1
[tsa1]
serial = tsaserial
signer_cert = tsa.pem
signer_key = ee-ec.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.2
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:500, microsecs:100
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
C
cat > tsaext.cnf <<'C'
[e]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
C
$OSSL req -new -key ee-ec.key -subj "/CN=Test TSA" -out tsa.csr
$OSSL x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -extfile tsaext.cnf -extensions e -days 365 -set_serial 77 -out tsa.pem 2>/dev/null
echo 01 > tsaserial
$OSSL ts -query -data data.txt -sha256 -cert -tspolicy 1.2.3.4.2 -out ../$O/tsp-req-policy-nonce-cert.der
$OSSL ts -query -data data.txt -sha384 -no_nonce -out ../$O/tsp-req-minimal.der
$OSSL ts -reply -config tsa.cnf -queryfile ../$O/tsp-req-policy-nonce-cert.der -out ../$O/tsp-resp-sha256-esscertv2.der 2>/dev/null
sed -i '' 's/ess_cert_id_alg = sha256/ess_cert_id_alg = sha1/' tsa.cnf
$OSSL ts -reply -config tsa.cnf -queryfile ../$O/tsp-req-minimal.der -out ../$O/tsp-resp-sha1-esscert.der 2>/dev/null
sed -i '' 's/ess_cert_id_alg = sha1/ess_cert_id_alg = sha384/; s/ess_cert_id_chain = no/ess_cert_id_chain = yes/' tsa.cnf
$OSSL ts -reply -config tsa.cnf -queryfile ../$O/tsp-req-minimal.der -out ../$O/tsp-resp-sha384-esscertv2-chain.der 2>/dev/null
$OSSL ts -reply -config tsa.cnf -queryfile ../$O/tsp-req-minimal.der -token_out -out ../$O/tsp-token.der 2>/dev/null

# ---------- PKCS#8 / PKCS#12 ----------
$OSSL pkcs8 -topk8 -in ee-ec.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:secret -outform DER -out ../$O/pkcs8-enc-pbes2.der
$OSSL pkcs8 -topk8 -in ee-ed.key -nocrypt -outform DER -out ../$O/pkcs8-ed25519.der
$OSSL pkcs12 -export -in ee-ec.pem -inkey ee-ec.key -certfile ca.pem -name ee -passout pass:secret -out ../$O/pkcs12-pbes2.p12
$OSSL pkcs12 -export -in ee-rsa.pem -inkey ee-rsa.key -name ee -legacy -passout pass:secret -out ../$O/pkcs12-legacy.p12 2>/dev/null || echo "no legacy provider: skip"
$OSSL pkcs12 -export -in ee-rsa.pem -inkey ee-rsa.key -name ee -pbmac1_pbkdf2 -passout pass:secret -out ../$O/pkcs12-pbmac1.p12 2>/dev/null || echo "no pbmac1: skip"

# ---------- CMP (OpenSSL mock server) ----------
S=(-use_mock_srv -srv_ref mock -srv_secret pass:test -ref client -secret pass:test -recipient "/CN=Test CA")
cmp() { $OSSL cmp "${S[@]}" "$@" >/dev/null 2>&1 || true; }
$OSSL crl -in full.pem -out crls.pem
cmp -cmd ir -subject "/CN=cmp-client" -newkey ee-ec.key -rsp_cert ee-ec.pem -rsp_capubs ca.pem \
  -rsp_extracerts ca.pem -implicit_confirm -certout x.pem -reqout ../$O/cmp-ir.der -rspout ../$O/cmp-ip-capubs.der
cmp -cmd p10cr -csr tmp.csr -rsp_cert ee-ec.pem -certout x.pem \
  -reqout ../$O/cmp-p10cr.der,../$O/cmp-certconf.der -rspout ../$O/cmp-cp.der,../$O/cmp-pkiconf.der
cmp -cmd cr -subject "/CN=cmp-client" -newkey ee-rsa.key -rsp_cert ee-rsa.pem -popo 2 -certout x.pem \
  -reqout ../$O/cmp-cr-keyenc.der -rspout ../$O/cmp-cp-keyenc.der
cmp -cmd kur -oldcert ee-ec.pem -key ee-ec.key -newkey ee-ec.key -rsp_cert ee-ec.pem -certout x.pem \
  -reqout ../$O/cmp-kur.der,../$O/cmp-certconf-3.der -rspout ../$O/cmp-kup.der,../$O/cmp-pkiconf-3.der
cmp -cmd ir -subject "/CN=cmp-client" -newkey ee-ec.key -rsp_cert ee-ec.pem -poll_count 1 -check_after 0 \
  -certout x.pem -reqout ../$O/cmp-ir-poll.der,../$O/cmp-pollreq.der,../$O/cmp-certconf-2.der \
  -rspout ../$O/cmp-ip-waiting.der,../$O/cmp-pollrep.der,../$O/cmp-pkiconf-2.der
cmp -cmd ir -subject "/CN=cmp-client" -newkey ee-ec.key -rsp_cert ee-ec.pem -send_error -certout x.pem \
  -reqout ../$O/cmp-ir-error.der -rspout ../$O/cmp-error.der
cmp -cmd rr -oldcert ee-ec.pem -revreason 1 -rsp_cert ee-ec.pem -reqout ../$O/cmp-rr.der -rspout ../$O/cmp-rp.der
cmp -cmd genm -infotype signKeyPairTypes -reqout ../$O/cmp-genm.der -rspout ../$O/cmp-genp.der
cmp -cmd genm -infotype crlStatusList -oldcrl crls.pem -rsp_crl crls.pem -crlout y.pem \
  -reqout ../$O/cmp-genm-crls.der -rspout ../$O/cmp-genp-crls.der
cmp -cmd genm -infotype caCerts -rsp_extracerts ca.pem -cacertsout y.pem \
  -reqout ../$O/cmp-genm-cacerts.der -rspout ../$O/cmp-genp-cacerts.der
cmp -cmd genm -infotype rootCaCert -oldwithold ca.pem -rsp_newwithnew ca.pem -rsp_newwithold ca.pem \
  -rsp_oldwithnew ca.pem -newwithnew y.pem -reqout ../$O/cmp-genm-rootca.der -rspout ../$O/cmp-genp-rootca.der
rm -f ../$O/cmp-ir-poll.der ../$O/cmp-ir-error.der

# ---------- certificates with non-conformant DN strings ----------
# Patch the UTF8String values of a certificate (the signature becomes invalid, but the
# structure must be kept unchanged by the decoder):
python3 - ../$O/cert-ee-ec-sha384.der ../$O <<'P'
import sys
d = open(sys.argv[1], 'rb').read()
cn = b'\x13\x0eee.example.com'
assert cn in d
open(sys.argv[2] + '/cert-lenient-printable.der', 'wb').write(d.replace(cn, b'\x13\x0e*e.example.com'))
open(sys.argv[2] + '/cert-printable-latin1.der', 'wb').write(d.replace(cn, b'\x13\x0e\xe9e.example.com'))
open(sys.argv[2] + '/cert-invalid-utf8.der', 'wb').write(d.replace(cn, b'\x0c\x0e\xc3e.example.com'))
P

cd ..; ls -la $O | awk '{print $5, $9}'
