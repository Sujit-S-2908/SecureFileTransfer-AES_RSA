#!/usr/bin/env bash
set -euo pipefail
mkdir -p sample_keys
openssl genpkey -algorithm RSA -out sample_keys/recipient_rsa_2048.priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in sample_keys/recipient_rsa_2048.priv.pem -out sample_keys/recipient_rsa_2048.pub.pem
openssl genpkey -algorithm RSA -out sample_keys/sender_rsa_2048.priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in sample_keys/sender_rsa_2048.priv.pem -out sample_keys/sender_rsa_2048.pub.pem
echo "Sample keys written to sample_keys/"
