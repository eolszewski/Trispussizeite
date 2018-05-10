#!/bin/sh

# Create a Key
gpg --batch --yes --no-tty --gen-key ./gen-alice.eddsa
echo 'hello' `date +%s` > ./data/doc

# Encrypt & Decrypt
echo 'secret' | gpg --batch --passphrase-fd 0 -u "Alice" --no-tty -c ./data/doc
echo 'secret' | gpg --batch --passphrase-fd 0 -u "Alice" --no-tty -d ./data/doc.gpg  

# Sign and Verify
echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 -u "Alice" --output ./data/doc2.sig --sign ./data/doc
gpg --verify ./data/doc2.sig 

# Export a Public Key
gpg --export -a "Alice" > ./data/public.key
# Armored
gpg --export -a "Alice" > ./data/public_key.asc
# cat public.key

# Export a Private Key
echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 --export-secret-key "Alice" > ./data/private.key
# Armored
echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 --export-secret-key -a "Alice" > ./data/private_key.asc
# cat private.key

# Export All
# gpg -a --export > ./data/public_keys.asc
# echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 -a --export-secret-keys > ./data/private_keys.asc
gpg --export-ownertrust > ./data/trust.txt

npm run test:ci