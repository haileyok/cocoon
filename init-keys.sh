#!/bin/sh
set -e

mkdir -p /keys
mkdir -p /data/cocoon

if [ ! -f /keys/rotation.key ]; then
    echo "Generating rotation key..."
    /cocoon create-rotation-key --out /keys/rotation.key 2>/dev/null || true
    if [ -f /keys/rotation.key ]; then
        echo "✓ Rotation key generated at /keys/rotation.key"
    else
        echo "✗ Failed to generate rotation key"
        exit 1
    fi
else
    echo "✓ Rotation key already exists"
fi

if [ ! -f /keys/jwk.key ]; then
    echo "Generating JWK..."
    /cocoon create-private-jwk --out /keys/jwk.key 2>/dev/null || true
    if [ -f /keys/jwk.key ]; then
        echo "✓ JWK generated at /keys/jwk.key"
    else
        echo "✗ Failed to generate JWK"
        exit 1
    fi
else
    echo "✓ JWK already exists"
fi

echo ""
echo "✓ Key initialization complete!"
