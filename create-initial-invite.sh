#!/bin/sh

INVITE_FILE="/keys/initial-invite-code.txt"
MARKER="/keys/.invite_created"

# Check if invite code was already created
if [ -f "$MARKER" ]; then
    echo "✓ Initial invite code already created"
    exit 0
fi

echo "Waiting for database to be ready..."
sleep 10

# Try to create invite code - retry until database is ready
MAX_ATTEMPTS=30
ATTEMPT=0
INVITE_CODE=""

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    OUTPUT=$(/cocoon create-invite-code --uses 1 2>&1)
    INVITE_CODE=$(echo "$OUTPUT" | grep -oE '[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}' || echo "")

    if [ -n "$INVITE_CODE" ]; then
        break
    fi

    if [ $((ATTEMPT % 5)) -eq 0 ]; then
        echo "  Waiting for database... ($ATTEMPT/$MAX_ATTEMPTS)"
    fi
    sleep 2
done

if [ -n "$INVITE_CODE" ]; then
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║   SAVE THIS INVITE CODE!               ║"
    echo "║                                        ║"
    echo "║   $INVITE_CODE                         ║"
    echo "║                                        ║"
    echo "║   Use this to create your first        ║"
    echo "║   account on your PDS.                 ║"
    echo "╚════════════════════════════════════════╝"
    echo ""

    echo "$INVITE_CODE" > "$INVITE_FILE"
    echo "✓ Invite code saved to: $INVITE_FILE"

    touch "$MARKER"
    echo "✓ Initial setup complete!"
else
    echo "✗ Failed to create invite code"
    echo "Output: $OUTPUT"
    exit 1
fi
