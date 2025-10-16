#!/bin/bash

# quick-idea.sh - Super quick idea capture
# Usage: ./scripts/quick-idea.sh "Your idea here"

set -e

# Check if GitHub CLI is available
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) not found. Please install it first."
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub. Run 'gh auth login' first."
    exit 1
fi

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 \"Your idea or feature description\""
    echo ""
    echo "Examples:"
    echo "  $0 \"Add dark mode support\""
    echo "  $0 \"Implement user authentication\""
    echo "  $0 \"Fix the login bug\""
    exit 1
fi

IDEA="$1"

echo "💡 Capturing idea..."

# Create the issue with minimal structure
ISSUE_URL=$(gh issue create \
    --title "$IDEA" \
    --label "idea" \
    --body "**Goal:** $IDEA

**Context:** (Add background here)

**Next Steps:** (Add approach here)")

echo "✅ Idea captured: $ISSUE_URL"
echo "📝 Edit the issue to add more details when ready"
