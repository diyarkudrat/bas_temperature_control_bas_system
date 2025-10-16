#!/bin/bash

# new-feature.sh - Quick feature issue creation script
# Usage: ./scripts/new-feature.sh "Title" "Brief description"

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
    echo "Usage: $0 \"Feature Title\" [\"Brief description\"]"
    echo ""
    echo "Examples:"
    echo "  $0 \"Add dark mode support\""
    echo "  $0 \"Implement user authentication\" \"Add OAuth2 login flow\""
    exit 1
fi

TITLE="$1"
DESCRIPTION="${2:-$1}"  # Use title as description if none provided

echo "🚀 Creating new feature issue..."

# Create the issue
ISSUE_URL=$(gh issue create \
    --title "$TITLE" \
    --label "idea" \
    --body "Goal: $DESCRIPTION

Context: (Add background and motivation here)

Rough Approach: (Add implementation ideas here)

Acceptance Criteria:
- [ ] Clear success metrics defined
- [ ] User-facing functionality working
- [ ] Code reviewed and tested
- [ ] Documentation updated")

echo "✅ Feature issue created: $ISSUE_URL"
echo ""
echo "📝 Next steps:"
echo "   1. Click the link above to edit the issue"
echo "   2. Fill in Context and Rough Approach sections"
echo "   3. Add any additional labels as needed"
echo ""
echo "🎯 Use 'idea' label for initial concepts, then move to 'in-progress' when starting work"
