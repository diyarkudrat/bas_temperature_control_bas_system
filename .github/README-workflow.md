## Overview
Integrates lightweight feature-capture workflow using GitHub Issues with minimal automation.

## Changes
- **Labels**: 8 standardized labels (idea, in-progress, done, spike, tech-debt, perf, security, blocked)
- **Issue Template**: Feature request form with Goal, Context, Approach, Acceptance Criteria
- **Blank Issues**: Disabled to force template usage
- **TODO→Issue**: Optional workflow to convert code TODOs to issues (gated by repo variable)
- **CLI Scripts**: Quick issue creation commands

## Usage
```bash
# Quick idea capture
./scripts/capture-idea.sh \"Add dark mode support\"

# Detailed feature request  
./scripts/create-feature-issue.sh \"Implement auth\" \"Add OAuth2 login\"
```

## Setup Required
1. Create remaining labels: \`gh label create \"in-progress\" --description \"Work in progress\" --color \"0e8a16\"\`
2. Set repo variable \`ENABLE_TODO_TO_ISSUE=true\` for TODO→Issue automation

## Testing
- ✅ Created test issues via CLI
- ✅ Labels applied correctly
- ✅ No automatic branch/PR creation (record-only workflow)
