#!/bin/sh
# .git/hooks/pre-push
echo "Checking author tests before push..."
prove -lr xt || {
    echo "Tests failed; push aborted. (can push with --no-verify)"
    exit 1
}
