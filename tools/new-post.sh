#!/usr/bin/env bash

set -e

title=""
categories=""
tags=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --title)
      title="$2"
      shift 2
      ;;
    --categories)
      categories="$2"
      shift 2
      ;;
    --tags)
      tags="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo 'Usage: ./tools/new-post.sh --title "HTB Shoppy" --categories "CPTS Preparation" --tags "HTB, Machine, Linux, Easy"'
      exit 1
      ;;
  esac
done

if [[ -z "$title" ]]; then
  echo "Error: --title is required"
  exit 1
fi

slug="$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/^htb //; s/[^a-z0-9]/-/g; s/-\+/-/g; s/^-//; s/-$//')"
date_file="$(date +%F)"
date_frontmatter="$(date '+%Y-%m-%d %H:%M %z')"
post_file="_posts/${date_file}-htb-${slug}.md"
image_dir="assets/img/posts/${slug}"
image_path="/assets/img/posts/${slug}/${slug}.png"

mkdir -p "$image_dir"

cat > "$post_file" <<EOF
---
title: "$title"
date: $date_frontmatter
categories: [$categories]
tags: [$tags]
image: $image_path
---

## Machine Information

## Reconnaissance

### Scanning

- Nmap (All ports)

\`\`\`
\`\`\`

- NSE Scripts & Version

\`\`\`
\`\`\`

### Configuration

- /etc/hosts

\`\`\`bash
sudo nxc smb \$ip --generate-hosts-file /etc/hosts
\`\`\`

- /etc/krb5.conf

\`\`\`bash
sudo nxc smb \$domain --generate-krb5-file /etc/krb5.conf
\`\`\`

- time

\`\`\`bash
sudo ntpdate -u \$domain
\`\`\`
EOF

echo "Created $post_file"
echo "Created $image_dir"