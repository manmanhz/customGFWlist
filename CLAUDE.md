# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a custom GFWList rule repository for proxy software. It maintains domain-based proxy rules used by Clash, ClashMeta, ShellClash, Surge, and Shadowrocket.

## Key File Types

- **.yaml files** - Clash/ClashMeta configuration with proxy providers, proxy groups, and rules
- **.list files** - Domain suffix rules in format: `DOMAIN-SUFFIX,example.com`
- **.ini files** - Surge/Shadowrocket configurations
- **white.list** - Whitelist rules (domains that should bypass proxy)

## Main Files

- `proxy_rule_antcc.yaml` - Primary Clash configuration with regional proxy groups (HK, TW, JP, US, SG)
- `proxy_rule_202507.yaml` - Updated Clash configuration
- `proxy_rule_simplified.yaml` - Simplified version
- `proxy.list` - Custom domain rules requiring proxy
- `white.list` - Domains that should not use proxy

## Workflow

This repository is data-driven. To update rules:
1. Add/remove domain suffixes in `proxy.list` (format: `- DOMAIN-SUFFIX,domain.com`)
2. Commit changes with descriptive message
3. Push to remote for distribution
