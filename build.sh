#!/bin/bash
# Build client, DS
bun ./bundle.ts
# Build docs
bun docs:build
mv docs/.vitepress/dist build/docs