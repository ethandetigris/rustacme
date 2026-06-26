#!/bin/bash
# ============================================================
# rustacme 一键部署脚本
# 用法: bash deploy.sh
# ============================================================
set -e
cd "$(dirname "$0")"

IMAGE="${RUSTACME_IMAGE:-ghcr.io/ethandetigris/rustacme:latest}"

if [ ! -f .env ]; then
    echo "ERROR: .env 文件不存在，请先创建。"
    echo "参考:"
    echo "  cp .env.example .env"
    echo "  chmod 600 .env"
    exit 1
fi

echo ">>> 启动容器..."
mkdir -p certs
chmod 700 certs
RUSTACME_IMAGE="$IMAGE" docker compose up -d
echo ">>> 完成。查看日志: docker logs rustacme"
