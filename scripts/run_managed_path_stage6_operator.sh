#!/bin/zsh
set -eu

usage() {
  echo "用法：$0 archive | $0 <install|apply|recover|rollback> <32位小写十六进制 barrier-id>" >&2
}

root_mode=0
if [ "${1:-}" = "--root" ]; then
  root_mode=1
  shift
fi
if [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

mode="$1"
case "$mode" in
  archive)
    if [ "$#" -ne 1 ]; then usage; exit 2; fi
    barrier_id=
    ;;
  install|apply|recover|rollback)
    if [ "$#" -ne 2 ]; then usage; exit 2; fi
    barrier_id="$2"
    ;;
  *) usage; exit 2 ;;
esac
if [ "$mode" != "archive" ]; then
  case "$barrier_id" in
    *[!0-9a-f]*)
      echo "barrier id 必须是 32 位小写十六进制。" >&2
      exit 2
      ;;
  esac
  if [ "${#barrier_id}" -ne 32 ]; then
    echo "barrier id 必须是 32 位小写十六进制。" >&2
    exit 2
  fi
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
if [ -x "$repo_root/.venv/bin/python" ]; then
  python_bin="$repo_root/.venv/bin/python"
elif [ -x /Users/mac/.local/bin/python3.12 ]; then
  python_bin=/Users/mac/.local/bin/python3.12
else
  python_bin="$(command -v python3)"
fi

cd "$repo_root"

if [ "$root_mode" -eq 0 ]; then
  if [ "$(id -u)" -eq 0 ]; then
    echo "请以普通登录用户运行；脚本会显示系统 sudo 提示。" >&2
    exit 1
  fi
  if [ "$mode" = "archive" ]; then
    exec /usr/bin/sudo "$0" --root archive
  fi
  if [ "$mode" = "install" ]; then
    exec /usr/bin/sudo "$0" --root install "$barrier_id"
  fi
  exec "$python_bin" -m scripts.managed_path_stage6_macos_operator "$mode" "$barrier_id"
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Stage 6 root 子流程必须由 sudo 启动。" >&2
  exit 1
fi
if [ "$mode" = "archive" ]; then
  exec "$python_bin" -m scripts.managed_path_stage6_apply \
    --platform macos \
    --archive-rolled-back
fi

run_stage6() {
  "$python_bin" -m scripts.managed_path_stage6_apply \
    --platform macos \
    --barrier-id "$barrier_id" \
    "$@"
}

case "$mode" in
  install)
    run_stage6 --install-macos-execution-materials
    exit 0
    ;;
  recover)
    IFS= read -r private_identity
    printf '%s\n' "$private_identity" | run_stage6 --identity-stdin --recover
    private_identity=
    exit 0
    ;;
  rollback)
    IFS= read -r private_identity
    printf '%s\n' "$private_identity" | run_stage6 --identity-stdin --rollback-create
    private_identity=
    exit 0
    ;;
esac

ready_path="/Volumes/DarkAI/Codex-project/Side project/Tunnelminion-stage6-data/macos/stage6-apply-ready.json"
data_root="$(dirname "$ready_path")"
for protected_name in \
  stage6-apply-evidence.json \
  stage6-apply-ready.json \
  stage6-apply-go.json \
  stage6-apply-peer-ready.json \
  stage6-apply-governance.sqlite3 \
  stage6-rollback-evidence.json
do
  if [ -e "$data_root/$protected_name" ] || [ -L "$data_root/$protected_name" ]; then
    echo "Stage 6 state already exists: $protected_name. Use recover or rollback; do not apply again." >&2
    exit 1
  fi
done
IFS= read -r private_identity
printf '%s\n' "$private_identity" | run_stage6 --identity-stdin --apply &
apply_pid=$!
private_identity=
deadline=$(( $(date +%s) + 120 ))
while [ ! -f "$ready_path" ]; do
  if ! kill -0 "$apply_pid" 2>/dev/null; then
    wait "$apply_pid"
    exit $?
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "等待 macOS ready marker 超时；apply 进程仍会按自身时限退出。" >&2
    exit 1
  fi
  sleep 1
done

ready_json="$(tr -d '\r\n' < "$ready_path")"
echo ""
echo "把下面这一整行复制到 Windows 管理员脚本："
echo "$ready_json"
echo ""
printf "再把 Windows 脚本输出的 ready JSON 整行粘贴到这里："
IFS= read -r peer_ready </dev/tty
printf '%s' "$peer_ready" | "$python_bin" -m scripts.managed_path_stage6_apply \
  --platform macos \
  --barrier-id "$barrier_id" \
  --import-peer-ready
run_stage6 --release-barrier
wait "$apply_pid"
echo "macOS Stage 6.3 apply、Provider verify、path verify 与 acknowledgement 已完成。"
