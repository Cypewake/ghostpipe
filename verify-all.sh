#!/usr/bin/env bash
# =============================================================================
# verify-all.sh —— ghostpipe 全场景一键回归
#
# 七个场景，每个场景给出 PASS/FAIL：
#   S1 M2 多路复用模式（mux）：外部 curl → 隧道 → 内网 filesrv
#   S2 M1 独立数据连接模式（conn）：同上（DATA_BIND token 绑定路径）
#   S3 SOCKS5 正向代理（M4）：客户端本地入口 → 经隧道由服务端出网
#   S4 WebSocket 载体（M3）：ws 之上的同一套自定义帧协议
#   S5 韧性：杀 client → 自动重连 → 服务端原子替换映射 → 恢复
#   S6 认证负路径：错误 PSK 必须被拒绝且服务端日志留痕
#   S7 服务端 SOCKS5 入口（M4 反向）：外部 curl → 服务端代理 → 经隧道由客户端内网拨号
#      （= frp socks5 插件等价方向：经代理访问客户端所在内网任意设备）
#
# 就绪判定采用【日志语义探针】（等服务端"已监听"/客户端"隧道就绪"日志行），
# 不做网络探测——避免 TLS 端口 HTTP 探测白等与环境代理干扰。
#
# 用法：bash verify-all.sh
# =============================================================================
set -u
cd "$(dirname "$0")"
START=$SECONDS

# 环境代理隔离：本机若配了 http_proxy 会让 curl 全部改道代理，必须显式禁用
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy 2>/dev/null
export NO_PROXY='*' no_proxy='*'
CURL="curl -s --noproxy *"

PASS=0; FAIL=0; DETAILS=""
PIDS=""          # server/client 进程（每场景清理）
FSRV_PID=""
FSRV2_PID=""

GOOS=$(go env GOOS)
SUF=""
[ "$GOOS" = "windows" ] && SUF=".exe"
SRV_BIN="target/ghostpipe-server$SUF"
CLI_BIN="target/ghostpipe-client$SUF"
FSRV_BIN="target/filesrv$SUF"

PSK="3f2a9c8b7e6d5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00"

check() { # check <场景名> <期望关键字> <实际输出>
  if echo "$3" | grep -q "$2"; then
    PASS=$((PASS+1)); DETAILS="$DETAILS  [PASS] $1\n"
  else
    FAIL=$((FAIL+1)); DETAILS="$DETAILS  [FAIL] $1: 未命中「$2」，实际输出：$(echo "$3" | head -c 200)\n"
  fi
}

check_fail() { # check_fail <场景名> <不该出现的关键字> <实际输出>
  if echo "$3" | grep -q "$2"; then
    FAIL=$((FAIL+1)); DETAILS="$DETAILS  [FAIL] $1: 不应命中「$2」却命中\n"
  else
    PASS=$((PASS+1)); DETAILS="$DETAILS  [PASS] $1\n"
  fi
}

wait_log() { # wait_log <日志文件> <日志模式> <最长等待秒>
  local log=$1 pat=$2 deadline=$((SECONDS + $3))
  while [ $SECONDS -lt $deadline ]; do
    if [ -f "$log" ] && grep -q "$pat" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "      [警告] 日志 $log 未出现「$pat」（${3}s）"
  return 1
}

ensure_filesrv() {
  if [ -n "$FSRV_PID" ] && kill -0 "$FSRV_PID" 2>/dev/null; then
    return 0
  fi
  "$FSRV_BIN" 18099 > target/filesrv.log 2>&1 &
  FSRV_PID=$!
  if ! $CURL --max-time 3 -o /dev/null "http://127.0.0.1:18099/"; then
    sleep 1
  fi
}

start_server() { # start_server <日志> <控制端口> <额外参数...>
  local log=$1 port=$2; shift 2
  "$SRV_BIN" -listen "127.0.0.1:$port" -psk "$PSK" "$@" > "$log" 2>&1 &
  PIDS="$PIDS $!"
  wait_log "$log" "控制端口已监听" 20
}

start_client() { # start_client <日志> <控制端口> <映射端口> <额外参数...>  → 设置全局 CLI_PID
  local log=$1 cport=$2 mport=$3; shift 3
  "$CLI_BIN" -server "127.0.0.1:$cport" -psk "$PSK" \
    -tunnel "$mport=127.0.0.1:18099" "$@" > "$log" 2>&1 &
  CLI_PID=$!
  PIDS="$PIDS $CLI_PID"
  wait_log "$log" "隧道就绪" 20
}

fingerprint_of() { # 从服务端日志提取 SPKI 指纹
  grep -oE '[0-9a-f]{64}' "$1" | head -1
}

kill_pids() { for p in $PIDS; do kill "$p" 2>/dev/null; done; PIDS=""; }
trap 'kill_pids; [ -n "$FSRV_PID" ] && kill "$FSRV_PID" 2>/dev/null; [ -n "$FSRV2_PID" ] && kill "$FSRV2_PID" 2>/dev/null' EXIT

# ---------- 准备 ----------
echo "[0/7] 构建..."
mkdir -p target
if go build -o "$SRV_BIN" ./cmd/server && go build -o "$CLI_BIN" ./cmd/client && go build -o "$FSRV_BIN" ./cmd/filesrv; then
  echo "      构建 OK"
else
  echo "      构建失败"; exit 1
fi
ensure_filesrv

# ---------- S1 M2 多路复用（mux） ----------
echo "[1/7] S1 多路复用模式（mux）"
start_server target/v-s1.log 19001
FP=$(fingerprint_of target/v-s1.log)
start_client target/c-s1.log 19001 19122 -fingerprint "$FP"
OUT_S1=$($CURL --max-time 8 "http://127.0.0.1:19122/")
check "S1 隧道转发内容" "ghostpipe-e2e-ok" "$OUT_S1"
CONC_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  $CURL --max-time 8 "http://127.0.0.1:19122/" | grep -q "ghostpipe-e2e-ok" && CONC_OK=$((CONC_OK+1))
done
check "S1 并发 10 连接全部成功" "^10$" "$CONC_OK"
kill_pids; sleep 1

# ---------- S2 M1 独立数据连接（conn，两端都要 -mode conn） ----------
echo "[2/7] S2 独立数据连接模式（conn）"
start_server target/v-s2.log 19002 -mode conn
FP=$(fingerprint_of target/v-s2.log)
start_client target/c-s2.log 19002 19222 -fingerprint "$FP" -mode conn
OUT_S2=$($CURL --max-time 8 "http://127.0.0.1:19222/")
check "S2 隧道转发内容" "ghostpipe-e2e-ok" "$OUT_S2"
check "S2 服务端日志含绑定记录" "数据连接已绑定" "$(cat target/v-s2.log)"
kill_pids; sleep 1

# ---------- S3 SOCKS5（M4，mux 模式） ----------
echo "[3/7] S3 SOCKS5 正向代理"
start_server target/v-s3.log 19003
FP=$(fingerprint_of target/v-s3.log)
"$CLI_BIN" -server "127.0.0.1:19003" -psk "$PSK" -fingerprint "$FP" \
  -socks5 "127.0.0.1:19080" > target/c-s3.log 2>&1 &
CLI_PID=$!; PIDS="$PIDS $CLI_PID"
wait_log target/c-s3.log "SOCKS5 已监听" 20
sleep 1
OUT_S3=$($CURL --max-time 8 --socks5 "127.0.0.1:19080" "http://127.0.0.1:18099/")
check "S3 SOCKS5 动态出口" "ghostpipe-e2e-ok" "$OUT_S3"
kill_pids; sleep 1

# ---------- S4 WebSocket 载体（M3） ----------
echo "[4/7] S4 WebSocket 载体"
start_server target/v-s4.log 19004 -ws
FP=$(fingerprint_of target/v-s4.log)
start_client target/c-s4.log 19004 19422 -fingerprint "$FP" -ws
OUT_S4=$($CURL --max-time 8 "http://127.0.0.1:19422/")
check "S4 WS 之上帧协议可用" "ghostpipe-e2e-ok" "$OUT_S4"
kill_pids; sleep 1

# ---------- S5 韧性：杀 client 自动重连 ----------
echo "[5/7] S5 断线重连与映射原子替换"
start_server target/v-s5.log 19005
FP=$(fingerprint_of target/v-s5.log)
start_client target/c-s5.log 19005 19522 -fingerprint "$FP"
OUT_PRE=$($CURL --max-time 8 "http://127.0.0.1:19522/")
check "S5 断线前可用" "ghostpipe-e2e-ok" "$OUT_PRE"
# 杀掉 client（模拟内网机器断网/进程崩溃）
kill -9 "$CLI_PID" 2>/dev/null
PIDS=$(echo "$PIDS" | tr ' ' '\n' | grep -v "^$CLI_PID$" | tr '\n' ' ')
sleep 2
start_client target/c-s5b.log 19005 19522 -fingerprint "$FP"
sleep 1   # 给重连+替换留时间
OUT_POST=$($CURL --max-time 8 "http://127.0.0.1:19522/")
check "S5 重连后恢复" "ghostpipe-e2e-ok" "$OUT_POST"
# kill -9 后服务端读循环立即感知断连并释放端口（先于新客户端注册）；
# 跨会话抢占（僵尸会话未超时）由全局端口归属表兜底，此处验证新实例完成二次注册
REG_COUNT=$(grep -c "隧道注册" target/v-s5.log)
check "S5 新实例完成二次注册" "^2$" "$REG_COUNT"
kill_pids; sleep 1

# ---------- S6 认证负路径 ----------
echo "[6/7] S6 错误 PSK 拒绝"
start_server target/v-s6.log 19006
FP=$(fingerprint_of target/v-s6.log)
BAD_PSK="0000000000000000000000000000000000000000000000000000000000000000"
"$CLI_BIN" -server "127.0.0.1:19006" -psk "$BAD_PSK" -fingerprint "$FP" \
  -tunnel "19626=127.0.0.1:18099" > target/c-s6.log 2>&1 &
CLI_PID=$!; PIDS="$PIDS $CLI_PID"
sleep 4
OUT_S6=$($CURL --max-time 5 "http://127.0.0.1:19626/" 2>/dev/null)
check_fail "S6 错误 PSK 无法获得服务" "ghostpipe-e2e-ok" "$OUT_S6"
check "S6 服务端日志记录认证失败" "认证失败" "$(cat target/v-s6.log)"
kill_pids; sleep 1

# ---------- S7 服务端 SOCKS5 入口（M4 反向 = frp socks5 插件等价方向） ----------
# 拓扑：filesrv2(18199) 模拟"客户端内网设备"。
# 外部 curl → 服务端 SOCKS5(19081) → OPEN_ADDR(S→C) 经隧道 → 客户端内网拨号 127.0.0.1:18199。
# 生产语义：把 127.0.0.1:18199 换成 client 所在内网任意 IP:端口 即可访问内网设备。
echo "[7/7] S7 服务端 SOCKS5 访问客户端内网"
"$FSRV_BIN" 18199 > target/filesrv2.log 2>&1 &
FSRV2_PID=$!
start_server target/v-s7.log 19007 -socks5 "127.0.0.1:19081"
check "S7 服务端 SOCKS5 已监听" "SOCKS5 已监听" "$(cat target/v-s7.log)"
FP=$(fingerprint_of target/v-s7.log)
start_client target/c-s7.log 19007 19727 -fingerprint "$FP"
sleep 1   # 等客户端完成注册（服务端 SOCKS5 依赖活跃会话）
OUT_S7=$($CURL --max-time 8 --socks5 "127.0.0.1:19081" "http://127.0.0.1:18199/")
check "S7 经服务端代理访问客户端内网设备" "ghostpipe-e2e-ok" "$OUT_S7"
kill_pids

# ---------- 汇总 ----------
echo
echo "================ 验收汇总 ================"
echo -e "$DETAILS"
echo "PASS=$PASS FAIL=$FAIL"
echo "总耗时：$((SECONDS - START)) 秒"
[ $FAIL -eq 0 ] && echo "结论：全部场景通过 ✅" || echo "结论：存在失败项 ❌（详见上方 FAIL 行）"
exit $FAIL
