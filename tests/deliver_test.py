#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真机端到端交付测试。密码经环境变量 P1/P2 注入,不落盘。
覆盖:vault、host CRUD、脱敏、真实 SSH connect、exec(argv/raw/script/注入防护)、
PTY 交互、SFTP 往返、reveal 主密码门禁、审计。"""
import json, os, sys, time, urllib.request, urllib.error

BASE = os.environ.get("BASE", "http://127.0.0.1:7600")
MP = os.environ.get("MP", "deliver-test-master-pw")

def require_env(name):
    value = os.environ.get(name)
    if not value:
        print(f"missing required environment variable: {name}", file=sys.stderr)
        sys.exit(2)
    return value

def host_from_env(prefix, default_alias):
    return {
        "alias": os.environ.get(f"{prefix}_ALIAS", default_alias),
        "host": require_env(f"{prefix}_HOST"),
        "port": int(os.environ.get(f"{prefix}_PORT", "22")),
        "user": os.environ.get(f"{prefix}_USER", "root"),
    }

H1 = host_from_env("H1", "机器1-ubuntu")
H2 = host_from_env("H2", "机器2-ubuntu")

passed = []; failed = []
def ok(m):  passed.append(m); print(f"  ✅ {m}")
def bad(m): failed.append(m); print(f"  ❌ {m}")

def http(path, obj=None, method=None):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(BASE + path, data=data,
        headers={'Content-Type': 'application/json'}, method=method or ('POST' if data else 'GET'))
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

class Mcp:
    def __init__(self):
        r = urllib.request.urlopen(urllib.request.Request(BASE+"/mcp",
            data=json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-03-26","capabilities":{},
                "clientInfo":{"name":"deliver","version":"1"}}}).encode(),
            headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream'}))
        self.sid = r.headers.get('mcp-session-id'); r.read()
        urllib.request.urlopen(urllib.request.Request(BASE+"/mcp",
            data=json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}).encode(),
            headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                     'mcp-session-id':self.sid})).read()
        self._id = 1
    def call(self, name, args):
        self._id += 1
        body = urllib.request.urlopen(urllib.request.Request(BASE+"/mcp",
            data=json.dumps({"jsonrpc":"2.0","id":self._id,"method":"tools/call",
                "params":{"name":name,"arguments":args}}).encode(),
            headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                     'mcp-session-id':self.sid}), timeout=60).read().decode()
        datas = [l[6:] for l in body.splitlines() if l.startswith("data: ") and l[6:].strip()]
        env = json.loads(datas[-1]) if datas else {}
        if "error" in env: return {"_error": env["error"]}
        # 工具结果文本在 content[0].text 里(JSON 字符串)
        try:
            return json.loads(env["result"]["content"][0]["text"])
        except Exception:
            return env.get("result", env)

def main():
    print("===== 1. 状态 / vault =====")
    print("  status:", http("/api/status"))
    r = http("/api/vault/init", {"master_password": MP})
    ok("vault 初始化") if r.get("ok") else bad(f"vault 初始化: {r}")

    print("===== 2. 添加两台真机 =====")
    a1 = http("/api/hosts", {**H1, "auth": {"type":"password","password":os.environ["P1"]}})
    id1 = a1.get("host_id"); ok(f"添加机器1 ({id1})") if id1 else bad(f"添加机器1: {a1}")
    a2 = http("/api/hosts", {**H2, "auth": {"type":"password","password":os.environ["P2"]}})
    id2 = a2.get("host_id"); ok(f"添加机器2 ({id2})") if id2 else bad(f"添加机器2: {a2}")

    print("===== 3. 列表脱敏 =====")
    lst = json.dumps(http("/api/hosts"), ensure_ascii=False)
    leak = os.environ["P1"][:6] in lst or os.environ["P2"][:6] in lst or "password" in lst.lower() and os.environ["P1"] in lst
    bad("列表泄露密码!") if (os.environ["P1"] in lst or os.environ["P2"] in lst) else ok("列表无明文密码")

    print("===== 4. connect 真机(真实 SSH 握手) =====")
    c1 = http(f"/api/hosts/{id1}/connect", {})
    ok("机器1 连接") if c1.get("status")=="connected" else bad(f"机器1 连接: {c1}")
    c2 = http(f"/api/hosts/{id2}/connect", {})
    ok("机器2 连接") if c2.get("status")=="connected" else bad(f"机器2 连接: {c2}")

    m = Mcp(); ok(f"MCP 会话 ({m.sid[:8]})")

    print("===== 5. exec argv(自动转义) =====")
    r = m.call("exec", {"host_id": id1, "argv": {"argv": ["uname","-a"]}})
    ok("exec argv (uname)") if "Linux" in r.get("stdout","") else bad(f"exec argv: {r}")

    print("===== 6. exec raw + 退出码 =====")
    r = m.call("exec", {"host_id": id1, "raw": {"raw": "echo hi-机器1 && hostname && exit 7"}})
    ok("exec raw 输出") if "hi-机器1" in r.get("stdout","") else bad(f"exec raw: {r}")
    ok("退出码捕获(7)") if r.get("exit_code")==7 else bad(f"退出码: {r.get('exit_code')}")

    print("===== 7. exec script(SFTP 上传执行) =====")
    r = m.call("exec", {"host_id": id2, "script": {"script": "#!/bin/bash\nfor i in 1 2 3; do echo line$i; done"}})
    ok("exec script 多行") if r.get("stdout","").count("line")==3 else bad(f"exec script: {r}")

    print("===== 8. 注入防护(argv 元字符当字面量) =====")
    r = m.call("exec", {"host_id": id1, "argv": {"argv": ["echo", "$(id); rm -rf /tmp/x"]}})
    out = r.get("stdout","")
    ok("argv 防注入(元字符未执行)") if "$(id)" in out and "uid=" not in out else bad(f"防注入: {r}")

    print("===== 9. PTY 交互 =====")
    info = m.call("session_open", {"host_id": id2, "rows":24, "cols":80})
    sess = info.get("session_id")
    ok(f"PTY 打开 ({sess[:8] if sess else '?'})") if sess else bad(f"PTY 打开: {info}")
    if sess:
        time.sleep(1)
        m.call("session_send_text", {"session_id": sess, "text": "echo PTY_OK_MARKER"})
        m.call("session_send_key", {"session_id": sess, "key": "enter"})
        time.sleep(1.5)
        scr = m.call("session_screen", {"session_id": sess})
        rows = scr.get("screen", []) if isinstance(scr, dict) else []
        joined = "\n".join(rows) if rows else json.dumps(scr, ensure_ascii=False)
        ok("PTY 屏幕快照含回显") if "PTY_OK_MARKER" in joined else bad(f"PTY 屏幕: {joined[:200]}")
        m.call("session_close", {"session_id": sess}); ok("PTY 关闭")

    print("===== 10. SFTP 往返(含中文) =====")
    stamp = f"deliver-{int(time.time())}"
    content = f"内容验证-{stamp}-✓"
    m.call("sftp_put", {"host_id": id1, "path": f"/tmp/{stamp}.txt", "content": content})
    ls = m.call("sftp_list", {"host_id": id1, "path": "/tmp"})
    names = [e.get("name","") for e in ls.get("entries",[])] if isinstance(ls,dict) else []
    ok("SFTP 上传+列目录") if any(stamp in n for n in names) else bad(f"SFTP 列目录: {names[:5]}")
    g = m.call("sftp_get", {"host_id": id1, "path": f"/tmp/{stamp}.txt"})
    ok("SFTP 下载内容一致(中文)") if g.get("content")==content else bad(f"SFTP 下载: {g}")
    m.call("exec", {"host_id": id1, "argv": {"argv": ["rm","-f",f"/tmp/{stamp}.txt"]}})

    print("===== 11. reveal 主密码门禁 =====")
    rv = http(f"/api/hosts/{id1}/reveal", {"master_password": MP})
    ok("reveal 正确主密码返回凭据") if "auth" in rv else bad(f"reveal: {rv}")
    rvb = http(f"/api/hosts/{id1}/reveal", {"master_password": "wrong"})
    ok("reveal 错误主密码被拒") if rvb.get("code") in ("vault_bad_password","auth_failed","vault_locked") else bad(f"reveal 错误密码: {rvb}")

    print("===== 12. 审计日志 =====")
    au = http("/api/audit?limit=50")
    n = len(au.get("entries", []))
    ok(f"审计记录 {n} 条") if n > 0 else bad("审计为空")

    print(f"\n========== 结果: 通过 {len(passed)} / 失败 {len(failed)} ==========")
    if failed:
        print("失败项:");  [print("  -", f) for f in failed]
        sys.exit(1)

if __name__ == "__main__":
    main()
