# agw

一个按配置顺序尝试上游的 Go HTTP reverse proxy。客户端不需要携带认证信息，代理会根据每个上游的 `authorization` 配置注入 `Authorization` header。

访问 `/` 可以打开基于 HTMX 的配置可视化页面；`/config` 返回可局部刷新的配置表格。认证值默认脱敏，点击“显示”后才在当前页面显示。

## 运行

```bash
go mod tidy
go run ./cmd/agw
```

`-config` 默认为当前目录的 `config.yaml`。监听端口优先读取环境变量 `PORT`，未设置时默认为 `:8080`；也可以用 `-listen` 覆盖。`-timeout` 默认是 `0`，不会设置请求总超时，适合长时间的 SSE 流；需要限制时可以显式设置，例如 `-timeout 2m`。
使用 `--allow-debug` 允许 request header 日志生效：未设置时，即使 `config.yaml` 里写了 `debug: true`、或通过页面提交修改，运行时都保持关闭（页面也不会显示 Debug headers 开关）；设置后，配置里的 `debug: true` 才会在运行时生效，并可通过页面 toggle 切换保存。
日志默认只进 `/logs` 实时流（保留最近 100 条），**不写入 stderr**，避免托管方从终端日志里看到敏感信息；需要同时输出到 stderr 时加 `-log-stderr`（或 `--log-stderr`）。

公开托管时建议设置管理面 Basic Auth：可通过 `--admin-user` / `--admin-password` 或环境变量 `AGW_ADMIN_USER` / `AGW_ADMIN_PASSWORD` 配置（两者必须同时设置，flag 优先于环境变量；密码建议走环境变量，避免出现在进程列表和历史记录里）。设置后，配置页 `/`、`/config`、`/logs`、Session journal（`/sessions*`）和 Stats（`/stats*`）这些管理路径需要 HTTP Basic Auth 才能访问，代理路径（`/v1/...`）保持开放；未设置时管理面不启用认证，保持原来的行为。凭据不会写入配置或出现在配置页中。

### Secrets（浏览器本地保存，服务端只存内存）

凭据与配置分离，且**服务端不落盘、不可读回**：`config.yaml` 里不保存 token，`authorization.value` 只写自动生成的 `secret:<key>` 引用；真实值（key → value 映射）只保存在浏览器 `localStorage`，页面加载时通过只写的 `POST /config/secrets` 注入服务端内存，服务端没有任何读取 secrets 的接口：

```yaml
# config.yaml
upstreams:
  - url: https://api.openai.com/v1
    authorization:
      type: bearer
      value: secret:3f9a1c2d4e5b6f7a8b9c0d1e2f3a4b5c
```

```yaml
# 浏览器 localStorage 中的 secrets（键值对，key 由服务端随机生成）
3f9a1c2d4e5b6f7a8b9c0d1e2f3a4b5c: sk-xxxxxxxx
```

行为说明：

- **浏览器是唯一持久源**：localStorage 为空时直接空注入，凭据需通过"密钥"modal 从你自己的本地副本粘贴进来；服务端不会把 secrets 读回来给你。
- **重启自动解锁**：服务端重启后内存清空，重新打开管理页面会自动用 localStorage 里的凭据解锁，无需重新输入。
- **保存即外部化**：配置页/UI 编辑时看到的是由**当前浏览器**用自己 localStorage 解析出的真实值（密码框默认掩码）；保存时字面量自动生成 key 并只把 `secret:<key>` 写进 config.yaml，相同值复用同一个 key、改动值生成新 key。
- **新 key 回传**：保存响应会把本次新生成 key→value 分配返回给浏览器（值就是你刚提交的那些），浏览器合并进 localStorage，保证重启后凭据不丢。
- **跨浏览器隔离**：`/config` 片段只渲染 `secret:<key>` 引用，值完全由每个浏览器从自己的 localStorage 解析；其他浏览器注入到服务端的凭据不会在本会话中显示。
- **未匹配显示锁定**：当前浏览器没有对应密钥的 upstream，authentication 栏只显示锁图标（引用保留在隐藏字段，不在页面明文展示）；该行整体只读、禁止删除，但可以 duplicate 后再编辑副本。
- 密钥管理入口：顶栏"密钥"按钮可查看/粘贴 key→value 并保存到浏览器。
- `authorization.value` 仍支持 `env:<VAR>` 直接引用环境变量（也是一种引用，config.yaml 里不含明文）。
- `GET /config/yaml` 导出的是磁盘形态：只有 `secret:<key>` 引用，不含真实值；YAML modal 里的"合并显示"由浏览器用 localStorage 本地合并，服务端不出值。

配置可以是旧版 upstream 数组，也可以是带 `appSelectors` 的对象。连接失败或上游返回 `502`、`503`、`504` 时会继续尝试下一个上游；其他响应会直接返回给客户端。
上游配置中的 URL 只提供 scheme 和 host，客户端请求的原始 path 和 query 会原样传递给上游，不会做路径前缀拼接或改写。
所有上游 `4xx/5xx` 响应都会记录到 `/logs` 实时流，包含响应体内容；正常响应保持流式转发。
代理向上游请求时使用 `Accept-Encoding: identity`，避免压缩错误 body 造成日志乱码。
服务自动添加 CORS header，当前允许任意 Origin、method 和 header；浏览器的 CORS 预检请求会直接返回 `204`。

```yaml
- url: https://pai.d1v.ai/v1
  authorization:
    type: bearer
    value: sk-example
- url: https://backup.example/v1
  authorization:
    type: basic
    value: user:pass
```

认证类型暂时支持 `none`、`basic`、`bearer`。页面中使用下拉框选择类型；`none` 会原样透传客户端的 `Authorization`，`basic` 和 `bearer` 会使用配置值覆盖客户端认证。`basic` 的 `user:pass` 会自动进行 Base64 编码。

配置页面支持拖动表格行调整重试顺序，直接编辑 URL、认证类型、认证值以及 upstream 兼容的 selector；认证值可以切换显示/隐藏，点击“保存”后会写回 `config.yaml` 并自动刷新。页面还支持新增和删除 upstream，以及新增、删除、排序 AppSelector。每个 selector 的规则统一放在一列里，每条规则带类型标签（path / header / body / rewrite）和启用开关：点“＋ 添加规则”会弹出菜单选择规则类型，用开关临时禁用某条规则方便调试，不用整个删除。

`appSelectors` 是服务端内部的应用识别规则，不要求客户端携带任何 AGW 专用 header。每个 selector 按配置顺序匹配请求的 URL path、query 参数、HTTP header 和 JSON body 字段，支持 `exact`、`prefix`、`contains`、`regex` 和 `present`；query / header / body 规则默认不区分大小写，可为单条规则设定 `caseSensitive: true`，path 规则按 URL 规范区分大小写。规则可以设置 `enabled: false` 临时禁用（缺省视为启用），禁用的规则不参与匹配、也不参与校验，方便调试时保存半成品配置。首个命中的 selector 决定路由。upstream 的 `appSelectors` 是它兼容的 selector 名称列表，只有兼容的 upstream 才会进入该请求的逐级重试链。未配置任何 selector 时保持旧行为，所有 upstream 按原顺序参与重试。

### Query 匹配（按 URL 参数路由）

`match.query` 按参数名精确查找请求的 query string（如 `?api-version=2024-02-15`），值沿用与 header 相同的算子；同名参数出现多次时，任意一个值命中即算匹配。适合按客户端传的参数分流，例如不同 `api-version` 走不同上游：

```yaml
appSelectors:
  - name: by-version
    match:
      query:
        - name: api-version
          operator: prefix
          value: 2024

upstreams:
  - url: https://2024.example
    name: v2024
    appSelectors: [by-version]
```

### Path 匹配（按 API 风格路由）

`match.path` 只匹配请求的 URL path（不含 query），适合按 API 风格分流：Anthropic `/v1/messages`、OpenAI Chat Completions `/v1/chat/completions`、OpenAI Responses `/v1/responses`。path 与 header、body 一样是规则列表，同一个 selector 内的所有规则全部命中才算匹配，可以把 path 规则与 header / body 规则混用。

```yaml
appSelectors:
  - name: anthropic-messages
    match:
      path:
        - operator: exact
          value: /v1/messages
  - name: chat-completions
    match:
      path:
        - operator: exact
          value: /v1/chat/completions
  - name: responses-api
    match:
      path:
        - operator: exact
          value: /v1/responses

upstreams:
  - url: https://anthropic.example
    name: claude
    appSelectors: [anthropic-messages]
  - url: https://deepseek.example
    name: deepseek
    appSelectors: [chat-completions]
  - url: https://api.openai.com
    name: openai
    appSelectors: [responses-api, chat-completions]
```

请求 path 会原样透传给上游（上游 URL 只提供 scheme 和 host），所以 `/v1/responses` 的请求只会到达声明了 `responses-api` selector 的 upstream；没有兼容 upstream 时返回 `503`，避免把请求盲目打到只支持 Chat Completions 的上游。

### Body peek（JSON body 匹配）

body 匹配从请求的 JSON body 中按点分路径取字段（例如 `model` 或 `metadata.provider`），再套用与 header 相同的运算符。标量值按字符串比较；数组和对象会先 JSON 序列化，因此 `contains` 可以搜索序列化后的文本。非 JSON body、字段缺失或值为 `null` 时该条规则不匹配。代理在路由前本来就会把整个 body 读入内存，所以 body peek 不会增加额外的读 body 开销。

```yaml
appSelectors:
  - name: deepseek-model
    match:
      body:
        - field: model
          operator: prefix
          value: deepseek
  - name: streaming
    match:
      body:
        - field: stream
          operator: exact
          value: "true"
```

上面的示例会把 body 中 `"model": "deepseek-..."` 的请求路由到声明了 `deepseek-model` selector 的 upstream；`headers` 与 `body` 规则可以混用，同一个 selector 内的所有规则都命中才算匹配。

### Rewrite（转发前改写 body）

命中 selector 后，可以在转发前用 `rewrite` 改写 JSON body 的字段，语义类似 jq 的 field set：字段不存在时会自动创建（包括中间的嵌套对象）。`value` 按 JSON 解析，能解析成数字、布尔、`null`、数组或对象时就保留其类型，否则按普通字符串处理；例如 `value: "true"` 会写入布尔 `true`，`value: 0.5` 写入数字，`value: gpt-5.6-luna` 写入字符串。改写后的 body 会发给该 selector 对应的整条 retry 链上的所有 upstream，Session journal 里展示的也是改写后实际转发的 body，并在事件里记录每次 `field -> value` 改写。

```yaml
appSelectors:
  - name: deepseek-model
    match:
      body:
        - field: model
          operator: prefix
          value: deepseek
    rewrite:
      - field: model
        value: gpt-5.6-luna
      - field: stream
        value: "true"
```

```yaml
debug: false
appSelectors:
  - name: openai-client
    match:
      headers:
        - name: User-Agent
          operator: contains
          value: OpenAI
  - name: deepseek-model
    match:
      body:
        - field: model
          operator: prefix
          value: deepseek
    rewrite:
      - field: model
        value: gpt-5.6-luna
  - name: fallback
upstreams:
  - url: https://pai.d1v.ai/v1
    name: luna-primary
    appSelectors: [openai-client]
    authorization:
      type: bearer
      value: replace-with-your-token
  - url: https://deepseek.example/v1
    name: deepseek
    appSelectors: [deepseek-model]
    authorization:
      type: bearer
      value: replace-with-your-deepseek-token
  - url: https://backup.example/v1
    name: fallback
    appSelectors: [fallback]
    authorization:
      type: bearer
      value: replace-with-your-backup-token
```

页面下方的实时日志通过 SSE 从 `/logs` 推送，保留最近 100 条日志并自动滚动到底部。
日志下方的 Session journal 通过 `/sessions` 和 `/sessions/stream` 展示最近的 API 请求；每个入站请求由服务端分配独立 UUIDv7，不会依据客户端的 `Session-Id`、`Thread-Id` 或 `X-Client-Request-Id` 合并卡片。卡片直接显示请求中的 `model`：未命中 rewrite 时显示原值（如 `gpt-5.6-luna`），命中 rewrite 时显示 `原值 => 改写值`（如 `deepseek-v4-flash => gpt-5.6-luna`），其中改写值即实际转发的值。卡片可展开查看状态、耗时、传输量、客户端 request header 与请求时间线；`Authorization`、cookie、API key 等敏感 header 会脱敏。streaming 期间卡片在页面里做增量更新（只就地更新摘要、概览和事件区域），不会整块重绘导致频闪。Session journal 由进程内结构化会话状态驱动，与日志流相互独立。
对于 JSON、SSE 和其他文本内容，Session journal 会截获请求体及实际转发给客户端的响应。正文不会塞入 Session SSE 事件：请求体与响应都写入进程专用的临时文件，卡片提供 "Intercepted request / response" 按钮，点击后在 modal 中按需加载（响应默认显示最新 64 KiB 预览），也可以在 modal 里打开完整原文（`?full=1`，新标签页）。临时文件会在 gateway 退出时删除。
服务端日志使用 `log/slog` 输出为每行一个 JSON 对象：`msg` 是语义化消息（如 `server listening`、`route matched`、`upstream attempt`、`upstream response`），其余信息全部在结构化字段中，并按级别区分 `INFO` / `WARN` / `ERROR`；实时日志通过 `/logs` 的 SSE 推送，保留最近 100 条。

### Stats（数据统计与可视化）

管理页面的 **Stats** 标签页（`/stats` 片段 + `/stats/stream` SSE 实时推送）基于**完整的请求历史**做多维聚合：只有进入终态的请求（完成 / 客户端断开 / 超时 / 中断）才会写入统计历史，流式传输中的请求不参与聚合，因此统计在数据流式推送时保持稳定（与 Session journal 的"最近 48 个会话"驱逐策略相互独立，历史不会被截断）。配置了 `--data-dir` 时，**完成的请求会以 JSON 行追加到 `data/stats.jsonl`**（与 `logs.jsonl` 同模式），重启后完整恢复，统计覆盖所有可用数据；首次启动（或 stats 日志缺失）时会从已持久化的 session 文件一次性回填历史，避免升级后从零开始。未配置 data dir 时统计仅存内存。

支持**时间窗口筛选**：面板顶部提供 `1 小时 / 24 小时 / 7 天 / 30 天 / 全部` 按钮，通过 `?window=` 参数切换，SSE 实时流会随所选窗口同步刷新。各维度内容：

- **概览 KPI**：请求总数、会话数、错误率（4xx/5xx 或客户端断开 / 超时 / 中断）、平均（`x̅`）/ P95 / 最大耗时、上行与下行流量。
- **请求时间分布**：由 [TradingView Lightweight Charts](https://github.com/tradingview/lightweight-charts) 渲染的交互式时间线——绿色柱为请求量（按跨度自动选择聚合粒度：1 分钟 / 5 分钟 / 15 分钟 / 小时 / 6 小时 / 天），红色折线为错误量，琥珀 / 品红折线为每个时间桶的 P50 / P95 延迟（右侧毫秒轴）；支持拖动缩放、十字光标悬停查看每个时间桶的请求、错误与延迟。十字光标的时间标签与悬停气泡均按操作者本地时区显示 `YYYY-MM-DD HH:MM:SS`；时间轴刻度随可见跨度自适应（跨天内显示 `时:分`，跨多天显示 `月/日`）。
- **Activity Heatmap**：小时 × 星期（本地时区）的请求活跃度气泡图，气泡大小 ∝ √请求数，颜色按占比从浅到深插值，悬停显示 `星期 小时:00 - N requests`。
- **HTTP 状态**：2xx / 3xx / 4xx / 5xx 的 doughnut 占比图 + 图例（数量与百分比）。
- **会话状态**：完成、客户端断开、超时、中断。
- **Upstream / AppSelector / 模型 / 请求方法**：各维度的 Top 8 排行（其余归入"其他"），配占比条；另附 **Upstream 汇总表**（请求数 / 错误率 / 上行 / 下行 / 平均耗时，按请求数排序）。
- **热门路径**：按方法 + 路径聚合的 Top 8 请求路径。
- **每日明细**：按本地日期聚合的请求 / 错误 / 上行 / 下行 / 平均耗时表（最近 30 个活跃日期）。

图表为客户端渲染：时间分布用 lightweight-charts，热力图与状态圆环用 Chart.js（均走 CDN，与 htmx / lucide 一致），颜色随页面明暗主题自动切换；图表 canvas 位于稳定容器中，SSE 增量更新只更新数据、不重建图表，避免流式刷新时的闪烁。

Stats 与 Session journal 同源，随会话实时更新；`/stats` 和 `/stats/stream` 与其他管理路径一样受 Basic Auth 保护。

```bash
curl http://localhost:8080/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"example","messages":[]}'
```
