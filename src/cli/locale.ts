export type CliLanguage = "en" | "zh";

let currentCliLanguage: CliLanguage = "en";

function normalizeLanguage(value?: string | null): CliLanguage {
  if (!value) {
    return "en";
  }

  const normalized = value.trim().toLowerCase();
  if (
    normalized === "zh" ||
    normalized === "zh-cn" ||
    normalized === "zh_cn" ||
    normalized === "cn" ||
    normalized === "chinese"
  ) {
    return "zh";
  }

  return "en";
}

export function detectCliLanguageFromArgv(argv: string[]): CliLanguage {
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value) {
      continue;
    }

    if (value === "--lang") {
      return normalizeLanguage(argv[index + 1]);
    }

    if (value.startsWith("--lang=")) {
      return normalizeLanguage(value.slice("--lang=".length));
    }
  }

  return normalizeLanguage(
    process.env.TRACEROOT_LANG ?? process.env.TRACEROOT_LANGUAGE ?? null
  );
}

export function setCliLanguage(language: CliLanguage): void {
  currentCliLanguage = language;
}

export function getCliLanguage(): CliLanguage {
  return currentCliLanguage;
}

const exactReplacements: Array<[RegExp, string]> = [
  [/请输入编号（直接回车采用 TraceRoot 的推荐：([^)]+)）：/g, "Enter a number (press Enter to use TraceRoot's recommendation: $1):"],
  [/请输入编号：/g, "Enter a number:"],
  [
    /请输入一个或多个编号（用逗号分隔，直接回车采用 TraceRoot 的推荐：([^)]+)）：/g,
    "Enter one or more numbers separated by commas (press Enter to use TraceRoot's recommendation: $1):"
  ],
  [/请输入一个或多个编号（用逗号分隔）：/g, "Enter one or more numbers separated by commas:"],
  [/请输入有效的编号。/g, "Please enter a valid number."],
  [/请至少选一个有效的编号。/g, "Please select at least one valid number."],
  [/请回答 yes 或 no。/g, "Please answer yes or no."],
  [/请先输入一个值。/g, "Please enter a value first."],
  [/ \[推荐\]/g, " [Recommended]"],
  [/🖥️ 这次 TraceRoot 会直接在这台机器上陪跑你常见的 agent \/ runtime 入口。/g, "🖥️ This time, TraceRoot will watch over the common agent/runtime entry points on this machine."],
  [/🖥️ TraceRoot 现在会在这台机器上继续陪跑你常见的 agent \/ runtime 入口。/g, "🖥️ TraceRoot will keep watching over the common agent/runtime entry points on this machine."],
  [/📌 当前已经看到 (\d+) 个可能真的会驱动 AI 动作的入口。/g, "📌 TraceRoot can already see $1 entries here that may genuinely drive AI actions."],
  [/📌 当前已经看到 (\d+) 个可能真的会驱动 AI 动作的入口/g, "📌 TraceRoot can already see $1 entries here that may genuinely drive AI actions"],
  [/🎯 现在最值得先盯住的是：(.+)/g, "🎯 Start by keeping an eye on: $1"],
  [/🔔 提醒方式：只保留本地审计时间线，不额外打扰你/g, "🔔 Reminder mode: keep a local audit timeline only, with no extra interruptions"],
  [/📚 想回看今天发生了什么，可以直接用：traceroot-audit logs --today/g, "📚 To review what happened today, run: traceroot-audit logs --today"],
  [/⏱️ 检查间隔：每 (\d+)s/g, "⏱️ Check interval: every $1s"],
  [/🪶 为了不打扰这台机器，TraceRoot 会一直盯住已接上的动作入口；整机入口变化会在后台轻量复查。/g, "🪶 To stay quiet on this machine, TraceRoot will keep watching the action feeds it has already connected to, while machine-wide entry changes are rechecked lightly in the background."],
  [/👂 TraceRoot 现在已经接上：OpenClaw 运行位点（([^）]+)）。/g, "👂 TraceRoot is now connected to: OpenClaw runtime location ($1)."],
  [/👂 TraceRoot 现在已经接上：MCP 配置位点（([^）]+)）。/g, "👂 TraceRoot is now connected to: MCP config location ($1)."],
  [/👂 TraceRoot 现在已经接上：运行位点（([^）]+)）。/g, "👂 TraceRoot is now connected to: runtime location ($1)."],
  [/👂 TraceRoot 现在已经接上：(.+?)。/g, "👂 TraceRoot is now connected to: $1."],
  [/（OpenClaw 运行态）/g, " (OpenClaw runtime)"],
  [/（本地 agent 运行态）/g, " (local agent runtime)"],
  [/🧾 这次先只保留本地审计时间线；之后想补外部提醒也可以随时重开。/g, "🧾 This run will keep a local audit timeline only. You can always turn external reminders back on later."],
  [/💓 TraceRoot 会继续盯着：/g, "💓 TraceRoot will keep watching:"],
  [/- 这台机器上新冒出来的 agent \/ runtime 入口/g, "- new agent/runtime entries that appear on this machine"],
  [/- 原本普通的入口，突然变成更值得优先关注的入口/g, "- entries that used to look ordinary but now deserve higher attention"],
  [/- 运行时自己吐出来的高风险动作事件/g, "- high-risk action events emitted directly by the runtime"],
  [/- runtime自己吐出来的高风险动作事件/g, "- high-risk action events emitted directly by the runtime"],
  [/- runtime自己吐出来的high-risk action事件/g, "- high-risk action events emitted directly by the runtime"],
  [/- emitted directly by the runtimehigh-risk action事件/g, "- high-risk action events emitted directly by the runtime"],
  [/- 这些入口有没有突然消失或换位置/g, "- whether these entries suddenly disappear or move"],
  [/🚀 如果你想先看最值得注意的几个入口：/g, "🚀 If you want to review the most important entries first:"],
  [/- (.+) → 直接让 TraceRoot Doctor 带你检查并守住这个本地 agent 运行态/g, "- $1 → let TraceRoot Doctor inspect and guard this local agent runtime directly"],
  [/📚 今天稍早已经出现过 (\d+) 个值得留意的动作，TraceRoot 已经先帮你补进时间线。/g, "📚 Earlier today, $1 actions worth your attention already appeared. TraceRoot has pulled them into the timeline for you."],
  [/目前补回来的重点包括：(.+)。/g, "The most important recovered actions so far are: $1."],
  [/👀 今天目前最值得你马上看一眼的是：「(.+)」。/g, '👀 The one worth checking right now is: "$1".'],
  [/想立刻看完整轨迹，可以直接用：traceroot-audit logs --today/g, "To review the full timeline right away, run: traceroot-audit logs --today"],
  [/🎬 动作审计覆盖：/g, "🎬 Action-audit coverage:"],
  [/- 这次先靠 (\d+) 个runtime事件入口陪跑整机上的 agent。/g, "- This run is relying on $1 runtime event feed(s) to watch over agents across the machine."],
  [/- 这次先靠 (\d+) 个运行时事件入口陪跑整机上的 agent。/g, "- This run is relying on $1 runtime event feed(s) to watch over agents across the machine."],
  [/- 这次先靠 (\d+) 个runtime事件入口watch over整机上的 agent。/g, "- This run is relying on $1 runtime event feed(s) to watch over agents across the machine."],
  [/- 只要这些入口里开始吐出高风险动作，TraceRoot 就会立刻提醒并留下审计轨迹。/g, "- As soon as these entries start emitting high-risk actions, TraceRoot will alert you and record an audit trail."],
  [/TraceRoot 实时提醒/g, "TraceRoot live alert"],
  [/- (.+) 刚刚触发了一个高风险动作：(.+)/g, "- $1 just triggered a high-risk action: $2"],
  [/- 为什么现在值得你看一眼：(.+)/g, "- Why it matters right now: $1"],
  [/这类动作会真正把内容发到外部世界里，通常值得你马上看一眼。/g, "this kind of action reaches the outside world and is usually worth checking right away."],
  [/- 这一步看起来涉及：(.+)/g, "- This step appears to involve: $1"],
  [/- TraceRoot 是从这个runtime日志里听到的：(.+)/g, "- TraceRoot heard this from the runtime log: $1"],
  [/- TraceRoot 是从这个 runtime 日志里听到的：(.+)/g, "- TraceRoot heard this from the runtime log: $1"],
  [/- Recommendation: 先确认这封邮件是不是真的该发出去。/g, "- Recommendation: Confirm that this email really should be sent before letting it go out."],
  [/- 想查看完整来龙去脉，可以运行：traceroot-audit logs/g, "- To review the full story, run: traceroot-audit logs"],
  [/💓 ([0-9:T .-]+Z) 这轮没有新的整机入口变化，也没有新的高风险动作提醒。TraceRoot 还在安静地陪跑。/g, "💓 $1 No new machine-wide entry changes or new high-risk alerts in this cycle. TraceRoot is still watching quietly."],
  [/💓 ([0-9:T .-]+Z) 这轮没有新的整机入口变化，也没有新的high-risk action提醒。TraceRoot 还在安静地watch over。/g, "💓 $1 No new machine-wide entry changes or new high-risk alerts in this cycle. TraceRoot is still watching quietly."],
  [/🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？/g, "🔔 When TraceRoot spots a high-risk action, should it send you a quick reminder?"],
  [/💡 如果你想让高风险动作一出现就顺手提醒你，直接回车就可以先用 TraceRoot 推荐的那个入口。\n/g, "💡 If you want a reminder as soon as a high-risk action appears, just press Enter to use TraceRoot's recommendation.\n"],
  [/💡 如果你现在还没接好聊天提醒入口也没关系，TraceRoot 会先继续保留本地审计时间线，等你以后想加提醒时再接上就行。\n/g, "💡 It's okay if you do not have a chat reminder route connected yet. TraceRoot can keep a local audit timeline for now and you can add reminders later.\n"],
  [/💡 TraceRoot 暂时还没认出你已经接好的聊天入口，所以这次会先只保留本地审计时间线。\n/g, "💡 TraceRoot could not recognize a connected chat route yet, so this run will keep a local audit timeline only.\n"],
  [/💡 你想用哪个已接好的聊天入口？/g, "💡 Which connected chat route do you want to use?"],
  [/✨ 这次你想让这个 AI 主要帮你做什么？可以选一个或多个工作流：/g, "✨ What do you want this AI to mainly help with this time? You can choose one or more workflows:"],
  [/🛑 外发或副作用动作，TraceRoot 默认该怎么帮你守住？/g, "🛑 How should TraceRoot guard outbound or side-effecting actions by default?"],
  [/📁 这套工作流最多该碰到多大的本地写文件范围？/g, "📁 How much local file write access should this workflow be allowed to have?"],
  [/🌐 这个运行态要不要允许其他设备连进来？/g, "🌐 Should this runtime be reachable from other devices?"],
  [/🛑 每次外发动作都确认/g, "🛑 Confirm every outbound action"],
  [/最稳妥，适合邮件、下单、发帖等场景/g, "Safest choice. Good for email, orders, and public posts."],
  [/⚠️ 仅高风险动作确认/g, "⚠️ Confirm high-risk actions only"],
  [/低风险自动执行，高风险动作要求人工确认/g, "Let low-risk actions run automatically, but require approval for high-risk ones."],
  [/🤖 允许自主外发/g, "🤖 Allow autonomous outbound actions"],
  [/风险最高，只适合你明确接受自动执行的场景/g, "Highest risk. Use only if you explicitly accept autonomous execution."],
  [/🚫 不允许写本地文件/g, "🚫 Do not allow local file writes"],
  [/只读更安全/g, "Read-only is safer."],
  [/📁 仅允许写工作目录/g, "📁 Allow writes to the working directory only"],
  [/推荐默认选项/g, "Recommended default"],
  [/🧨 允许更广泛写文件/g, "🧨 Allow broader file writes"],
  [/只有在确实需要时再选/g, "Choose this only when you truly need it."],
  [/🏠 仅本机访问/g, "🏠 Localhost only"],
  [/推荐默认选项，避免局域网或公网可达/g, "Recommended default. Avoid LAN or public exposure."],
  [/🌐 允许局域网访问/g, "🌐 Allow LAN access"],
  [/只在你明确需要跨设备访问时使用/g, "Use this only when you explicitly need access from other devices."],
  [/📨 TraceRoot 应该把提醒发到哪里？（([^）]+)）/g, "📨 Where should TraceRoot send reminders? ($1)"],
  [/💡 要把提醒发到 WhatsApp，TraceRoot 还需要知道你已经在 OpenClaw 里接好的那个号码或聊天目标。/g, "💡 To send reminders through WhatsApp, TraceRoot still needs the number or chat target you already connected in OpenClaw."],
  [/例如：\+4917612345678。如果你现在拿不准，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "For example: +4917612345678. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Telegram，TraceRoot 还需要知道你已经在 OpenClaw 里接好的聊天目标。/g, "💡 To send reminders through Telegram, TraceRoot still needs the chat target you already connected in OpenClaw."],
  [/例如：@ops-room 或 chat id。如果你现在拿不准，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "For example: @ops-room or a chat id. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 (.+?)，TraceRoot 还需要知道你已经接好的频道、房间或聊天目标。/g, "💡 To send reminders through $1, TraceRoot still needs the connected channel, room, or chat target."],
  [/例如：#ops-alerts、房间 id 或聊天目标。如果你现在拿不准，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "For example: #ops-alerts, a room id, or another chat target. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 (.+?)，TraceRoot 还需要知道应该发到哪个聊天目标。/g, "💡 To send reminders through $1, TraceRoot still needs to know which chat target to use."],
  [/如果你现在拿不准，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/🧾 这次先只保留本地审计时间线；等你确认好提醒目标以后，再把聊天提醒接上就可以。/g, "🧾 This run will keep a local audit timeline only. Once you know the reminder target, you can connect chat reminders later."],
  [/✨ TraceRoot 已经在这个运行态里看到了这些可用聊天入口：(.+)。\n/g, "✨ TraceRoot can already see these available chat routes in this runtime: $1.\n"],
  [/💡 如果你还没把聊天入口接进 OpenClaw 也没关系，这次先只保留本地审计时间线也可以。\n/g, "💡 It is okay if you have not connected a chat route in OpenClaw yet. This run can keep a local audit timeline only.\n"],
  [/💡 TraceRoot 这次会直接把高风险提醒顺手发到 ([^（]+)（([^）]+)）。如果你之后想改提醒方式，再重新运行 doctor 就可以。\n/g, "💡 This run will send high-risk reminders straight to $1($2). If you want to change that later, just run doctor again.\n"],
  [/TraceRoot 在 (.+) 里看到了这个聊天入口/g, "TraceRoot found this chat route in $1"],
  [/前提是 OpenClaw 已经接好了这个入口/g, "This assumes OpenClaw has already connected this route."],
  [/💡 要把提醒发到 WhatsApp，TraceRoot 还需要知道你已经在 OpenClaw 里接好的那个号码或聊天目标。/g, "💡 To send reminders through WhatsApp, TraceRoot still needs the number or chat target you already connected in OpenClaw."],
  [/1\. 先在 OpenClaw 里跑 `openclaw channels login --channel whatsapp`\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪个号码，现在就填，例如：\+4917612345678\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Run `openclaw channels login --channel whatsapp` in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know which number should receive reminders, enter it now. Example: +4917612345678\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Telegram，TraceRoot 还需要知道你已经在 OpenClaw 里接好的聊天目标。/g, "💡 To send reminders through Telegram, TraceRoot still needs the chat target you already connected in OpenClaw."],
  [/1\. 先在 Telegram 里用 @BotFather 创建机器人并拿到 token\n2\. 把 token 配进 OpenClaw（例如 `channels\.telegram\.botToken`）\n3\. 再启动或重启 `openclaw gateway`\n4\. 如果你已经知道提醒要发到哪里，现在就填，例如：@ops-room 或 chat id\n5\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Create a Telegram bot with @BotFather and get the token.\n2. Put that token into OpenClaw (for example `channels.telegram.botToken`).\n3. Start or restart `openclaw gateway`.\n4. If you already know where reminders should go, enter it now. Example: @ops-room or a chat id.\n5. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Discord，TraceRoot 还需要知道你已经在 OpenClaw 里接好的频道或用户目标。/g, "💡 To send reminders through Discord, TraceRoot still needs the channel or user target you already connected in OpenClaw."],
  [/1\. 先把 Discord 机器人接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：channel:123456789 或 user:123456789\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect your Discord bot in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: channel:123456789 or user:123456789.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Slack，TraceRoot 还需要知道你已经在 OpenClaw 里接好的频道或用户目标。/g, "💡 To send reminders through Slack, TraceRoot still needs the channel or user target you already connected in OpenClaw."],
  [/1\. 先把 Slack 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：channel:C123456 或 user:U123456\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect Slack in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: channel:C123456 or user:U123456.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Signal，TraceRoot 还需要知道你已经在 OpenClaw 里接好的号码或群组目标。/g, "💡 To send reminders through Signal, TraceRoot still needs the number or group target you already connected in OpenClaw."],
  [/1\. 先把 Signal 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：\+4917612345678 或 group:<id>\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect Signal in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: +4917612345678 or group:<id>.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Google Chat，TraceRoot 还需要知道你已经在 OpenClaw 里接好的 space 或用户目标。/g, "💡 To send reminders through Google Chat, TraceRoot still needs the space or user target you already connected in OpenClaw."],
  [/1\. 先把 Google Chat 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：spaces\/<spaceId>\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect Google Chat in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: spaces/<spaceId>.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Mattermost，TraceRoot 还需要知道你已经在 OpenClaw 里接好的频道或用户目标。/g, "💡 To send reminders through Mattermost, TraceRoot still needs the channel or user target you already connected in OpenClaw."],
  [/1\. 先把 Mattermost 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：@ops-room 或 channel:<id>\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect Mattermost in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: @ops-room or channel:<id>.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 iMessage，TraceRoot 还需要知道你已经在 OpenClaw 里接好的聊天目标。/g, "💡 To send reminders through iMessage, TraceRoot still needs the chat target you already connected in OpenClaw."],
  [/1\. 先把 iMessage 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：chat_id:<id> 或一个联系人号码\/邮箱\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect iMessage in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: chat_id:<id> or a contact phone number/email.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/💡 要把提醒发到 Microsoft Teams，TraceRoot 还需要知道你已经在 OpenClaw 里接好的会话目标。/g, "💡 To send reminders through Microsoft Teams, TraceRoot still needs the conversation target you already connected in OpenClaw."],
  [/1\. 先把 Microsoft Teams 接进 OpenClaw\n2\. 再启动或重启 `openclaw gateway`\n3\. 如果你已经知道提醒要发到哪里，现在就填，例如：conversation:<id>\n4\. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。/g, "1. Connect Microsoft Teams in OpenClaw.\n2. Start or restart `openclaw gateway`.\n3. If you already know where reminders should go, enter it now. Example: conversation:<id>.\n4. If you are not sure yet, just press Enter and TraceRoot will keep a local audit timeline for now."],
  [/🧾 这次先只保留本地审计时间线；等你确认好提醒目标以后，再把聊天提醒接上就可以。\n/g, "🧾 This run will keep a local audit timeline only. Once you know the reminder target, you can connect chat reminders later.\n"],
  [/📧 邮件整理与回复/g, "📧 Email triage and reply"],
  [/社交媒体发帖 \/ 运营/g, "Social posting / operations"],
  [/购物 \/ 下单自动化/g, "Shopping / order automation"],
  [/PR 审查 \/ 代码反馈/g, "PR review / code feedback"],
  [/客服 \/ 聊天支持 \/ 消息代发/g, "Support / chat ops / outbound messaging"],
  [/市场监控 \/ 图表分析/g, "Market monitoring / chart analysis"],
  [/读取邮件、起草回复、在确认后发送/g, "Read email, draft replies, and send after confirmation"],
  [/发 X\/Twitter 更新，管理社媒发布流程/g, "Post X/Twitter updates and manage social publishing flows"],
  [/购物车、配送时段、确认订单/g, "Handle carts, delivery windows, and order confirmation"],
  [/代码变更审查、反馈回传到聊天渠道/g, "Review code changes and send feedback back to chat"],
  [/在聊天渠道自动回复或转发消息/g, "Auto-reply or relay messages in chat channels"],
  [/查看图表、抓截图、做技术分析/g, "Review charts, capture screenshots, and run technical analysis"],
  [/💓 接下来如果这台机器上有 agent 开始做高风险动作，TraceRoot 会尽快提醒你，并把动作记进本地审计时间线。/g, "💓 If an agent on this machine starts a high-risk action, TraceRoot will alert you and record it in the local audit timeline."],
  [/💓 TraceRoot 会继续盯着高风险动作，并把今天值得你注意的事情记进本地审计时间线。/g, "💓 TraceRoot will keep watching high-risk actions and record the things worth your attention today in the local audit timeline."],
  [/🩺 今天的审计结论：/g, "🩺 Today's audit conclusion:"],
  [/今天已经发生过高风险动作，最该先回看的是「([^」]+)」/g, 'A high-risk action already happened today. Start by reviewing "$1".'],
  [/今天出现过高风险动作，但目前看起来都已经收住了/g, "High-risk actions happened today, but they currently look contained."],
  [/今天主要是边界和风险信号有变化，还没看到高风险动作失控/g, "Today mainly shows boundary and risk-signal changes. No high-risk action appears to be out of control yet."],
  [/今天 agent 有动作记录，但目前没有需要立刻打断你的事情/g, "The agent recorded actions today, but nothing currently needs to interrupt you right away."],
  [/今天目前还比较平稳，TraceRoot 正在继续陪跑/g, "Today still looks calm. TraceRoot is continuing to watch alongside the runtime."],
  [/只要有新的高风险动作、边界漂移或风险变化冒出来，TraceRoot 就会把它提到最前面。/g, "As soon as a new high-risk action, boundary drift, or risk change appears, TraceRoot will bring it to the top."],
  [/先记住这一件：/g, "Start with this:"],
  [/🟢 这条时间线里还没有符合条件的审计记录。\n先运行 `traceroot-audit doctor --watch`，TraceRoot 才会开始陪跑并留下本地审计轨迹。\n/g, "🟢 There are no matching audit records in this timeline yet.\nRun `traceroot-audit doctor --watch` first so TraceRoot can start watching alongside the runtime and recording a local audit trail.\n"],
  [/🧾 先只保留本地审计/g, "🧾 Keep local audit only for now"],
  [/🔔 发到其他已接好的聊天入口/g, "🔔 Send to another connected chat route"],
  [/🪝 发到自己的提醒入口/g, "🪝 Send to your own alert endpoint"],
  [/发到已识别的 /g, "Send to detected "],
  [/发到 /g, "Send to "],
  [/适合你已经在 OpenClaw 里接好这个聊天入口的情况/g, "Good if you already have this chat route connected in OpenClaw"],
  [/如果你已经有 webhook 或自动化接收端/g, "If you already have a webhook or automation receiver"],
  [/高风险动作会继续记在本地时间线里，但不额外打扰你/g, "High-risk actions stay in the local timeline without extra interruptions"],
  [/比如 Signal、Mattermost、Google Chat、iMessage、Teams/g, "For example: Signal, Mattermost, Google Chat, iMessage, Teams"],
  [/💓 陪跑状态：/g, "💓 Watch status:"],
  [/🗂 审计日志位置:/g, "🗂 Audit log location:"],
  [/🗂 审计日志：/g, "🗂 Audit log:"],
  [/🖥 正在查看: 整机陪跑时间线/g, "🖥 Viewing: machine-wide watch timeline"],
  [/📅 时间范围: 今天/g, "📅 Date range: today"],
  [/🧲 TraceRoot 这次还顺手从原生运行时日志里补回了 (\d+) 条今天的动作记录。/g, "🧲 TraceRoot also backfilled $1 action record(s) from native runtime logs this time."],
  [/🧾 对你来说更像 (\d+) 件完整的事/g, "🧾 This reads more like $1 complete incident(s) for you"],
  [/📚 本次显示 (\d+) 条审计记录/g, "📚 Showing $1 audit events in this view"],
  [/🎬 动作记录: (\d+) 条/g, "🎬 Action records: $1"],
  [/🧱 边界与漂移: (\d+) 条边界漂移，(\d+) 条整体变化/g, "🧱 Boundary and drift: $1 boundary drift event(s), $2 overall drift event(s)"],
  [/🎬 当前动作审计覆盖：/g, "🎬 Current action-audit coverage:"],
  [/🎬 当前整机动作审计覆盖：/g, "🎬 Current machine-wide action-audit coverage:"],
  [/🩺 今天的审计结论：/g, "🩺 Today's audit conclusion:"],
  [/🧭 今天这条主线可以先这样记：(.+)/g, "🧭 Here is the simplest way to remember today's main thread: $1"],
  [/   TraceRoot 还会继续保留“上次没看完”的提醒，等你真正把这段时间线看完整再替你消掉它。/g, "   TraceRoot will keep this reminder until you have really reviewed the rest of the timeline."],
  [/- 今天已经出现了 (\d+) 条这类记录/g, "- $1 record(s) of this kind already appeared today"],
  [/💓 陪跑状态：/g, "💓 Watch status:"],
  [/当前整机动作审计覆盖/g, "Current machine-wide action-audit coverage"],
  [/主要还是靠原生运行时事件入口继续陪跑/g, "TraceRoot is mainly continuing to watch through native runtime event feeds"],
  [/今天最值得留意的动作/g, "The action worth the most attention today"],
  [/今天这些 agent 最值得你看一眼/g, "The agents worth your attention today"],
  [/今天最值得回头看的位置/g, "The place most worth revisiting today"],
  [/里面最值得先看的是：/g, "Start with this inside it: "],
  [/这个动作刚刚开始，TraceRoot 已经先把它记进审计时间线里。/g, "This action has just started, and TraceRoot has already written it into the audit timeline."],
  [/OpenClaw 运行时 正在尝试：(.+)/g, "OpenClaw runtime is attempting: $1"],
  [/OpenClaw 运行时 已完成：(.+)/g, "OpenClaw runtime completed: $1"],
  [/OpenClaw 运行时 没有完成：(.+)/g, "OpenClaw runtime did not complete: $1"],
  [/TraceRoot 已经开始陪跑这个 agent/g, "TraceRoot has started watching this agent"],
  [/TraceRoot 已经开始在这台机器上陪跑，会继续盯着常见的 OpenClaw \/ runtime \/ skill 入口。/g, "TraceRoot has started watching this machine and will keep an eye on common OpenClaw, runtime, and skill entrypoints."],
  [/机器上的 agent 入口今天有变化/g, "The machine's agent entrypoints changed today"],
  [/Agent 开始尝试：(.+)/g, "Agent started attempting: $1"],
  [/Agent 已完成：(.+)/g, "Agent completed: $1"],
  [/Agent 没有完成：(.+)/g, "Agent did not complete: $1"],
  [/Agent 触发了一个动作：(.+)/g, "Agent triggered an action: $1"],
  [/对外发邮件：出现了 (\d+) 次/g, 'send an outbound email: seen $1 time(s)'],
  [/读取敏感数据：出现了 (\d+) 次/g, 'access sensitive data: seen $1 time(s)'],
  [/访问银行或支付账户：出现了 (\d+) 次/g, 'access bank or payment accounts: seen $1 time(s)'],
  [/今天还没收住的事情/g, "Still not contained today"],
  [/当前最值得注意的事情：/g, "What deserves the most attention right now:"],
  [/当前运行态重新变宽了/g, "The current runtime has widened again"],
  [/当前运行态比你批准的边界更宽/g, "The current runtime is broader than the boundary you approved"],
  [/风险概览/g, "Risk overview"],
  [/今天还没有触发值得单独提醒的 agent 动作/g, "No agent action has triggered a standalone alert yet today"],
  [/TraceRoot 目前主要在盯边界有没有重新变宽，以及新的风险信号有没有冒出来。/g, "TraceRoot is mainly watching whether the boundary widens again and whether new risk signals appear."],
  [/最近发生的事/g, "What happened recently"],
  [/先记住这一件：(.+?) 今天已经完成过「(.+)」。/g, "Start with this: $1 already completed \"$2\" today."],
  [/先记住这一件：(.+?) 今天尝试过「(.+)」，但最后没有完成。/g, "Start with this: $1 attempted \"$2\" today, but it did not complete."],
  [/先记住这一件：(.+?) 今天动过「(.+)」。/g, "Start with this: $1 touched \"$2\" today."],
  [/今天还有 (\d+) 件事没收住，最该先盯的是「(.+)」/g, "There are still $1 thing(s) not contained today. Start with \"$2\"."],
  [/今天已经发生过高风险动作，最该先回看的是「(.+)」/g, "High-risk actions already happened today. Start by reviewing \"$1\"."],
  [/今天出现过高风险动作，但目前看起来都已经收住了/g, "High-risk actions appeared today, but they currently look contained."],
  [/今天主要是边界和风险信号有变化，还没看到高风险动作失控/g, "Today's main changes are boundary and risk-signal shifts; no high-risk action appears out of control yet."],
  [/今天 agent 有动作记录，但目前没有需要立刻打断你的事情/g, "The agent has action records today, but nothing seems urgent enough to interrupt you right now."],
  [/今天目前还比较平稳，TraceRoot 正在继续陪跑/g, "Things look calm so far today, and TraceRoot is still watching."],
  [/今天这类高风险动作已经走完了 (\d+) 次，至少从时间线上看，目前没有卡在半路。/g, "This kind of high-risk action has already completed $1 time(s) today, and nothing appears stuck mid-flight in the timeline."],
  [/这类高风险动作今天已经顺利走完，至少从时间线上看，目前没有卡在半路。/g, "This kind of high-risk action has already completed successfully today, and nothing appears stuck mid-flight in the timeline."],
  [/今天最值得回头确认的一类动作，至少从时间线上看，它目前已经走完了。/g, "This is the action family most worth reviewing today, and it currently appears completed in the timeline."],
  [/TraceRoot 目前主要在盯运行态有没有重新变宽，以及新的风险入口有没有冒出来。/g, "TraceRoot is mainly watching whether the runtime widens again and whether new risky entry points appear."],
  [/TraceRoot 已经把这些动作记进审计时间线里了；如果你想回看来龙去脉，直接往下看今天的记录就行。/g, "TraceRoot has already written these actions into the audit timeline; if you want the full story, keep reading today's records below."],
  [/只要有新的高风险动作、边界漂移或风险变化冒出来，TraceRoot 就会把它提到最前面。/g, "If any new high-risk action, boundary drift, or risk change appears, TraceRoot will move it right to the top."],
  [/🫶 今天暂时没有“还没收住”的高风险事情。/g, "🫶 There are no high-risk issues still left open today."],
  [/✅ 今天已经收住的高风险动作：/g, "✅ High-risk actions already contained today:"],
  [/🔥 今天最值得留意的动作：/g, "🔥 The action worth the most attention today:"],
  [/🧩 今天 agent 真正碰到的关键对象：/g, "🧩 Key objects the agent really touched today:"],
  [/📍 今天最值得回头看的位置：/g, "📍 The place most worth revisiting today:"],
  [/📬 今天最值得留意的触发入口：/g, "📬 The trigger route most worth attention today:"],
  [/🧠 TraceRoot 先帮你继续看上次整机陪跑的时间线。\n\n/g, "🧠 TraceRoot is reopening the machine-wide watch timeline from last time first.\n\n"],
  [/🧠 TraceRoot 先帮你继续看上次陪跑的 target：(.+?)。\n\n/g, "🧠 TraceRoot is reopening the last watched target first: $1.\n\n"],
  [/\n💓 实时查看已开启。TraceRoot 每 (\d+)s 会刷新一次新的审计事件，按 Ctrl\+C 可以停止。\n\n/g, "\n💓 Live view is on. TraceRoot will refresh new audit events every $1s. Press Ctrl+C to stop.\n\n"],
  [/暂时还没在这台机器上看到明显的 OpenClaw \/ runtime \/ skill 入口。/g, "TraceRoot has not spotted an obvious OpenClaw, runtime, or skill entrypoint on this machine yet."],
  [/等你的 runtime 真正跑起来以后，再重新运行 `traceroot-audit doctor --watch` 就可以了。/g, "Once your runtime is actually running, just run `traceroot-audit doctor --watch` again."],
  [/- 最近一次报平安：刚刚（看起来它还在继续陪跑）/g, "- Most recent heartbeat: just now (it still looks like TraceRoot is actively watching)"],
  [/- 最近一次报平安：刚刚 \(看起来它还在继续watch\)/g, "- Most recent heartbeat: just now (it still looks like TraceRoot is actively watching)"],
  [/- 最近一次值得你看一眼的是：(.+)/g, "- The latest thing worth your attention is: $1"],
  [/- 这台机器上暂时还没看到已经自动接好的动作入口。/g, "- TraceRoot has not seen any action entrypoints automatically wired on this machine yet."],
  [/- TraceRoot 这次TraceRoot is mainly continuing to watch through native runtime event feeds。/g, "- TraceRoot is mainly continuing to watch through native runtime event feeds this time."],
  [/- TraceRoot 这次主要还是靠原生运行时事件入口继续陪跑。/g, "- TraceRoot is mainly continuing to watch through native runtime event feeds this time."],
  [/- 另外还在继续听 (\d+) 个runtime事件入口。/g, "- TraceRoot is also still listening to $1 runtime event feed(s)."],
  [/- 另外还在继续听 (\d+) 个运行时事件入口。/g, "- TraceRoot is also still listening to $1 runtime event feed(s)."],
  [/send an outbound email \(mailer\.ts\) 刚刚开始了，但还没看到它收住/g, "send an outbound email (mailer.ts) has just started, and TraceRoot has not seen it settle yet"],
  [/「(.+)」刚刚开始了，但还没看到它收住/g, "\"$1\" has just started, and TraceRoot has not seen it settle yet"],
  [/TraceRoot 已经先把这一步记住了，你可以继续盯一下它后面有没有真的完成。/g, "TraceRoot has already recorded this step, and it is worth checking whether it really completes."],
  [/Start with this:(.+?) 今天动过「(.+)」。/g, "Start with this: $1 touched \"$2\" today."],
  [/今天这条主线可以先这样记：(.+?) 的「(.+)」，涉及：(.+?)，这一步还值得继续盯一下。/g, "Here is the simplest way to remember today's main thread: $1 touched \"$2\", involving $3, and this step is still worth watching."],
  [/🆕 自从你上次回来看这条时间线以后：/g, "🆕 Since you last came back to this timeline:"],
  [/- 又发生了 (\d+) 条值得留意的记录/g, "- $1 more record(s) worth your attention appeared"],
  [/- 最常冒出来的是：(.+)/g, "- The one appearing most often is: $1"],
  [/：出现了 (\d+) 次值得留意的动作（(.+)）/g, ": $1 action(s) worth attention ($2)"],
  [/：被碰了 (\d+) 次 \((.+)\)/g, ": touched $1 time(s) ($2)"],
  [/：被碰了 (\d+) 次（(.+)）/g, ": touched $1 time(s) ($2)"],
  [/：出现了 (\d+) 次值得留意的动作 \((.+)\)/g, ": $1 action(s) worth attention ($2)"],
  [/如果你之后只想回看某一个位置的完整轨迹，可以直接运行：traceroot-audit logs <那个路径>/g, "If you later want the full trail for just one location, run: traceroot-audit logs <that path>"],
  [/如果你之后只想回看某一个location的完整轨迹，可以直接运行：traceroot-audit logs <那个路径>/g, "If you later want the full trail for just one location, run: traceroot-audit logs <that path>"],
  [/(.+?) 刚刚开始了，但还没看到它收住/g, "$1 has just started, and TraceRoot has not seen it settle yet"],
  [/这台机器上目前已经看到 (\d+) 个可能真的会驱动 AI 动作的入口。现在最值得先看：(.+?)。/g, "TraceRoot can currently see $1 entrypoint(s) on this machine that may genuinely drive AI actions. Start with: $2."],
  [/🎯 这一步看起来涉及：/g, "🎯 This step appears to involve: "],
  [/📍 发生在: /g, "📍 Happened at: "],
  [/🧷 来源日志: /g, "🧷 Source log: "],
  [/🔧 TraceRoot 建议先做: /g, "🔧 TraceRoot suggests starting with: "],
  [/今天这条主线可以先这样记：/g, "Here is the simplest way to remember today's main thread: "],
  [/🔥 The action worth the most attention today：/g, "🔥 The action worth the most attention today:"],
  [/🚨 Still not contained today：/g, "🚨 Still not contained today:"],
  [/🧭 The agents worth your attention today：/g, "🧭 The agents worth your attention today:"],
  [/📍 The place most worth revisiting today：/g, "📍 The place most worth revisiting today:"],
  [/📘 What happened recently：/g, "📘 What happened recently:"],
  [/\] 机器上的 agent 入口有变化/g, "] The machine's agent entrypoints changed today"],
  [/说明：/g, "Note: "],
  [/Trigger(ed)? from: /g, "Triggered from: "]
];

const fragmentReplacements: Array<[RegExp, string]> = [
  [/高风险动作/g, "high-risk action"],
  [/本地审计时间线/g, "local audit timeline"],
  [/本地审计轨迹/g, "local audit trail"],
  [/审计时间线/g, "audit timeline"],
  [/审计日志/g, "audit log"],
  [/陪跑/g, "watch"],
  [/运行时/g, "runtime"],
  [/聊天入口/g, "chat route"],
  [/已识别的/g, "detected"],
  [/推荐默认选项/g, "recommended default"],
  [/只保留本地审计/g, "keep local audit only"],
  [/高风险/g, "high-risk"],
  [/风险/g, "risk"],
  [/今天已经收住的高风险动作/g, "High-risk actions already contained today"],
  [/今天最值得留意的动作/g, "the action worth the most attention today"],
  [/今天最值得回头看的位置/g, "the place most worth revisiting today"],
  [/对外发邮件/g, "send an outbound email"],
  [/对外发消息/g, "send an outbound message"],
  [/公开发帖/g, "publish a public post"],
  [/删改本地文件/g, "delete or modify local files"],
  [/删除本地文件/g, "delete local files"],
  [/修改本地文件/g, "modify local files"],
  [/付款或下单/g, "make a payment or place an order"],
  [/访问银行或支付账户/g, "access bank or payment accounts"],
  [/读取敏感数据/g, "access sensitive data"],
  [/读取敏感 secret/g, "access sensitive secrets"],
  [/收到新任务指令/g, "receive a new task instruction"],
  [/收到停止指令/g, "receive a stop instruction"],
  [/收到恢复运行指令/g, "receive a resume instruction"],
  [/OpenClaw 运行时/g, "OpenClaw runtime"],
  [/Claw 运行时/g, "Claw runtime"],
  [/Lobster 运行时/g, "Lobster runtime"],
  [/MCP 服务/g, "MCP service"],
  [/机器上的 agent 入口有变化/g, "The machine's agent entrypoints changed"],
  [/runtime自己吐出来的/g, "emitted directly by the runtime"],
  [/来自 /g, "from "],
  [/发给 /g, "to "],
  [/TraceRoot 是从这个runtime日志里听到的：/g, "TraceRoot heard this from the runtime log: "],
  [/位置：/g, "Location: "],
  [/状态：/g, "Status: "],
  [/建议：/g, "Recommendation: "],
  [/触发来源：/g, "Triggered from: "],
  [/发生在: /g, "Happened at: "],
  [/来源日志: /g, "Source log: "],
  [/最近一次报平安/g, "Most recent heartbeat"],
  [/最近一次值得你看一眼的是/g, "The latest thing worth your attention is"],
  [/What happened recently：/g, "What happened recently:"],
  [/又发生了/g, "appeared again"],
  [/值得留意的记录/g, "record(s) worth your attention"],
  [/最常冒出来的是/g, "The one appearing most often is"],
  [/这条主线可以先这样记/g, "Here is the simplest way to remember today's main thread"],
  [/被碰了/g, "touched"],
  [/出现了/g, "appeared"],
  [/ 次/g, " time(s)"],
  [/刚刚开始了，但还没看到它收住/g, "has just started, and TraceRoot has not seen it settle yet"],
  [/值得留意的动作/g, "action(s) worth attention"],
  [/机器上的 agent 入口今天有变化/g, "The machine's agent entrypoints changed today"],
  [/TraceRoot 已经开始watch这个 agent/g, "TraceRoot has started watching this agent"],
  [/TraceRoot 已经开始在这台机器上watch，会继续盯着常见的 OpenClaw \/ runtime \/ skill 入口。/g, "TraceRoot has started watching this machine and will keep an eye on common OpenClaw, runtime, and skill entrypoints."],
  [/如果你之后只想回看某一个位置的完整轨迹，可以直接运行：traceroot-audit logs <那个路径>/g, "If you later want the full trail for just one location, run: traceroot-audit logs <that path>"],
  [/次值得留意的动作/g, "action(s) worth attention"],
  [/这台机器上暂时还没看到已经自动接好的动作入口。/g, "TraceRoot has not seen any action entrypoints automatically wired on this machine yet."],
  [/如果你之后只想回看某一个location的完整轨迹，可以直接运行：traceroot-audit logs <那个路径>/g, "If you later want the full trail for just one location, run: traceroot-audit logs <that path>"],
  [/说明：/g, "Note: "],
  [/为什么值得现在看一眼：/g, "Why it matters right now: "],
  [/本地审计时间线也已经同步更新了。/g, "The local audit timeline has been updated too."],
  [/想看今天完整来龙去脉：traceroot-audit logs --today/g, "To review the full story for today: traceroot-audit logs --today"],
  [/先确认这封邮件是不是真的该发出去。/g, "Confirm that this email really should be sent before letting it go out."],
  [/是谁：/g, "Actor: "],
  [/动作：/g, "Action: "],
  [/正在尝试执行/g, "currently attempting"],
  [/已经执行完成/g, "completed successfully"],
  [/这次尝试没有完成/g, "did not complete"],
  [/极高风险/g, "critical risk"],
  [/高风险/g, "high risk"],
  [/有风险/g, "risky"],
  [/普通/g, "normal"],
  [/位置/g, "location"],
  [/位点/g, "location"],
  [/（/g, " ("],
  [/）/g, ")"]
];

function translateChineseOutput(text: string): string {
  let translated = text;

  for (const [pattern, replacement] of exactReplacements) {
    translated = translated.replace(pattern, replacement);
  }

  for (const [pattern, replacement] of fragmentReplacements) {
    translated = translated.replace(pattern, replacement);
  }

  return translated;
}

export function translateCliText(text: string): string {
  if (getCliLanguage() === "zh") {
    return text;
  }

  return translateChineseOutput(text);
}
