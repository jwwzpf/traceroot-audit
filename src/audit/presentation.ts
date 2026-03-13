export function actionLabel(action?: string): string {
  if (!action) {
    return "未知动作";
  }

  const normalized = action.trim().toLowerCase();

  switch (normalized) {
    case "send-email":
      return "对外发邮件";
    case "publish-or-send-message":
      return "对外发帖或发消息";
    case "delete-or-modify-files":
      return "删改本地文件";
    case "purchase-or-payment":
      return "付款或下单";
    case "finance-access":
      return "访问金融或交易数据";
    case "delete-files":
      return "删除本地文件";
    case "modify-files":
      return "修改本地文件";
    case "public-post":
      return "公开发帖";
    case "send-message":
      return "对外发消息";
    case "sensitive-secret-access":
      return "读取敏感 secret";
    case "bank-access":
      return "访问银行或支付账户";
    case "sensitive-data-access":
      return "读取敏感数据";
  }

  if (/(send|draft).*(email|mail)|(email|mail).*(send|draft)/.test(normalized)) {
    return "对外发邮件";
  }

  if (/(publish|post|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "公开发帖";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "对外发消息";
  }

  if (/(delete|remove|rm|unlink|wipe|purge)/.test(normalized)) {
    return "删除本地文件";
  }

  if (/(write|modify|edit|update|rename|move|copy)/.test(normalized) && /(file|files|fs|disk|path|workspace)/.test(normalized)) {
    return "修改本地文件";
  }

  if (/(payment|purchase|checkout|order|stripe|paypal|wallet)/.test(normalized)) {
    return "付款或下单";
  }

  if (/(bank|finance|broker|trade|portfolio|account-balance)/.test(normalized)) {
    return "访问银行或交易数据";
  }

  if (/(secret|token|credential|password|key)/.test(normalized)) {
    return "读取敏感 secret";
  }

  if (/(sensitive|private|customer-data|pii|record|records)/.test(normalized)) {
    return "读取敏感数据";
  }

  return action.replace(/^run-/, "运行 ").replace(/-/g, " ");
}

export function summarizeActionLabels(actions: string[], maxItems = 3): string {
  const labels = [...new Set(actions.map((action) => actionLabel(action)))];

  if (labels.length === 0) {
    return "暂无已接入的高风险动作";
  }

  if (labels.length <= maxItems) {
    return labels.join("、");
  }

  return `${labels.slice(0, maxItems).join("、")} 等 ${labels.length} 类高风险动作`;
}
