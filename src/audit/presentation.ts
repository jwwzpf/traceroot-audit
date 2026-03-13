export function actionLabel(action?: string): string {
  if (!action) {
    return "未知动作";
  }

  switch (action) {
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
    default:
      return action.replace(/^run-/, "运行 ").replace(/-/g, " ");
  }
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
