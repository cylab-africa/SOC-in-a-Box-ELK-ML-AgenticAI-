function onMessage(event) {
  return { "text": "" };
}

function onCardClick(event) {
  var action = event.action || {};
  var params = {};
  (action.parameters || []).forEach(function(p) { params[p.key] = p.value; });

  var alertId = params.alert_id || "";
  var feedbackType = params.feedback_type || "";

  if (!alertId || !feedbackType) {
    return { "text": "Missing parameters." };
  }

  var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  sheet.appendRow([
    new Date().toISOString(),
    alertId,
    feedbackType,
    (event.user || {}).displayName || "unknown",
    (event.user || {}).email || "unknown",
    "pending"
  ]);

  return {
    "actionResponse": { "type": "NEW_MESSAGE" },
    "text": "Feedback recorded: " + feedbackType + " for alert " + alertId + ". The system will process this shortly."
  };
}

function onAddToSpace(event) {
  return { "text": "SIEM Maintenance Bot is ready to receive feedback." };
}

function onRemoveFromSpace(event) {}
