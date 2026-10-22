var SHEET_ID = "1uOqnq1HYOocLlqcZdJAJrZUWYIbPHuPasKVp0d4tXgM";

function _extractParams(e) {
  var params = {};
  if (e && e.commonEventObject && e.commonEventObject.parameters) {
    var cp = e.commonEventObject.parameters;
    for (var k in cp) params[k] = cp[k];
  }
  if (e && e.action && e.action.parameters) {
    var ap = e.action.parameters;
    for (var i = 0; i < ap.length; i++) params[ap[i].key] = ap[i].value;
  }
  return params;
}

function _appendRow(row) {
  SpreadsheetApp.openById(SHEET_ID).getActiveSheet().appendRow(row);
}

function _chatMessage(text) {
  return {
    hostAppDataAction: {
      chatDataAction: {
        createMessageAction: { message: { text: text } }
      }
    }
  };
}

function feedback_response(e) {
  var p = _extractParams(e);
  var aid = p.alert_id || "unknown";
  var ftype = p.feedback_type || "unknown";
  var user = e.user || (e.commonEventObject && e.commonEventObject.user) || {};
  var msg;
  try {
    _appendRow([new Date().toISOString(), aid, ftype, user.displayName || "", user.email || "", "pending"]);
    msg = "Thanks! Feedback recorded (" + ftype + "). Memory will update shortly.";
  } catch (err) {
    msg = "ERROR: Could not record feedback - " + err.message;
  }
  return _chatMessage(msg);
}

function open_custom_dialog(e) {
  var p = _extractParams(e);
  var aid = p.alert_id || "unknown";
  return {
    actionResponse: {
      type: "DIALOG",
      dialogAction: {
        dialog: {
          body: {
            sections: [{
              header: "Custom instruction for this alert",
              widgets: [
                {
                  textInput: {
                    label: "What should the agent do differently?",
                    type: "MULTIPLE_LINE",
                    name: "custom_text"
                  }
                },
                {
                  buttonList: {
                    buttons: [{
                      text: "Submit",
                      onClick: {
                        action: {
                          function: "submit_custom_instruction",
                          parameters: [{ key: "alert_id", value: aid }]
                        }
                      }
                    }]
                  }
                }
              ]
            }]
          }
        }
      }
    }
  };
}

function submit_custom_instruction(e) {
  var p = _extractParams(e);
  var aid = p.alert_id || "unknown";
  var customText = "";
  try {
    var fi = e.commonEventObject.formInputs.custom_text;
    customText = fi.stringInputs.value[0] || "";
  } catch (err) {
    customText = "";
  }
  var user = e.user || (e.commonEventObject && e.commonEventObject.user) || {};
  try {
    _appendRow([new Date().toISOString(), aid, "custom", user.displayName || "", user.email || "", "pending", customText]);
  } catch (err2) {}
  return {
    actionResponse: {
      type: "DIALOG",
      dialogAction: {
        actionStatus: {
          statusCode: "OK",
          userFacingMessage: "Instruction recorded. The system will apply it shortly."
        }
      }
    }
  };
}

function onMessage(e) { return _chatMessage(""); }
function onAddToSpace(e) { return _chatMessage("SIEM Maintenance Bot is ready to receive feedback."); }
function onRemoveFromSpace(e) {}
