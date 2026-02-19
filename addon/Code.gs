/**
 * Phishing Detection Gmail Add-on
 *
 * When the user opens a message, shows a card with "Scan for Phishing".
 * On click, sends the email's raw content to the backend POST /scan and
 * displays label (color-coded), confidence, and reasons. No detection
 * logic runs in the add-on; everything is done by the backend.
 *
 * Backend URL: set in Script Properties as BACKEND_URL (e.g. https://your-api.com or http://127.0.0.1:8000 for local).
 */

var CONFIG = {
  /** Fallback backend base URL if Script Property BACKEND_URL is not set. */
  defaultBackendUrl: 'http://127.0.0.1:8000',
  scanPath: '/scan',
  requestTimeoutSeconds: 60
};

/**
 * Contextual trigger: runs when the user opens a Gmail message with the add-on visible.
 * Builds the initial card with a "Scan for Phishing" button.
 *
 * @param {Object} e - Event object with e.gmail.messageId and e.gmail.accessToken
 * @returns {Card[]} Array of cards to show in the add-on panel
 */
function onGmailMessageOpen(e) {
  if (!e || !e.gmail) {
    return [buildErrorCard('No Gmail context.')];
  }
  var accessToken = e.gmail.accessToken;
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detection'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('Check this email against the phishing detection backend.')
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Scan for Phishing')
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName('runScan')
                .setParameters({ messageId: messageId })
            )
        )
    )
    .build();
  return [card];
}

/**
 * Called when the user clicks "Scan for Phishing". Fetches the current message
 * raw content, POSTs to backend /scan, then returns a card with results.
 * Uses the same message access token from the current context when available.
 *
 * @param {Object} e - Event object; e.parameters.messageId and optionally e.gmail.accessToken
 * @returns {ActionResponse} Response that pushes the result card (or error card)
 */
function runScan(e) {
  var messageId = e && e.parameters && e.parameters.messageId;
  if (!messageId) {
    return buildActionResponse(buildErrorCard('Missing message ID.'));
  }

  if (e.gmail && e.gmail.accessToken) {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  }

  var rawContent;
  try {
    var message = GmailApp.getMessageById(messageId);
    rawContent = message.getRawContent();
  } catch (err) {
    return buildActionResponse(buildErrorCard('Could not read message: ' + err.toString()));
  }

  if (!rawContent || rawContent.length === 0) {
    return buildActionResponse(buildErrorCard('Message has no content.'));
  }

  var backendUrl = getBackendUrl();
  var url = backendUrl + CONFIG.scanPath;
  var payload = JSON.stringify({ raw: rawContent });
  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: payload,
    muteHttpExceptions: true,
    headers: {}
  };

  try {
    var response = UrlFetchApp.fetch(url, options);
    var code = response.getResponseCode();
    var body = response.getContentText();
  } catch (err) {
    return buildActionResponse(
      buildErrorCard('Backend request failed: ' + err.toString() + '. Is the server at ' + backendUrl + ' running?')
    );
  }

  if (code !== 200) {
    var detail = body;
    try {
      var parsed = JSON.parse(body);
      if (parsed.detail) detail = typeof parsed.detail === 'string' ? parsed.detail : JSON.stringify(parsed.detail);
    } catch (ignored) {}
    return buildActionResponse(buildErrorCard('Backend error (' + code + '): ' + detail));
  }

  var result;
  try {
    result = JSON.parse(body);
  } catch (err) {
    return buildActionResponse(buildErrorCard('Invalid JSON from backend.'));
  }

  var resultCard = buildResultCard(result);
  return buildActionResponse(resultCard);
}

/**
 * @returns {string} Backend base URL from Script Property or default
 */
function getBackendUrl() {
  var url = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  if (url && url.length > 0) {
    return url.replace(/\/$/, '');
  }
  return CONFIG.defaultBackendUrl.replace(/\/$/, '');
}

/**
 * Build a card that shows scan result: label (color-coded), confidence, reasons, optional LLM block.
 *
 * @param {Object} result - Backend response: label, confidence, reasons, signals?, metadata?
 * @returns {Card}
 */
function buildResultCard(result) {
  var label = (result.label || 'Safe').toString();
  var confidence = typeof result.confidence === 'number' ? (result.confidence * 100).toFixed(0) + '%' : String(result.confidence);
  var reasons = result.reasons || [];
  var metadata = result.metadata || {};

  var section = CardService.newCardSection();
  var colorHint = labelColorName(label);

  // Label with color hint: Red=Phishing, Orange=Suspicious, Green=Safe
  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Result')
      .setContent(label + ' — ' + colorHint)
  );
  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Confidence')
      .setContent(confidence)
  );

  if (reasons.length > 0) {
    section.addWidget(CardService.newTextParagraph().setText('<b>Reasons</b>'));
    reasons.forEach(function (r) {
      section.addWidget(CardService.newTextParagraph().setText('• ' + escapeHtml(r)));
    });
  }

  // LLM block when backend used LLM (Suspicious case)
  if (metadata.llm_used && (metadata.llm_label !== undefined || metadata.llm_confidence !== undefined)) {
    var llmLabel = metadata.llm_label != null ? String(metadata.llm_label) : '—';
    var llmConf = metadata.llm_confidence != null ? (metadata.llm_confidence * 100).toFixed(0) + '%' : '—';
    section.addWidget(CardService.newTextParagraph().setText('<b>LLM opinion</b>'));
    section.addWidget(
      CardService.newKeyValue()
        .setTopLabel('LLM label')
        .setContent(llmLabel)
    );
    section.addWidget(
      CardService.newKeyValue()
        .setTopLabel('LLM confidence')
        .setContent(llmConf)
    );
    if (metadata.llm_reasons && metadata.llm_reasons.length > 0) {
      metadata.llm_reasons.forEach(function (r) {
        section.addWidget(CardService.newTextParagraph().setText('• ' + escapeHtml(r)));
      });
    }
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Scan result'))
    .addSection(section)
    .build();
}

/**
 * Returns a color name for the label (for reference; Cards have limited inline styling).
 * Red = Phishing, Orange = Suspicious, Green = Safe.
 *
 * @param {string} label - "Safe" | "Suspicious" | "Phishing"
 * @returns {string} Color name
 */
function labelColorName(label) {
  var lower = (label || '').toLowerCase();
  if (lower === 'phishing') return 'Red (high risk)';
  if (lower === 'suspicious') return 'Orange (review)';
  return 'Green (safe)';
}

/**
 * Build a simple error card.
 *
 * @param {string} message
 * @returns {Card}
 */
function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Error'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(escapeHtml(message))
      )
    )
    .build();
}

/**
 * Escape HTML so we can safely show user/backend text in cards.
 *
 * @param {string} s
 * @returns {string}
 */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {Card} card
 * @returns {ActionResponse}
 */
function buildActionResponse(card) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}
