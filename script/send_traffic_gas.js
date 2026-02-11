// Google Apps Script - Sustained intake traffic sender
// Sends 10 requests per batch, triggered every 1 minute for 10 minutes.
//
// Setup:
// 1. Go to https://script.google.com and create a new project
// 2. Paste this script
// 3. Set your API key below
// 4. Run sendContinuous() once to start

var DD_API_KEY = 'YOUR_API_KEY';
var URL = 'https://logs.browser-intake-datad0g.com/api/v2/logs';
var REQUESTS_PER_BATCH = 10;

function sendBatch() {
  var requests = [];
  var now = new Date().toISOString();

  for (var i = 0; i < REQUESTS_PER_BATCH; i++) {
    requests.push({
      'url': URL,
      'method': 'post',
      'headers': {
        'dd-api-key': DD_API_KEY,
        'content-type': 'application/json'
      },
      'payload': JSON.stringify({
        'message': 'req ' + i + ' at ' + now + ' source google-apps-script'
      }),
      'muteHttpExceptions': true
    });
  }

  var responses = UrlFetchApp.fetchAll(requests);

  var codes = responses.map(function(r, i) {
    return 'req ' + i + ': ' + r.getResponseCode();
  });
  Logger.log(now + ' | ' + codes.join(', '));
}

// Runs sendBatch() in a tight loop for ~10 minutes (GAS execution limit is 6 min)
// Each iteration sends 10 parallel requests then waits 1 second
function sendContinuous() {
  var durationMs = 10 * 60 * 1000; // 10 minutes (stay under 6-min limit)
  var start = Date.now();
  var totalSent = 0;

  while (Date.now() - start < durationMs) {
    sendBatch();
    totalSent += REQUESTS_PER_BATCH;
    Utilities.sleep(1000); // 1 second between batches
  }

  Logger.log('Done. Sent ' + totalSent + ' requests in ' + Math.round((Date.now() - start) / 1000) + 's');
}
