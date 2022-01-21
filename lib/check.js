const list = require("./list");

exports.checkMessage = async function checkMessage(message, scanSuspiciousDomains = false) {
  return !!(await exports.findSuspiciousLink(message, scanSuspiciousDomains));
};

/**
  Returns the first suspicous link found in `message`.
  The message is first split by whitespace, and each token is then verified
  to see whether or not it contains a phishing domain.
**/
exports.findSuspiciousLink = async function findSuspiciousLink(message, scanSuspiciousDomains = false) {
  let domains = await list.listDomains();
  let suspiciousDomains = scanSuspiciousDomains ? await list.listSuspicious() : null;

  function susDomainsChecker(arg) {
    if (domains.some((domain) => arg.includes(domain))) {
      return true;
    } else if (scanSuspiciousDomains) {
      if (suspiciousDomains.some((domain) => arg.includes(domain))) {
        return true;
      }
    }
    return false;
  };

  const susDomainsArgs = message.toLowerCase().split(/\s+/);

  return susDomainsArgs.find(susDomainsChecker);
};

