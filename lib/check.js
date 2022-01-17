const list = require("./list");

/**
  Returns true if a phishing domain was found in `message`.
  The message is first split by whitespace, and each token is then verified
  to see whether or not it contains a phishing domain.
**/
exports.checkMessage = async function checkMessage(message) {
  let domains = await list.listDomains();

  const susDomainsChecker = (arg) =>
    domains.some((domains) => arg.includes(domains));

  const susDomainsArgs = message.toLowerCase().split(/\s+/);

  return susDomainsArgs.some(susDomainsChecker);
};

/**
  Returns the first suspicous link found in `message`.
  The message is first split by whitespace, and each token is then verified
  to see whether or not it contains a phishing domain.
**/
exports.findSuspiciousLink = async function findSuspiciousLink(message) {
  let domains = await list.listDomains();

  const susDomainsChecker = (arg) =>
    domains.some((domains) => arg.includes(domains));

  const susDomainsArgs = message.toLowerCase().split(/\s+/);

  return susDomainsArgs.find(susDomainsChecker);
}
