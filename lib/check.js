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

  // TODO: handle non-domains
  function susDomainsChecker(arg) {
    let [domain, path] = arg.split("/");
    if (!path) path = "";
    // For the URL `www.example.com`, `domainParts` will contain `["www", "example", "com"]`
    let domainParts = domain.split(".");
    // For the URL `www.example.com`, `subDomains` will contain `["com", "example.com", "www.example.com"]`
    let subDomains = domainParts.map((_, i) => domainParts.slice(i).join("."));

    function matchDomain(domain) {
      let [matchDomain, matchPath] = domain.split("/");
      // Ignore domain with path if its path is different than our URL's path (using startsWith as to ignore GET parameters or #)
      if (matchPath && !path.startsWith(matchPath)) return false;
      // Returns true if matchDomain ∈ subDomains
      return subDomains.includes(matchDomain);
    }

    if (domains.some(matchDomain)) {
      return true;
    } else if (scanSuspiciousDomains) {
      if (suspiciousDomains.some(matchDomain)) {
        return true;
      }
    }
    return false;
  };

  const susDomainsArgs = message.toLowerCase().match(/\b(\w+\.)+\w+\b(\/\S+)?/g) ?? [];

  return susDomainsArgs.find(susDomainsChecker);
};
