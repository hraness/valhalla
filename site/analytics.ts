import { initHranessCookieConsent } from "@hraness/site-footer/consent";
import {
  capturePostHogCtaClicked, capturePostHogEvent, capturePostHogOutboundLinkOpened,
  capturePostHogInstallCommandCopied, capturePostHogPageNotFound, installPostHogExceptionCapture, observePostHogBrowser,
} from "@hraness/posthog/client";
import { analyticsSite, analyticsCtaForUrl } from "./analytics-site";

initHranessCookieConsent();

observePostHogBrowser({
  site: analyticsSite,
  apiKey: "phc_xqEpQgmKxZDYda3DvForfnKDuVL6urqD2YTtqDPmUL4u",
  evidence: {
    hostname: window.location.hostname, href: window.location.href,
    referrer: document.referrer, production: true,
  },
}, () => {
  const stopErrors = installPostHogExceptionCapture(analyticsSite);
  if (document.querySelector("[data-analytics-not-found]")) capturePostHogPageNotFound(analyticsSite);
  const click = (event: MouseEvent) => {
    if (!(event.target instanceof Element)) return;
    const anchor = event.target.closest("a");
    if (!(anchor instanceof HTMLAnchorElement)) return;
    const url = new URL(anchor.href);
    if (url.protocol !== "https:" && url.protocol !== "http:") return;
    const placement = anchor.closest("header") ? "nav" : anchor.closest("footer") ? "footer" : "inline";
    if (anchor.hasAttribute("download") || url.pathname.includes("/releases/download/")) {
      capturePostHogEvent(analyticsSite, "download started", { platform: "web", artifact: "release", placement });
    }
    if (anchor.matches(".header-cta, .primary-action, [data-analytics-cta]")) {
      capturePostHogCtaClicked(analyticsSite, { cta: analyticsCtaForUrl(url), placement, targetHost: url.hostname });
    }
    if (url.hostname.replace(/^www\./, "") !== analyticsSite.canonicalDomain.replace(/^www\./, "")) {
      capturePostHogOutboundLinkOpened(analyticsSite, { targetHost: url.hostname, placement });
    }
  };
  const copied = (event: Event) => {
    const method = event instanceof CustomEvent && ["brew", "curl", "other"].includes(event.detail) ? event.detail : "curl";
    capturePostHogInstallCommandCopied(analyticsSite, { installMethod: method, placement: "inline" });
  };
  document.addEventListener("analytics-install-copied", copied);
  document.addEventListener("click", click);
  return () => { document.removeEventListener("analytics-install-copied", copied); stopErrors(); document.removeEventListener("click", click); };
});
