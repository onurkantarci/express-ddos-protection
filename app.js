const express = require("express");
const ipfilter = require("express-ipfilter").IpFilter;
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();
app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    dnsPrefetchControl: { allow: false },
    expectCt: {
      enforce: true,
      maxAge: 30,
    },
    frameguard: { action: "deny" },
    hidePoweredBy: true,
    hsts: {
      maxAge: 63072000,
      includeSubDomains: true,
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "no-referrer" },
    xssFilter: true,
  })
);

const ips = ["::1"];

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

app.use((req, res, next) => {
  console.log(`Request IP: ${req.ip}`);
  next();
});

app.use(ipfilter(ips, { mode: "allow" }));
app.use(limiter);

app.get("/test", (req, res) => {
  res.send("test reached");
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`App listening on ${PORT}`);
});
