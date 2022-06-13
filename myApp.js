const express = require('express');
const app = express();

// 1: Install helmet, then require it
let helmet = require('helmet');

// 2: Hide potentially dangerous information - `helmet.hidePoweredBy()`

// Hackers can exploit known vulnerabilities in Express/Node if they see that your site is powered by Express. `X-Powered-By: Express` is sent in every request coming from Express by default.

// The `hidePoweredBy` middleware will remove the `X-Powered-By` header. You can also explicitly set the header to something else, to throw people off. e.g. `helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' })`
app.use(helmet.hidePoweredBy({ setTo: "PHP 4.2.0" }));

// 3: Mitigate the risk of clickjacking - `helmet.frameguard()`

// Your page could be put in a <frame> or an <iframe> without your consent. This can result in clickjacking attacks among other things. Clickjacking is a technique of tricking a user into interacting with a page different from what the user thinks it is. Often this happens using another page put over the framed original, in a transparent layer. The `X-Frames-Options` header set by this middleware restricts who can put your site in a frame. It has three modes: DENY, SAMEORIGIN, and ALLOW-FROM.

// We don't need our app to be framed, so we should use `helmet.frameguard()` passing to it the configuration object `{action: "deny"}`
app.use(helmet.frameguard({
  action: 'deny'
}
));

// 4: Mitigate the Risk of XSS - `helmet.xssFilter()`

// Cross-site scripting (XSS) is a very frequent type of attack where malicious script are injected into vulnerable pages, on the purposes of stealing sensitive data such as session-cookies, or passwords. The basic rule to lower the risk of an XSS attack is simple: "Never trust the user input", so as a developer you should always *sanatize* all the input coming from the outside. This includes data coming from forms, GET query urls, and even from POST bodies. Sanatizing means that you should find and encode the characters that may be dangerous e.g. '<', '>'

// Modern browsers can help mitigate XSS risk by adopting software strategies, which often are configuarable via http headers. The 'X-XSS-Protection' HTTP header is a basic protection. When the browser detects a potential injected script using a heuristic filter, it changes it, making the script non-executable. It still has limited support.
app.use(helmet.xssFilter());

// 5: Avoid inferring the response MIME type - `helmet.noSniff()`

// Browsers can use content or MIME sniffing to override response `Content-Type` headers to guess and process the data using an implicit content type. While this can be convienent in some scenarios, it can also lead to some dangerous attacks.

// This middleware sets `X-Content-Type-Options` header to `nosniff`, instructing the browser to not bypass the provided `Content-Type`.
app.use(helmet.noSniff());

// 6: Prevent IE from opening *untrusted* HTML - `helmet.ieNoOpen()`

// Some web apps will serve untrusted HTML for download. By default, some versions of Internet Explorer will allow you to open those HTML files in the context of your site, which means an untrsuted HTML page could start doing bad things inside your pages.

// This middleware sets the `X-Download-Options` header to `noopen`, to prevent IE users from executing downloads in the *trusted* site's context.
app.use(helmet.ieNoOpen());

// 7: Ask browsers to access your site via HTTPS only - `helmet.hsts()`

// HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking. If your website can be accessed via HTTPS you can ask the user's browsers to avoid using insecure HTTP. Setting the header `Strict-Transport-Security` instructs browsers to use HTTPS for all the future requests ocurring in a specified amount of time. This will work for requests coming in **after** the initial request.

// Configure `helmet.hsts()` to instruct browsers to use HTTPS for the next **90 days**, passing the config object {maxAge: timeInSeconds}. Replit already has **hsts** enabled, to override its settings we need to set the `force` field to `true` in the config object. To not alter the replit security policy, we will intercept and restore the header, after inspecting it for texting.
var ninetyDaysInSeconds = 90*24*60*60;
app.use(helmet.hsts({ 
  maxAge: ninetyDaysInSeconds, 
  force: true }));

// 8: Disable DNS Prefetching - `helmet.dnsPrefetchControl()`

// To improve performance, most browsers prefetch DNS records for the links in a page. In that way the destination ip is already known when the user clicks on a link. This may lead to over-use of the DNS service (if you own a big website with millions of users...), privacy issues (one eavesdropper could infer that you are on a certain page - even if encrypted - from the links you are prefetching), or page statistics alteration (some links may appear visited even if they are not). If you have high security needs you can disable DNS prefetching, at the cost of a performance penalty.
app.use(helmet.dnsPrefetchControl());

// 9: Disable Client-Side Caching - `helmet.noCache()`

// If you are releasing an update for your website, and you want users to download the newer, more performant and safer version, you can (try to) disbale caching on your client's browser, for your website. It can be useful in development too. Caching has performance benefits, and you will lose them, so use this option only when there is a real need.
app.use(helmet.noCache());

// 10: Content Security Policy - `helmet.contentSecurityPolicy()`

// This challenge highlights one promising new defense that can significantly reduce the risk and impact of many types of attacks in modern browsers. By setting an configuring the Content Security Policy you can prevent the injection of anything unintended into your page. This will protect your app from XSS vulnerabilities, undesired tracking, malicious frames, and much more. CSP works by defining a whitelist of content sources which are trusted, for each kind of resource a web page may need to load (scripts, stylesheets, fonts, frames, media, etc.). There are multiple directives avaliable so a website owner can have granular control. Unfortunately, CSP is not supported by older browsers.

// By default, directives are wide open, so it is important to set the `defaultSrc` directive (helmet supports both `defaultSrc` and `default-src` naming styles), as a fallback for most of the other unspecified directives.
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'trusted-cdn.com']
  }
}))

// TIP

// `app.use(helmet())` will automatically include all the middleware we used above except `noCache()` and `contentSecurityPolicy()`, but these can be enabled if necessary. You can also disable or set any other middleware individually, using a config object.

// Example
// app.use(helmet({
//   framework: {            <-- configure
//     action: 'deny'
//   },
//   contentScurityPolicy: {   <-- enable and configure
//     directives :{
//       defaultSrc: ["'self'"],
//       scriptSrc: ["'self'", "trusted-cdn.com"]
//     }
//   },
//   dnsPrefetchControl: false   <-- disable
// }))













































module.exports = app;
const api = require('./server.js');
app.use(express.static('public'));
app.disable('strict-transport-security');
app.use('/_api', api);
app.get("/", function (request, response) {
  response.sendFile(__dirname + '/views/index.html');
});
let port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Your app is listening on port ${port}`);
});
