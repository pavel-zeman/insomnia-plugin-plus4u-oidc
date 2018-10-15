const OidcToken = require("./oidc-interactive-login");
const NodeCache = require("node-cache");
const Jwt = require("jws");

let isAlreadyRunning = false;

const MY_TOKEN = "myToken";

module.exports.templateTags = [
  {
    name: "uuPersonPlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net",
    description: "Get identity token from oidc.plus4u.net",
    oidcTokenCache: new NodeCache({ stdTTL: 60 * 60, checkperiod: 120 }),

    async run() {
      const cacheToken = this.oidcTokenCache.get(MY_TOKEN);
      if (cacheToken) {
        return cacheToken;
      }
      if (isAlreadyRunning) {
        return "";
      }
      isAlreadyRunning = true;
      const token = await OidcToken.login();
      const decodedToken = Jwt.decode(token);
      if(decodedToken && decodedToken.payload){
        let now = new Date();
        let exp = new Date(decodedToken.payload.exp*1000); //token exp is in seconds
        let cacheTtl = (exp.getTime() - now.getTime() - 15*60*1000);
        this.oidcTokenCache.set(MY_TOKEN, token, cacheTtl/1000);
      } else {
        console.log("decoding failed, storing token withou additional info");
        this.oidcTokenCache.set(MY_TOKEN, token);
      }


      isAlreadyRunning = false;
      return token;
    }
  }
];
