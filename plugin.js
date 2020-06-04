const OidcToken = require("./oidc-client");
const NodeCache = require("node-cache");
const Jwt = require("jws");
const secureStore = require("oidc-plus4u-vault/lib/securestore");
const fetch = require("node-fetch");

let isAlreadyRunning = false;

const MY_TOKEN = "myToken";

let oidcTokenCache= new NodeCache({ stdTTL: 60 * 60, checkperiod: 120 });

function cacheToken(token, identification) {
  const decodedToken = Jwt.decode(token);
  if (decodedToken && decodedToken.payload) {
    let now = new Date();
    let exp = new Date(decodedToken.payload.exp * 1000); //token exp is in seconds
    let cacheTtl = exp.getTime() - now.getTime() - 15 * 60 * 1000;
    oidcTokenCache.set(identification, getTokenObject(token, exp), cacheTtl / 1000);
  } else {
    console.log("decoding failed, storing token without additional info");
    oidcTokenCache.set(identification, getTokenObject(token, exp));
  }
}

function getTokenObject(token, exp){
  let limit = exp.getTime - 60*60*1000;
  return {
    token: token,
    reuseLimit: new Date(limit)
  }
}

module.exports.templateTags = [
  {
    name: "uuPersonPlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net",
    description: "Get identity token from oidc.plus4u.net",

    async run(context, oidcServer) {
      const cachedToken = oidcTokenCache.get(MY_TOKEN);
      if (cachedToken) {
        if(cachedToken.reuseLimit > new Date()){
          //refreshToken + this.cacheToken(token, identification);
        }
        return cachedToken.token;
      }
      if (isAlreadyRunning) {
        return "";
      }
      isAlreadyRunning = true;
      try {
        const token = await OidcToken.interactiveLogin();
        cacheToken(token, MY_TOKEN);
      }catch (e) {
        console.error(e);
      }finally {
        isAlreadyRunning = false;
      }



      return token;
    }
  },
  {
    name: "uuEePlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net for uuEE",
    description: "Get identity token from oidc.plus4u.net as defined uuEE",
    accessCodesStore: new Map(),
    vaultPassword: null,
    args: [
      {
        displayName: "Prompt user identification",
        type: "string",
        help: `Identification to distinguish prompts for multiple different users. Please note that this information is shared accross the application in all
      prompts. So in case that you have multiple prompts with the same identification, they will share the token and access codes.`
      },
      {
        displayName: "OIDC Server",
        type: "string",
        defaultValue: "https://oidc.plus4u.net/uu-oidcg01-main/0-0",
        help: `URL of the OIDC server.`
      }
    ],

    async login(accessCode1, accessCode2, oidcServer) {
      if (accessCode1.length === 0 || accessCode2.length === 0) {
        throw `Access code cannot be empty. Ignore this error for "Prompt ad-hoc".`;
      }

      let tokenEndpoint = await this.getTokenEndpoint(oidcServer);

      let credentials = {
        accessCode1,
        accessCode2,
        grant_type: "password"
      };

      let headers = {};
      headers["Content-Type"] = "application/json";
      headers["Accept"] = "application/json";

      const res = await fetch(grantTokenUri, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(credentials),
      })
      let resp = res.json();
      if (Object.keys(resp.uuAppErrorMap).length > 0) {
        throw `Cannot login to OIDC server on ${oidcServer}. Probably invalid combination of Access Code 1 and Access Code 2.`;
      }
      return resp.id_token;
    },

    async getTokenEndpoint(oidcServer) {
      let oidcServerConfigUrl = oidcServer + "/.well-known/openid-configuration";
      const response = await fetch(oidcServerConfigUrl);
      const oidcConfig = await response.json();
      if (Object.keys(oidcConfig.uuAppErrorMap).length > 0) {
        throw `Cannot get configuration of OIDC server on ${oidcServer}. Probably invalid URL.`;
      }
      return oidcConfig.token_endpoint;
    },

    async loginDirectly(context, identification, oidcServer) {
      let ac1;
      let ac2;
      if (this.accessCodesStore.get(identification)) {
        ac1 = this.accessCodesStore.get(identification).accessCode1;
        ac2 = this.accessCodesStore.get(identification).accessCode2;
      } else {
        if (secureStore.exists()) {
          if (!this.vaultPassword) {
            let password;
            password = await context.app.prompt('OIDC vault password', {label: "OIDC vault password", inputType: "password"});
            if (password) {
              try {
                secureStore.read(password);
                this.vaultPassword = password;
              } catch (e) {
                console.error("Invalid vault password.");
                console.error(e);
              }
            }
          }
          if (this.vaultPassword) {
            let vault = secureStore.read(this.vaultPassword);
            if (vault[identification]) {
              ac1 = vault[identification].ac1;
              ac2 = vault[identification].ac2;
            }
          }
        }
        if (!ac1) {
          ac1 = await context.app.prompt('Access code 1', {label: "Access Code 1 for user " + identification, inputType: "password"});
          ac2 = await context.app.prompt('Access code 2', {label: "Access Code 2 for user " + identification, inputType: "password"});
        }
        console.log(`Using ${ac1} and ${ac2} for user ${identification}.`);
      }

      let token = await this.login(ac1, ac2, oidcServer);
      console.log(`Obtained new token for for user ${identification}`);
      this.accessCodesStore.set(identification, {accessCode1: ac1, accessCode2: ac2});

      return token;
    },

    async run(context, identification, oidcServer) {
      const cachedToken = oidcTokenCache.get(identification);
      if (cachedToken) {
        return cachedToken.token;
      }

      let token = await this.loginDirectly(context, identification, oidcServer);

      cacheToken(token, identification);

      return token;
    }
  }
];
