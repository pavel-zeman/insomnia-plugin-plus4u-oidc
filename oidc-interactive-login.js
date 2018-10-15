"use strict";

const http = require("http");
const url = require("url");
const opn = require("opn");
const Got = require("got");

const OAUTH_CODE = "code";
const DEFAULT_OIDC_TENANT = "99923616732452117-4f06dafc03cb4c7f8c155aa53f0e86be";
const DEFAULT_OIDC_BASE_URI = "https://oidc.plus4u.net/uu-oidcg01-main";
const OIDC_WELL_KNOWN_DISCOVERY_PATH = ".well-known/openid-configuration";
const OAUTH_GRANT_TYPE = "grant_type";
const OAUTH_GRANT_TYPE_CODE = "authorization_code";
const OAUTH_SCOPE = "scope";
const OAUTH_SCOPE_OPENID = "openid";
const OAUTH_SCOPE_OFFLINE_ACCESS = "offline_access";
const OAUTH_CLIENT_ID = "client_id";
const OAUTH_UNREGISTERED_CLIENT_ID_PREFIX = "uu-oidc:unregistered-client:";
const CLIENT_ID = `${OAUTH_UNREGISTERED_CLIENT_ID_PREFIX}insomnia-plugin`;

class InteractiveLogin {

  static async login() {
    let code = await InteractiveLogin.get();
    let token = await InteractiveLogin.grantAuthorizationCodeToken(code);
    return token.id_token;
  }

  static isAvailable() {
    // TODO
    return true;
  }

  static async get() {
    let metadata = await InteractiveLogin.getMetadata();
    return await new Promise((resolve, reject) => {
      // Start local server to handle auth callback
      let server = http.createServer((req, res) => {
        let query = url.parse(req.url, true).query;
        let code = query[OAUTH_CODE];
        let redirectUri = metadata["issuer"];
        if (code) {
          resolve(code);
          redirectUri += `/showAccessTokenCode?close_page=now&code=${code}&message=Access%20Token%20Code%20accepted%20by%20Client.`;
          res.writeHead(302, {"Location": redirectUri});
        } else {
          reject(new Error("No access token code returned from OIDC server."));
          redirectUri += `/showAccessTokenCode?error=No%20access%20token%20code%20returned%20from%20OIDC%20server.`;
          res.writeHead(302, {"Location": redirectUri});
        }
        res.end(() => {
          // Close server after response is handled
          server.close();
        });
      });
      server.listen(0);
      // Open browser to initialize auth process
      let authzUri = metadata["authorization_endpoint"];
      authzUri += `?acr_values=1&client_id=${CLIENT_ID}&redirect_uri=http://localhost:${server.address().port}&response_type=code&scope=openid%20offline_access`;
      opn(authzUri);
    });
  }

  static async getMetadata(providerUri = null, refresh = false) {
    if (typeof(providerUri) === "boolean") {
      refresh = providerUri;
      providerUri = null;
    }
    if (providerUri === null) {
      // TODO Handle trailing slashes from configuration parameters
      providerUri = this.getOidcUri();
    }

    let discoveryUri = `${providerUri}/${OIDC_WELL_KNOWN_DISCOVERY_PATH}`;
    let result = await Got(discoveryUri);
    let metadata = JSON.parse(result.body);
    return metadata;
  }

  static async getPublicKeyData(kid, issuerUri = null) {
    let metadata = await InteractiveLogin.getMetadata(issuerUri);
    if (!issuerUri) {
      issuerUri = metadata["issuer"];
    }
    let result = await Got(metadata["jwks_uri"]);
    let jwks = JSON.parse(result.body);
    let publicKeyData = jwks.keys.find(pk => pk.kid === kid);

    if (!publicKeyData) {
      throw new BaseError(`Unable to obtain public JWK key with jwk_id=${kid} from ${metadata["jwks_uri"]}.`);
    }
    return publicKeyData;
  }

  static async grantAuthorizationCodeToken(authorizationCode) {
    let params = {};
    params[OAUTH_GRANT_TYPE] = OAUTH_GRANT_TYPE_CODE;
    params[OAUTH_CODE] = authorizationCode;
    params[OAUTH_CLIENT_ID] = CLIENT_ID;
    params[OAUTH_SCOPE] = `${OAUTH_SCOPE_OPENID} ${OAUTH_SCOPE_OFFLINE_ACCESS}`;
    return await InteractiveLogin.grantToken(params);
  }

  static async grantToken(params) {
    let metadata = await InteractiveLogin.getMetadata();
    let grantTokenUri = metadata["token_endpoint"];

    let headers = {};
    headers["Content-Type"] = "application/json";
    headers["Accept"] = "application/json";

    let result = await Got.post(grantTokenUri, {
      headers: headers,
      body: JSON.stringify(params)
    });

    return JSON.parse(result.body);
  }

  static getOidcUri() {
    let oidcUri = `${DEFAULT_OIDC_BASE_URI}/${DEFAULT_OIDC_TENANT}`;
    return oidcUri;
  }
}

module.exports = InteractiveLogin;
