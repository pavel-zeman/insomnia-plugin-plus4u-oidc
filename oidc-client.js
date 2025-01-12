"use strict";

const http = require("http");
const url = require("url");
const open = require("open");
const fetch = require("node-fetch");

const OAUTH_CODE = "code";
const DEFAULT_OIDC_TENANT = "bb977a99f4cc4c37a2afce3fd599d0a7";
const DEFAULT_OIDC_BASE_URI = "https://uuidentity.plus4u.net/uu-oidc-maing02";
const OIDC_WELL_KNOWN_DISCOVERY_PATH = ".well-known/openid-configuration";
const OAUTH_GRANT_TYPE = "grant_type";
const OAUTH_GRANT_TYPE_CODE = "authorization_code";
const OAUTH_SCOPE = "scope";
const OAUTH_SCOPE_OPENID = "openid";
const OAUTH_CLIENT_ID = "client_id";
const OAUTH_CLIENT_SECRET = "client_secret";
const OAUTH_REDIRECT_URI = "redirect_uri";
const OAUTH_RESPONSE_TYPE = "response_type";
const DEFAULT_CLIENT_ID = "F64b643R05xQ62696875W1j2";
const DEFAULT_CLIENT_SECRET = "2u1q5KU2Z0Bs5SErmYVwM053+zyKDxT7QLU2Q7Rr7nn5t5%Bt80px8mf3$s16FdK";
const DEFAULT_AUDIENCE = "https:// http://localhost";
const DEFAULT_INFO_PAGE = "https://uuidentity.plus4u.net/uu-identitymanagement-maing01/a9b105aff2744771be4daa8361954677/showAuthorizationCode";

class OidcClient {

  static async interactiveLogin() {
    let [code, serverPort] = await OidcClient.getAuthorizationCode();
    let token = await OidcClient.grantAuthorizationCodeToken(code, serverPort);
    return token.id_token;
  }

  static isInteractiveLoginAvailable() {
    // TODO
    return true;
  }

  static async getAuthorizationCode() {
    let metadata = await OidcClient.getMetadata();
    return await new Promise((resolve, reject) => {
      // Start local server to handle auth callback
      let server = http.createServer((req, res) => {
        let query = url.parse(req.url, true).query;
        let code = query[OAUTH_CODE];
        let redirectUri = DEFAULT_INFO_PAGE;
        redirectUri += `?clientId=${DEFAULT_CLIENT_ID}`;
        if (code) {
          resolve([code, server.address().port]);
          res.writeHead(302, {"Location": redirectUri});
        } else {
          let uuAppErrorMap = query["uuAppErrorMap"];
          reject(new Error(`No access token code returned from OIDC server: ${uuAppErrorMap}`));
          redirectUri += `&uuAppErrorMap=${uuAppErrorMap}`;
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
      authzUri += `?${OAUTH_CLIENT_ID}=${DEFAULT_CLIENT_ID}`;
      authzUri += `&${OAUTH_REDIRECT_URI}=http://localhost:${server.address().port}`;
      authzUri += `&${OAUTH_RESPONSE_TYPE}=${OAUTH_CODE}`;
      authzUri += `&${OAUTH_SCOPE}=${OAUTH_SCOPE_OPENID}${encodeURIComponent(" " + DEFAULT_AUDIENCE)}`;
      open(authzUri);
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
    const response = await fetch(discoveryUri);
    const result = await response.json();
    return result;
  }

  static async getPublicKeyData(kid, issuerUri = null) {
    let metadata = await OidcClient.getMetadata(issuerUri);
    if (!issuerUri) {
      issuerUri = metadata["issuer"];
    }
    const response = await fetch(metadata["jwks_uri"]);
    const result = await response.json();
    let jwks = JSON.parse(result.body);
    let publicKeyData = jwks.keys.find(pk => pk.kid === kid);

    if (!publicKeyData) {
      throw new Error(`Unable to obtain public JWK key with jwk_id=${kid} from ${metadata["jwks_uri"]}.`);
    }
    return publicKeyData;
  }

  static async grantAuthorizationCodeToken(authorizationCode, serverPort) {
    let params = {};
    params[OAUTH_GRANT_TYPE] = OAUTH_GRANT_TYPE_CODE;
    params[OAUTH_CODE] = authorizationCode;
    params[OAUTH_CLIENT_ID] = DEFAULT_CLIENT_ID;
    params[OAUTH_CLIENT_SECRET] = DEFAULT_CLIENT_SECRET;
    params[OAUTH_SCOPE] = `${OAUTH_SCOPE_OPENID} ${DEFAULT_AUDIENCE}`;
    params[OAUTH_REDIRECT_URI] = `http://localhost:${serverPort}`;
    return await OidcClient.grantToken(params);
  }

  static async grantToken(params) {
    let metadata = await OidcClient.getMetadata();
    let grantTokenUri = metadata["token_endpoint"];

    let headers = {};
    headers["Content-Type"] = "application/json";
    headers["Accept"] = "application/json";

    let result;
    try {
      const res = await fetch(grantTokenUri, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(params),
      })
      result = res.json();
    } catch (e) {
      throw new Error(`Authentication failed: ${e.response.body}`);
    }
    return result;
  }

  static getOidcUri() {
    let oidcUri = `${DEFAULT_OIDC_BASE_URI}/${DEFAULT_OIDC_TENANT}/oidc`;
    return oidcUri;
  }
}

module.exports = OidcClient;
