const authLib = require('/lib/xp/auth');
const contextLib = require('/lib/context');
const configLib = require('/lib/config');
const commonLib = require('/lib/xp/common');
const portalLib = require('/lib/xp/portal');
const preconditions = require('/lib/preconditions');
const oidcLib = require('./oidc');

const regExp = /\$\{([^\}]+)\}/g;

function login(token, tokenClaims, isAutoLogin) {
    const idProviderKey = portalLib.getIdProviderKey();
    const idProviderConfig = configLib.getIdProviderConfig();
    const userName = commonLib.sanitize(preconditions.checkParameter(tokenClaims, idProviderConfig.claimUsername));
    const principalKey = `user:${idProviderKey}:${userName}`;
    const user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));

    let claims = isAutoLogin? tokenClaims : resolveClaims(idProviderConfig, token, tokenClaims);
    let wasUserCreated = false;
    if (!user) {
        if (!isAutoLogin || idProviderConfig.autoLogin.createUser) {
            if (isAutoLogin) {
                claims = resolveClaims(idProviderConfig, token, tokenClaims);
            }
            doCreateUser(idProviderConfig, claims, userName, isAutoLogin);
            wasUserCreated = true;
        } else if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user '${userName}'. User does not exist`);
        }
    }

    if (wasUserCreated || !isAutoLogin) {
        saveClaims(claims, principalKey);
    }

    if (!wasUserCreated && !isAutoLogin) {
        updateUserData(claims, idProviderConfig, user);
    }

    doLogin(idProviderConfig, userName, isAutoLogin);
}

function getClaim(claims, claimKey) {
    const claimKeys = claimKey.split('.');

    let currentClaimObject = claims;
    let claim;
    for (const claimKey of claimKeys) {
        currentClaimObject = currentClaimObject[claimKey];
        if (currentClaimObject == null) {
            log.warning(`Claim [${claimKey}] missing`);
            return '';
        }
        claim = currentClaimObject;
    }
    return claim || '';
}

function removeNonSupportedKeys(claims) {
    if (typeof claims !== 'object' || claims === null) {
        return claims;
    }

    if (Array.isArray(claims)) {
        return claims.map(removeNonSupportedKeys);
    }

    const newClaims = {};

    for (const key in claims) {
        if (claims.hasOwnProperty(key) && !(key.indexOf('.') !== -1 || key.indexOf('[') !== -1 || key.indexOf(']') !== -1)) {
            newClaims[key] = removeNonSupportedKeys(claims[key]);
        }
    }

    return newClaims;
}

function saveClaims(claims, principalKey) {
    const profile = contextLib.runAsSu(() => authLib.modifyProfile({
        key: principalKey,
        scope: 'oidc',
        editor: () => removeNonSupportedKeys(claims)
    }));

    log.debug(`Modified profile of [${principalKey}]: ${JSON.stringify(profile)}`);
}

function doLogin(idProviderConfig, userName, isAutoLogin) {
    const idProviderKey = idProviderConfig._idProviderName;
    const principalKey = `user:${idProviderKey}:${userName}`;

    const loginParams = {
        user: userName,
        idProvider: idProviderKey,
        skipAuth: true
    };

    if (isAutoLogin) {
        loginParams.scope = idProviderConfig.autoLogin.createSession ? 'SESSION' : 'REQUEST';
    }

    //Logs in the user
    const loginResult = authLib.login(loginParams);
    if (loginResult.authenticated) {
        log.debug(`Logged in user [${principalKey}]`);
    } else {
        if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user [${principalKey}]`);
        }
        throw `Error while logging user [${principalKey}]`;
    }
}

function doCreateUser(idProviderConfig, claims, userName, isAutoLogin) {
    const userinfoClaims = claims.userinfo;

    if (idProviderConfig.rules.forceEmailVerification) {
        if (userinfoClaims.email_verified !== true) {
            if (isAutoLogin) {
                throwAutoLoginFailedError(`Auto login failed for user '${userName}'. Email must be verified`);
            }
            throw 'Email must be verified';
        }
    }

    const email = resolveEmail(claims, idProviderConfig);
    const displayName = resolveDisplayName(claims, idProviderConfig) || email;

    if (!email) {
        if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user '${userName}'. User can not be created without email.`);
        }
        throw 'User can not be created without email';
    }

    let user;
    try {
        user = contextLib.runAsSu(() => authLib.createUser({
            idProvider: idProviderConfig._idProviderName,
            name: userName,
            displayName: displayName,
            email: email
        }));
        log.info(`User [${user.key}] created in ID Provider [${idProviderConfig._idProviderName}]`);
    } catch (e) {
        if (`${e}`.startsWith('com.enonic.xp.security.PrincipalAlreadyExistsException')) {
            const principalKey = `user:${idProviderConfig._idProviderName}:${userName}`
            user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));
        } else {
            throw `User '${userName}' could not be provided: ${e}`;
        }
    }

    if (user) {
        contextLib.runAsSu(() => {
            idProviderConfig.defaultGroups.forEach(function (defaultGroup) {
                authLib.addMembers(defaultGroup, [user.key]);
                log.debug(`User [${user.key}] added to group [${defaultGroup}]`);
            });
        });
    }
}

function resolveClaims(idProviderConfig, accessToken, tokenClaims) {
    const claims = {
        userinfo: tokenClaims
    };

    if (idProviderConfig.userinfoUrl && idProviderConfig.useUserinfo) {
        const userinfoClaims = oidcLib.requestOAuth2({
            url: idProviderConfig.userinfoUrl,
            accessToken: accessToken,
        });

        if (tokenClaims.sub !== userinfoClaims.sub) {
            throw `Invalid sub in user info : ${userinfoClaims.sub}`;
        }

        claims.userinfo = oidcLib.mergeClaims(claims.userinfo, userinfoClaims);
    }

    idProviderConfig.additionalEndpoints.forEach(additionalEndpoint => {
        const additionalClaims = oidcLib.requestOAuth2({
            url: additionalEndpoint.url,
            accessToken: accessToken
        });
        log.debug(`OAuth2 endpoint [${additionalEndpoint.name}] claims: ${JSON.stringify(additionalClaims)}`);
        claims[additionalEndpoint.name] = oidcLib.mergeClaims(claims[additionalEndpoint.name] || {}, additionalClaims);
    });

    return claims;
}

function throwAutoLoginFailedError(message) {
    const error = Error(message);
    error.name = 'AutoLoginFailedError';

    throw error;
}

function resolveEmail(claims, idProviderConfig) {
    return idProviderConfig.mappings.email.replace(regExp, (match, claimKey) => getClaim(claims, claimKey)) ||
           claims.userinfo.email;
}

function resolveDisplayName(claims, idProviderConfig) {
    const userinfoClaims = claims.userinfo;
    return idProviderConfig.mappings.displayName.replace(regExp,
        (match, claimKey) => getClaim(claims, claimKey)) || userinfoClaims.preferred_username || userinfoClaims.name || userinfoClaims.sub;
}

function updateUserData(claims, idProviderConfig, user) {
    const email = resolveEmail(claims, idProviderConfig);
    const displayName = resolveDisplayName(claims, idProviderConfig) || email;

    if (user.displayName !== displayName || user.email !== email) {
        contextLib.runAsSu(() => authLib.modifyUser({
            key: user.key,
            editor: function (c) {
                c.displayName = displayName;
                c.email = email;
                return c;
            }
        }));

        log.debug(`User [${user.key}] updated with displayName [${displayName}] and email [${email}]`);
    }
}

exports.login = login;

function loginMatchingUser(tokenClaims, idProviderConfig) {
    const user = findMatchingUser(tokenClaims, idProviderConfig);
    if (!user) {
        throw `Could not find matching user for token claims`;
    }
    doLogin(idProviderConfig, user.login, true);
    return;
}

function findMatchingUser(tokenClaims, idProviderConfig) {
    const idProviderKey = portalLib.getIdProviderKey();
    const additionalOidcServers = idProviderConfig.autoLogin.additionalOidcServers;
    log.debug("additionalOidcServers: %s", JSON.stringify(additionalOidcServers, null, 4));

    let matchUsername = null;
    let matchEmail = null;
    for (const candidateOidcServer of additionalOidcServers) {
        log.debug("candidateOidcServer: %s", JSON.stringify(candidateOidcServer, null, 4));
        if (candidateOidcServer.issuer == tokenClaims.iss) {
            matchUsername = candidateOidcServer.matchUsername;
            matchEmail = candidateOidcServer.matchEmail;
            log.debug("matchUsername: %s", JSON.stringify(matchUsername, null, 4));
            log.debug("matchEmail: %s", JSON.stringify(matchEmail, null, 4));
            break;
        } 
    }
    if (matchUsername) {
        const username = matchUsername.replace(regExp, (match, claimKey) => getClaim(tokenClaims, claimKey));
        const resolvedPrincipalKey = `user:${idProviderKey}:${username}`;
        log.debug("resolvedPrincipalKey: %s", JSON.stringify(resolvedPrincipalKey, null, 4));
        const user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));
        if (user) {
            return user;
        }
    }

    if (!matchEmail) {
        return null;
    }

    const email = matchEmail.replace(regExp, (match, claimKey) => getClaim(tokenClaims, claimKey));
    const findUsersQuery = `email = '${email}' AND userStoreKey = '${idProviderKey}'`;
    log.debug("findUsersQuery: %s", JSON.stringify(findUsersQuery, null, 4));
    const findUsersResult = contextLib.runAsSu(() => authLib.findUsers({
        count: 2,
        query: findUsersQuery
    }));
    log.debug("findUsersResult: %s", JSON.stringify(findUsersResult, null, 4));
    if (findUsersResult.count != 1) {
        return null;
    }
    return findUsersResult.hits[0];
}

exports.loginMatchingUser = loginMatchingUser;