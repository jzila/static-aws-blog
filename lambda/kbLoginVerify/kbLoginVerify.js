var kblib = require("kb-signin");

exports.handler = function (event, context) {
    var blob = JSON.parse(event.blob);
    var signature = event.signature;

    var user_auth_func = function(user) {
        return user.kb_uid == '69da56f622a2ac750b8e590c3658a700';
    };

    var keybaseSignin = new kblib.KeybaseSignin({
        AWS: {
            IdentityPoolId: 'us-east-1:0586c251-cf19-49d3-8a55-cfb1a4129b1b',
            IdentityId: event.identity_id,
            LoginProvider: "login.jzila.blog",
            LambdaContext: context,
            UserAuthenticator: user_auth_func
        }
    });
    keybaseSignin.lookupKeybase(blob, signature);
};
