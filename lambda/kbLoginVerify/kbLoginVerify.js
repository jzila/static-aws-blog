var kblib = require("kb-signin");

exports.handler = function (event, context) {
    var blob = JSON.parse(event.blob);
    var signature = event.signature;

    var keybaseSignin = new kblib.KeybaseSignin({
        AWS: {
            IdentityPoolId: 'us-east-1:0586c251-cf19-49d3-8a55-cfb1a4129b1b',
            IdentityId: event.identity_id,
            LoginProvider: "login.jzila.blog",
            LambdaContext: context
        }
    });
    keybaseSignin.lookupKeybase(blob, signature);
};
