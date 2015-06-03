var invokeLambda = function(functionName, payload, successCb, failCb) {
    var lambda = new AWS.Lambda({apiVersion: '2015-03-31'});
    var params = {
        FunctionName: functionName,
        Payload: payload
    };
    lambda.invoke(params, function(err, data) {
        if (err) {
            if (failCb) {
                failCb(err);
            } else {
                console.log(err);
            }
        } else {
            successCb(data);
        }
    });
};

var getBlobFunc = function(successCb) {
    var cb = function(blob) {
        var data = JSON.parse(blob.Payload);
        return successCb(data);
    };
    invokeLambda('getSigninBlob', null, cb);
    // To call a specific URL:
    //$.ajax({
    //    url: "/api/get_blob/",
    //    type: "GET",
    //    success: successCb
    //});
};

var validUserHandler = function (user) {
    // user.full_name potentially contains full name
    // user.kb_username contains keybase username
};

var invalidUserHandler = function () {
};

$(document).ready(function () {
    var credentials = new AWS.CognitoIdentityCredentials({
        RoleArn: 'arn:aws:iam::491003545914:role/Cognito_JZilaBlogUnauth_Role',
        IdentityPoolId: 'us-east-1:0586c251-cf19-49d3-8a55-cfb1a4129b1b'
    });
    AWS.config.update({
        region: 'us-east-1',
        credentials: credentials
    });
    var sts = new AWS.STS();

    var kbLoginFunc = function(data, successHandler, failHandler) {
        data.identity_id = credentials.identityId;
        var cb = function(data) {
            var blob = JSON.parse(data.Payload);
            var stsParams = {
                RoleArn: 'arn:aws:iam::491003545914:role/Cognito_JZilaBlogAuth_Role',
                RoleSessionName: blob.user.kb_uid,
                WebIdentityToken: blob.user.identity.Token
            };
            sts.assumeRoleWithWebIdentity(stsParams, function(err, data) {
                if (err) console.log(err, err.stack);
                else     console.log(data);
            });
            return successHandler(blob);
        };
        invokeLambda('kbLoginVerify', JSON.stringify(data), cb, failHandler);
    };

    getBlob(getBlobFunc, kbLoginFunc, validUserHandler, invalidUserHandler);
});
