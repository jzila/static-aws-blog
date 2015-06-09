var kblib = require("kb-signin");

exports.handler = function (event, context) {
    var kbSignin = new kblib.KeybaseSignin();
    var blob = kbSignin.generateBlob("jzila.blog");
    context.succeed(blob);
};
