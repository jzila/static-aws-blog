var crypto = require("crypto");

exports.handler = function (event, context) {
    var siteId = "jzila.blog";
	var random = crypto.randomBytes(64).toString('base64');

	var blob = {
		siteId: siteId,
		token: random,
	};
    context.succeed(blob);
};
