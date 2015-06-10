var kb_user_blob_id = "kb-user-blob";
var kb_signature_blob_id = "kb-signature-blob";

function createKbElements(blob) {
	var input_string = "<input type=\"text\" style=\"width: 1px !important; height: 1px !important; position:absolute !important; top:-100px !important; left: -100px !important;\" />";
	$(input_string).attr("id", "kb-login-blob").prependTo($("body")).val(JSON.stringify(blob));
	$(input_string).attr("id", kb_user_blob_id).prependTo($("body"));
	$(input_string).attr("id", kb_signature_blob_id).prependTo($("body"));
};

function kbUserChange(handleValidUser, handleInvalidUser) {
    return function() {
        var val;

        if (Object.getPrototypeOf(this) === HTMLInputElement.prototype && (val = $(this).val())) {
            user = JSON.parse(val);
            handleValidUser(user);
        } else {
            handleInvalidUser();
        }
    }
};

function signatureChange(sigVerifyFunc) {
    return function() {
        var val;

        if (Object.getPrototypeOf(this) === HTMLInputElement.prototype && (val = $(this).val())) {
            var data = JSON.parse(val);
            var user_blob = $('#kb-user-blob');
            var successHandler = function (data) {
                user_blob.val(JSON.stringify({user: data.user}));
                user_blob[0].dispatchEvent(new CustomEvent("change"));
            };
            var failHandler = function (err) {
                user_blob.val(JSON.stringify({error: "Unable to verify identity"}));
                user_blob[0].dispatchEvent(new CustomEvent("change"));
            };
            sigVerifyFunc(data, successHandler, failHandler);
        }
    };
};

function getBlob(getBlobFunc, signatureVerifyFunc, handleValidUser, handleInvalidUser) {
    getBlobFunc(function (blob) {
        createKbElements(blob);

        $("#" + kb_user_blob_id).change(kbUserChange(validUserHandler, invalidUserHandler));
        $("#" + kb_signature_blob_id).change(signatureChange(signatureVerifyFunc));
    });
};
