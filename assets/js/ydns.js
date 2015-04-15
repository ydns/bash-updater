/**
 * YDNS
 *
 * Copyright (C) 2015 TFMT UG (haftungsbeschränkt).
 * All rights reserved.
 */

"use strict";

var YDNS = function() {};

YDNS.init = function() {
	$('[data-toggle="tooltip"]').tooltip();
};

YDNS.safeForm = function(selector) {
	$(selector).on("submit", function() {
		$(this).find("button").attr("disabled", true);
		$(this).find("button.btn-primary").html('<i class="fa fa-spin fa-refresh fa-fw"></i>');
	});
};

YDNS.focusNextError = function(selector) {
	var el = $(selector).find(".form-group.has-error").find("input");

	if (el.size() > 0) {
		el.first().select().focus();
	}
};

YDNS.setActiveSection = function(names) {
    var n = names.split(",");

    for (var i in n) {
        $('[data-nav-id=' + n[i] + ']').addClass('active');
    }
};

$(function() {
	YDNS.init();
});