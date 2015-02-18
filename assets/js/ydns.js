/**
 * YDNS
 *
 * Copyright (C) 2015 TFMT UG (haftungsbeschränkt).
 * All rights reserved.
 */

"use strict";

var YDNS = function() {

};

YDNS.init = function() {
	$('[data-toggle="tooltip"]').tooltip();
	$('select.form-control').select2();
};

YDNS.focusNextError = function(selector) {
	var el = $(selector).find(".form-group.has-error").find("input");

	if (el.size() > 0) {
		el.first().select().focus();
	}
};

$(function() {
	YDNS.init();
});