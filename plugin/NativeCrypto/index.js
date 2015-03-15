/*
* Copyright (c) 2013-2014 BlackBerry Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

var nativeCrypto,
	resultObjs = {},
   _utils = require("../../lib/utils");

module.exports = {

	// Code can be declared and used outside the module.exports object,
	// but any functions to be called by client.js need to be declared
	// here in this object.

	// These methods call into JNEXT.GSECrypto which handles the
	// communication through the JNEXT plugin to gseCrypto_js.cpp

    rsaDecrypt: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().rsaDecrypt(result.callbackId,
            input.eLen, input.nLen, input.dLen, input.pLen, input.qLen,
            input.e,    input.n,    input.d,    input.p,    input.q,
            input.message
        ), false);
    },
    rsaEncrypt: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().rsaEncrypt(result.callbackId,
            input.nLen,
            input.e,    input.n,
            input.message
        ), false);
    },
    aes128ecb: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().aes128ecb(result.callbackId, input.key, input.block), false);
    },
    produceKeyByPassword: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().produceKeyByPassword(result.callbackId,
            input.password, input.numBytes, input.algorithm, input.type, input.c, input.salt), false);
    },
	hashMd5: function (success, fail, args, env) {
	        var result = new PluginResult(args, env);
	        var input = JSON.parse(decodeURIComponent(args.input));
	        result.ok(nativeCrypto.getInstance().hashMd5(result.callbackId, input), false);
	},
    ripemd160: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().ripemd160(result.callbackId, input), false);
    },
    hashSha1: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().hashSha1(result.callbackId, input), false);
    },
    hashSha224: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().hashSha224(result.callbackId, input), false);
    },
    hashSha256: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().hashSha256(result.callbackId, input), false);
    },
    hashSha384: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().hashSha384(result.callbackId, input), false);
    },
    hashSha512: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        var input = JSON.parse(decodeURIComponent(args.input));
        result.ok(nativeCrypto.getInstance().hashSha512(result.callbackId, input), false);
    },

    ping: function (success, fail, args, env) {
        var result = new PluginResult(args, env);
        result.ok(nativeCrypto.getInstance().ping(), false);
    }

};

///////////////////////////////////////////////////////////////////
// JavaScript wrapper for JNEXT plugin for connection
///////////////////////////////////////////////////////////////////

JNEXT.NativeCrypto = function () {
	var self = this,
		hasInstance = false;

	self.getId = function () {
		return self.m_id;
	};

	self.init = function () {
		if (!JNEXT.require("libNativeCrypto")) {
			return false;
		}

		self.m_id = JNEXT.createObject("libNativeCrypto.NativeCryptoJS");

		if (self.m_id === "") {
			return false;
		}

		JNEXT.registerEvents(self);
	};

	// ************************
	// Enter your methods here
	// ************************

	// calls into InvokeMethod(string command) in nativeCrypto_js.cpp

    self.ping = function () {
        return JNEXT.invoke(self.m_id, "ping");
    };

    self.produceKeyByPassword = function (callbackId, password, numBytes, algorithm, type, c, salt) {
        return JNEXT.invoke(self.m_id, "produceKeyByPassword " + callbackId + " " + password +" "+ numBytes +" "+algorithm+" "+type+" "+c+" "+salt);
    };
    self.aes128ecb = function (callbackId, key, block) {
        return JNEXT.invoke(self.m_id, "aes128ecb " + callbackId + " " + key +" "+ block);
    };
    self.rsaEncrypt = function (callbackId, nLen, e, n, message) {
        return JNEXT.invoke(self.m_id, "rsaEncrypt " + callbackId + " " + nLen+ " " + e+ " " + n+ " " + message);
    };
    self.rsaDecrypt = function (callbackId, eLen, nLen, dLen, pLen, qLen, e, n, d, p, q, message) {
        return JNEXT.invoke(self.m_id, "rsaDecrypt " + callbackId + " " + eLen+ " " + nLen+ " " + dLen+ " " + pLen+ " " + qLen+ " " + e+ " " + n+ " " + d+ " " + p+ " " + q+ " " + message);
    };
    self.hashMd5 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashMd5 " + callbackId + " " + input );
    };
    self.ripemd160 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "ripemd160 " + callbackId + " " + input );
    };
    self.hashSha1 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashSha1 " + callbackId + " " + input );
    };
    self.hashSha224 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashSha224 " + callbackId + " " + input );
    };
    self.hashSha256 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashSha256 " + callbackId + " " + input );
    };
    self.hashSha384 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashSha384 " + callbackId + " " + input );
    };
    self.hashSha512 = function (callbackId, input) {
        return JNEXT.invoke(self.m_id, "hashSha512 " + callbackId + " " + input );
    };

	// ************************
	// End of methods to edit
	// ************************
	self.m_id = "";

	self.getInstance = function () {
		if (!hasInstance) {
			hasInstance = true;
			self.init();
		}
		return self;
	};

};

nativeCrypto = new JNEXT.NativeCrypto();
