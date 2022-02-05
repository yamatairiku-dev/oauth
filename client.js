// クライアントのサンプルコード
'use strict';
const express = require("express");
const fetch = require('node-fetch');
const qs = require("qs");
const querystring = require('querystring');
const cons = require('consolidate');
const __ = require('underscore');
__.string = require('underscore.string');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));	// support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// 自サーバ（クライアント）の情報
const hostAddress = 'localhost';
const portNumber = 3000;
const authorizationServerPort = 3001;
const protectedResourceServerPort = 3002;
const client = {
	"client_id": "takusou",
	"client_secret": "takusou-secret",
	"scope": "foo bar"
};

// 認可サーバの情報
const authServer = {
	authorizationEndpoint: `http://${hostAddress}:${authorizationServerPort}/oauth`,		// リソースオーナー・パスワード・クレデンシャルズでは使用しない
	tokenEndpoint: `http://${hostAddress}:${authorizationServerPort}/token`
};

// リソースサーバの情報
const protectedResource = `http://${hostAddress}:${protectedResourceServerPort}/resource`;

// 初期化
let access_token = null;
let scope = null;
let expires_in = null;
let expires_date = null;

// index表示
app.get('/', (req, res) => {
	access_token = null;
	scope = null;
	expires_in = null;
	expires_date = null;
	res.render('index', {access_token: access_token, scope: scope, expires_in: expires_in, expires_date: expires_date});
});

// ブラウザにリソースオーナー情報を入力する画面を表示
app.get('/authorize', (req, res) => {
	res.render('username_password');
	return;
});

// リソースオーナー・パスワード・クレデンシャルズ
// ブラウザからリソースオーナー情報を取得
app.post('/username_password', (req, res) => {
	const username = req.body.username;
	const password = req.body.password;

	// ボディーにセットするフォーム情報
	const form_data = qs.stringify({
		grant_type: 'password',
		username: username,
		password: password,
		scope: client.scope
	});
	
	// ヘッダー情報
	const headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		// AuthorizationヘッダーにクライアントIDとクライアントシークレットをBase64エンコードしてセット
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	fetch(authServer.tokenEndpoint, { method: 'POST', body: form_data, headers: headers })
	.then(res => {
		if (res.ok) {
			return res;
		} else {
			throw fetchTokenError(res.statusCode);
		}
	})
	.then(res => res.json())
	.then(body => {
		// トークン、スコープ、有効期限を取得
		access_token = body.access_token;
		scope = body.scope;
		expires_in = body.expires_in;
		// トークンの有効期限から有効期日を計算
		const expiresDate =new Date(expires_in*1000 + Date.now());
		expires_date= expiresDate.toUTCString();
	
		res.render('index', {access_token: access_token, scope: scope, expires_in: expires_in, expires_date: expires_date});
	});
});

// クライアント・クレデンシャルズ
app.post('/client_credentials', (req, res) => {

	// ボディーにセットするフォーム情報
	const form_data = qs.stringify({
		grant_type: 'client_credentials',
		scope: client.scope
	});

	// ヘッダー情報
	const headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		// AuthorizationヘッダーにクライアントIDとクライアントシークレットをBase64エンコードしてセット
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};
	
	fetch(authServer.tokenEndpoint, { method: 'POST', body: form_data, headers: headers })
	.then(resToken => {
		if (resToken.ok) {
			return resToken;
		} else {
			throw fetchTokenError(res, resToken.statusText);
		}
	})
	.then(res => res.json())
	.then(body => {
		// トークン、スコープ、有効期限を取得
		access_token = body.access_token;
		scope = body.scope;
		expires_in = body.expires_in;
		// トークンの有効期限から有効期日を計算
		const expiresDate =new Date(expires_in*1000 + Date.now());
		expires_date= expiresDate.toUTCString();
	
		res.render('index', {access_token: access_token, scope: scope, expires_in: expires_in, expires_date: expires_date});
	})
	.catch(error => {
		console.log("fetch token error");
	});
});

// ブラウザからリソース取得トリガー発行
app.get('/fetch_resource', (req, res) => {

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}

	console.log(`Making request with token ${access_token}`);
	
	// リクエストヘッダーにトークンをセット
	const headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	// リソース取得エンドポイントへヘッダー情報をPOST
	fetch(protectedResource, { method: 'POST', headers: headers })
	.then(resResouce => {
		if (resResouce.ok) {
			return resResouce;
		} else {
			throw fetchResourceError(res, resResouce.statusText);
		}
	})
	.then(res => res.json())
	.then(json => {
		res.render('data', {resource: json});
	})
	.catch(error => {
		console.log("fetch resource error");
	});
});

// クライアントID・クライアントシークレットをBase64エンコードする関数
const encodeClientCredentials = (clientId, clientSecret) => {
	return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

// トークン取得エラーハンドラー
const fetchTokenError = (res, status) => {
	res.render('error', {error: 'Unable to fetch access token, server response: ' + status})
};

// リソース取得エラーハンドラー
const fetchResourceError = (res, status) => {
	access_token = null;
	res.render('error', {error: 'Unable to fetch resource, server response: ' + status})
};

// サーバ起動
const server = app.listen(portNumber, () => {
	console.log(`OAuth Client is listening at http://${hostAddress}:${portNumber}`);
});
