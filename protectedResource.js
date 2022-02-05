// リソースサーバのサンプルコード
'use strict';
const express = require("express");
const cons = require('consolidate');
const nosql = require('nosql');
const db = nosql.load('database.nosql');

const app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

// 自サーバ（リソースサーバ）の情報
const hostAddress = 'localhost';
const portNumber = 3002;

// リクエストからトークンを取得しデータベースと照合する関数
const getAccessToken = (req, res, next) => {
	// トークンはAuthorizationヘッダーにある前提
	// 次は期待している書式
	// Authorization: Bearer QKpmh6Snzpr5YbruVRQ8OqY5E9hJ8uoI
	const auth = req.headers['authorization'];
	let inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	};
	console.log(`Incoming token: ${inToken}`);

	// データベースからトークンを検索
	db.one().make((builder) => {
	  builder.where('access_token', inToken);
	  builder.callback((err, token) => {
	    if (token) {
			// トークンの有効期限をチェック
			if (token.expires_date > Date.now()){
				console.log(`We found a valid token: ${inToken}`);
				req.access_token = token;
			} else {
				console.log('token expired');
				token = null;
			};
	    } else {
	    	console.log('No matching token was found.');
	    };
		req.access_token = token;
	    next();
	    return;
	  });
	});
};

// index表示
app.get('/', (req, res) => {
	res.render('index', {hostAddress: hostAddress, portNumber: portNumber});
});

// リソース取得エンドポイント
// エンドポイントへのリクエストをgetAccessTokenで前処理
app.post("/resource", getAccessToken, (req, res) => {
	// トークンがあればリソースをレスポンス
	if (req.access_token) {
		const resource = {
			"Resource Scope": req.access_token.scope,
			"Resource Owner": req.access_token.username,
			"description": "This data has been protected by OAuth 2.0"
		};
		res.json(resource);
	} else {
		res.status(401).end();
	}
});

// サーバ起動
const server = app.listen(portNumber, () => {
	console.log(`OAuth Resource Server is listening at http://${hostAddress}:${portNumber}`);
});
