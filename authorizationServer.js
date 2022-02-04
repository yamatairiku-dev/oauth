// 認可サーバのサンプルコード
'use strict';
const express = require("express");
const randomstring = require("randomstring");
const cons = require('consolidate');
const nosql = require('nosql');
const db = nosql.load('database.nosql');
const querystring = require('querystring');
const __ = require('underscore');
__.string = require('underscore.string');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// 自サーバ（認可サーバ）の情報
const hostAddress = 'localhost';
const portNumber = 9001;

// トークンの有効期限を設定（秒）
const expiresIn = 30*24*60*60;		//30日
// const expiresIn = 3;				//3秒

// クライアントの情報
const clients = [
	{
		"client_id": "takusou",
		"client_secret": "takusou-secret",
		"scope": "foo bar"
	},
	{
		"client_id": "jiken",
		"client_secret": "jiken-secret",
		"scope": "data.all"
	},
	{
		"client_id": "keiki",
		"client_secret": "keiki-secret",
		"scope": "data.read"
	}
];

// リソースオーナーの情報
const userInfo = {
	"komori": {
		"username": "komori",
		"password": "password"
	},
	"oyama": {
		"username": "oyama",
		"password": "password"
	},
	"fujita": {
		"username": "fujita",
		"password": "password"
	},
	"nunomura": {
		"username": "nunomura",
		"password": "password"
	}
};

// index表示
app.get('/', (req, res) => {
	res.render('index', {clients: clients, authServer: authServer});
});

// トークン取得エンドポイントへの要求
app.post("/token", (req, res) => {
	// Authorizationヘッダーを取得
	// 次は期待している書式
	// Authorization: Basic dGFrdXNvdTp0YWt1c291LXNlY3JldA==
	const auth = req.headers['authorization'];
	let clientId = null;
	let clientSecret = null;
	if (auth) {
		let clientCredentials = decodeClientCredentials(auth);
		clientId = clientCredentials.id;
		clientSecret = clientCredentials.secret;
	}
	
	// クライアントIDからクライアントオブジェクトを取得
	const client = getClient(clientId);
	if (!client) {
		console.log(`Unknown client ${clientId}`);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	// クライアントシークレットをチェック
	if (client.client_secret != clientSecret) {
		console.log(`Mismatched client secret, expected ${client.client_secret} got ${clientSecret}`);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	const grantType = req.body.grant_type;
	const userName = req.body.username;

	// グラントタイプをチェック。リソースオーナー・パスワード・クレデンシャルズまたはクライアント・クレデンシャルズのみをサポート。
	// リソースオーナー・パスワード・クレデンシャルズの場合
	if (grantType == 'password') {
		// リソースオーナー名からリソースオーナーオブジェクトを取得
		const user = getUser(userName);
		if (!user) {
			res.status(401).json({error: 'invalid_grant'});
			return;
		};
		// リソースオーナーのパスワードをチェック
		const password = req.body.password;
		if (user.password != password) {
			console.log(`Mismatched resource owner password, expected ${user.password} got ${password}`);
			res.status(401).json({error: 'invalid_grant'});
			return;
		} ;
		console.log('Resource Owner Password Credentials grant type');
	// クライアント・クレデンシャルズの場合
	} else if (grantType == 'client_credentials') {
		console.log('Client Credentials grant type');
	} else {
		console.log(`Unknown grant type ${req.body.grant_type}`);
		res.status(400).json({error: 'unsupported_grant_type'});
		return;
	};

	// リクエストからスコープを取得
	const rscope = req.body.scope ? req.body.scope.split(' ') : undefined;
	// クライアントの登録スコープ情報を取得
	const cscope = client.scope ? client.scope.split(' ') : undefined;
	// スコープに差異がないかチェック
	if (__.difference(rscope, cscope).length > 0) {
		res.status(401).json({error: 'invalid_scope'});
		return;
	};

	// トークンにランダム文字列をセット
	const accessToken = randomstring.generate();
	// 有効期限から有効期日を計算
	const expiresDate = expiresIn*1000 + Date.now();

	// トークン情報をデータベースに記録
	const tokenType = 'Bearer';
	db.insert({ access_token: accessToken, token_type: tokenType, client_id: clientId, scope: rscope, username: userName, expires_in: expiresIn, expires_date: expiresDate });

	// トークンをレスポンス
	const token_response = { access_token: accessToken, token_type: tokenType, scope: rscope.join(' '), expires_in: expiresIn };
	res.status(200).json(token_response);
		
	const expiresDateUTC = new Date(expiresDate);
	console.log(`Issue a token: ${accessToken}, ExpiresDate: ${expiresDateUTC.toUTCString()}`);
});

// クライアントIDからクライアントオブジェクトを取得する関数
const getClient = (clientId) => {
	return __.find(clients, (client) => { return client.client_id == clientId; });
};

// リソースオーナー名からリソースオーナーオブジェクトを取得する関数
const getUser = (username) => {
	return userInfo[username];
};

// Base64エンコードされたクライアントIDとクライアントシークレットをデコード
const decodeClientCredentials = (auth) => {
	const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	const clientId = querystring.unescape(clientCredentials[0]);
	const clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

// データベースをリセット
db.clear();

// サーバ起動
const server = app.listen(portNumber, () => {
	console.log(`OAuth Authorization Server is listening at http://${hostAddress}:${portNumber}`);
});
