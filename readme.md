# 学习 JWT 登录鉴权笔记

前端采用 React，后端服务器使用 express.js

# 使用 JWT 的原因

由于 HTTP 服务器是无状态的协议，因此即使上一次 HTTP 请求是登录，下一次请求其他资源服务器也不记得你是谁，因此需要一种登录凭证。

登录凭证从 cookie、session，一直到现在的 jwt token.

## 什么是 jwt token

jwt token 个人理解，通常是用户登录后，服务器根据用户的部分数据（比如 id、username）作为 payload，生成一个 token，然后返回给用户。此后用户请求其他接口，只要带上 token，作为身份验证。

## jwt token 组成

jwt token 由三部分组成：

1. header：其中指明了 token 的版本、加密算法、哈希算法等
2. payload：用户数据、过期时间等
3. signature：用密钥加密 base64(header) + base64(payload)后生成的签名。

## 前端 token 方案

使用两个 token，一个 accessToken，用来访问其他接口时作为用户的凭证；refreshToken，在 refreshToken 未过期时，而 accessToken 过期时，用来刷新 refreshToken 与 accessToken.
通常 refreshToken 的过期时间比较久（一个月），而 accessToken 则可能只有十几分钟、几小时。

# 后端接口

## 登录接口

这里的登录接口逻辑是，当用户登陆后，且用户存在于数据库中，那么利用 jsonwebtoken 库，利用用户数据，签发一个 accessToken 与一个 refreshToken，其中 refreshToken 时间久一点。并且把 refreshToken 存在数据库中（这里用数组模拟），用来后续 token 续期。

### dummy users

`const users = [ { id: 1, username: "John", password: "John0908", isAdmin: true, }, { id: 2, username: "Jane", password: "Jane0908", isAdmin: false, }, ];`

### 登录接口

```js
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.isAdmin,
    },
    "mySecretKey",
    { expiresIn: "5s" }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.isAdmin,
    },
    "myRefreshSecretKey",
    { expiresIn: "15m" }
  );
};

app.use(express.json());

// 放refreshToken
// 退出后，删除refreshToken
// 在refreshToken没过期的情况下，刷新accessToken
let refreshTokens = [];
// 登录
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (user) => user.username === username && user.password === password
  );
  if (user) {
    // 生成access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken: accessToken,
      refreshToken: refreshToken,
    });
  } else {
    res.status(400).json("密码或账户出错");
  }
});
```

### 验证登录接口的中间件 verify

注意，token 在请求中，放在 authorization header，authorization: Bearer accessToken

```js
const verify = (req, res, next) => {
  // token 在 header
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    // console.log(token);
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        console.log(err);
        return res.status(403).json("token is not valid!");
      }

      // 传递user给下一个中间件
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("未授权");
  }
};
```

### 其他接口：删除接口

```js
app.delete("/api/users/:userId", verify, (req, res) => {
  console.log(req.user.id, req.params.userId);
  if (Number(req.user.id) === Number(req.params.userId) || req.user.isAdmin) {
    res.status(200).json("User has been deleted");
  } else {
    res.status(403).json("权限不够");
  }
});
```

### refreshToken 续期

删除已有的 refreshToken

```js
app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.token;

  // send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("未授权");

  if (!refreshTokens.includes(refreshToken))
    return res.status(403).json("Refresh token is not valid");

  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    if (err) {
      console.log(err);
      return;
    }
    // 未过期
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
    // 删除原有的两个token，生成新的token
  });

  // if everything is ok，create new access token, refresh token and send to user
});
```

### 退出接口

删除记录在服务期端的 refreshToken

```js
app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => refreshToken !== token);
  res.status(200).json("成功退出");
});
```

## 前端处理

前端主要是登陆后的其他接口逻辑，需要用 axios 配置请求拦截器，利用 jwt-decode 判断 accessToken 是否过期，若过期；若 refreshToken 也过期，则消除用户信息，重新登录（？）；若 refreshToken 未过期，则续期 accessToken 与 refreshToken:

```js
// 续费token
const refreshToken = async () => {
  try {
    const res = await axios.post("/api/refresh", {
      token: user.refreshToken,
    });
    setUser({
      ...user,
      accessToken: res.data.accessToken,
      refreshToken: res.data.refreshToken,
    });
    return res.data;
  } catch (err) {
    console.log(err);
  }
};

// 用于除了续期、登录的请求配置
const axiosJWT = axios.create();

axiosJWT.interceptors.request.use(
  // do something before sending request
  async (config) => {
    let currentDate = new Date();
    // decode jwt token判断是否过期
    const decodedToken = jwt_decode(user.accessToken);
    if (decodedToken.exp * 1000 < currentDate.getTime()) {
      // token过期
      const data = await refreshToken();
      config.headers["authorization"] = "Bearer " + data.accessToken;
    }
    return config;
  },
  (err) => {
    return Promise.reject(err);
  }
);

// 登录
const handleSubmit = async (e) => {
  e.preventDefault();
  try {
    const res = await axios.post("/api/login", {
      username,
      password,
    });
    setUser(res.data);
  } catch (err) {
    console.log(err);
  }
};

// 登陆后删除用户的操作
const handleDelete = async (id) => {
  setSuccess(false);
  setError(false);
  try {
    await axiosJWT.delete("/api/users/" + id, {
      headers: {
        authorization: "Bearer " + user.accessToken,
      },
    });
    setSuccess(true);
  } catch (err) {
    setError(true);
  }
};
```
