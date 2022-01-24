const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
// dummy users
const users = [
  {
    id: 1,
    username: "John",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: 2,
    username: "Jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

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

// 验证用户权限的中间件，主要是验证access token是否过期
// 若不过期，把解码出的token中的payload传递给下一个中间件、控制器
const verify = (req, res, next) => {
  // token在header
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
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    const newAccessToken = generateAccessToken(user, refreshToken);
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

// 退出登录
app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => refreshToken !== token);
  res.status(200).json("成功退出");
});

// 删除
app.delete("/api/users/:userId", verify, (req, res) => {
  console.log(req.user.id, req.params.userId);
  if (Number(req.user.id) === Number(req.params.userId) || req.user.isAdmin) {
    res.status(200).json("User has been deleted");
  } else {
    res.status(403).json("权限不够");
  }
});

app.listen(6000, () => {
  console.log("服务器启动");
});
