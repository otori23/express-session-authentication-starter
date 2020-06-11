module.exports.isAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    res
      .status(401)
      .send(
        '<h1>You are not authenticated</h1><p><a href="/login">Login</a></p>'
      );
  }
};

module.exports.isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.admin) {
    next();
  } else {
    res
      .status(401)
      .send(
        '<h1>You are not authenticated as an Admin</h1><p><a href="/login">Login</a></p>'
      );
  }
};
