function SessionManager(options, serializeUser) {
  if (typeof options == 'function') {
    serializeUser = options;
    options = undefined;
  }
  options = options || {};
  
  this._key = options.key || 'passport';
  this._serializeUser = serializeUser;
}

SessionManager.prototype.logIn = function(req, user, cb) {
  var self = this;
  this._serializeUser(user, req, function(err, obj) {
    if (err) {
      return cb(err);
    }
    if (!req._passport.session) {
      req._passport.session = {};
    }
    // 在这里正式将 登陆用户user对象的user.id 存到了req._passport.session.user中
    req._passport.session.user = obj; 
    if (!req.session) {
      req.session = {};
    }
    // 将req._passport.session指向req.session.passport(默认为passport属性) 也就是说 req.session.passport.user为最终的落点
    req.session[self._key] = req._passport.session;
    cb();
    // 回到 http/request.js 中的req.login中继续执行代码
  });
}

// 删除了req._passport.session.user 等价于删除了 req.session.passport.user
SessionManager.prototype.logOut = function(req, cb) {
  if (req._passport && req._passport.session) {
    delete req._passport.session.user;
  }
  cb && cb(); // 回到 http/request.js 中的req.logout中继续执行代码
}


module.exports = SessionManager;
