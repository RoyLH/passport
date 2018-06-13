/**
 * Module dependencies.
 */
//var http = require('http')
//  , req = http.IncomingMessage.prototype;


var req = exports = module.exports = {};

/**
 * Initiate a login session for `user`.
 *
 * Options:
 *   - `session`  Save login state in session, defaults to _true_
 *
 * Examples:
 *
 *     req.logIn(user, { session: false });
 *
 *     req.logIn(user, function(err) {
 *       if (err) { throw err; }
 *       // session saved
 *     });
 *
 * @param {User} user
 * @param {Object} options
 * @param {Function} done
 * @api public
 */
req.login =
req.logIn = function(user, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }
  options = options || {};
  
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  var session = (options.session === undefined) ? true : options.session;
  
  this[property] = user; // (这里最终经过 framework/connect.js的处理 this指向了 req) 所以这里即就是req.user = user;
  if (session) {
    if (!this._passport) { throw new Error('passport.initialize() middleware not in use'); }
    if (typeof done != 'function') { throw new Error('req#login requires a callback function'); }
    
    var self = this;
    // 再在SessionManager.prototype.logIn中 
    // 完成将user.id 序列化到 req._passport.session.user 等价于挂载在了 req.session.passport.user
    this._passport.instance._sm.logIn(this, user, function(err) {
      if (err) { self[property] = null; return done(err); } // 若是失败 req.user = null; return done(err);
      done(); // 回到应用程序中调用req.login()方法的地方继续执行代码
    });
  } else {
    done && done();
  }
};

/**
 * Terminate an existing login session.
 *
 * @api public
 */
req.logout =
req.logOut = function() {
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  
  this[property] = null; // 将 req.user = null；
  if (this._passport) {
    // 再在SessionManager.prototype.logOut中 
    // 删除了req._passport.session.user 等价于删除了 req.session.passport.user
    this._passport.instance._sm.logOut(this); 
  }
};

/**
 * Test if request is authenticated.
 *
 * @return {Boolean}
 * @api public
 */
// 判断req.user(默认为user属性)是否存在 存在为true表示通过该验证
req.isAuthenticated = function() {
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  
  return (this[property]) ? true : false;
};

/**
 * Test if request is unauthenticated.
 *
 * @return {Boolean}
 * @api public
 */
// 与isAuthenticated方法相反
req.isUnauthenticated = function() {
  return !this.isAuthenticated();
};
