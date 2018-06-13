/**
 * Module dependencies.
 */
var pause = require('pause')
  , util = require('util')
  , Strategy = require('passport-strategy');


/**
 * `SessionStrategy` constructor.
 *
 * @api public
 */
function SessionStrategy(options, deserializeUser) {
  if (typeof options == 'function') {
    deserializeUser = options;
    options = undefined;
  }
  options = options || {};
  
  // SessionStrategy构造函数 继承了 Strategy构造函数中的属性和方法 注意: SessionStrategy只是仅仅继承了 Strategy 在构造函数中定义的属性和方法
  Strategy.call(this);
  this.name = 'session';
  this._deserializeUser = deserializeUser;
}

/**
 * Inherit from `Strategy`.
 */

// SessionStrategy类 继承了 Strategy类 注意: SessionStrategy只是仅仅继承了 Strategy 在原型中定义的属性和方法 源码如下：
// console.log(util.inherits.toString())
// function (ctor, superCtor) {
//   ctor.super_ = superCtor;
//   ctor.prototype = Object.create(superCtor.prototype, {
//     constructor: {
//       value: ctor,
//       enumerable: false,
//       writable: true,
//       configurable: true
//     }
//   });
// }
util.inherits(SessionStrategy, Strategy);

/**
 * Authenticate request based on the current session state.
 *
 * The session authentication strategy uses the session to restore any login
 * state across requests.  If a login session has been established, `req.user`
 * will be populated with the current user.
 *
 * This strategy is registered automatically by Passport.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
SessionStrategy.prototype.authenticate = function(req, options) {
  // 如果没有使用过initialize，报错
  if (!req._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
  options = options || {};

  var self = this,
      su;
  if (req._passport.session) {
    // 看是否含有user
    su = req._passport.session.user;
  }

  if (su || su === 0) {
    // NOTE: Stream pausing is desirable in the case where later middleware is
    //       listening for events emitted from request.  For discussion on the
    //       matter, refer to: https://github.com/jaredhanson/passport/pull/106
    
    // 这个策略其实做的像是一个中间件， 只调用了pass和error方法， 主要的功能在req中加入user属性其中user可以定义_userProperty来修改
    // 我们要在应用开始的时候注册一下session的中间件， app.use(passport.session())
    var paused = options.pauseStream ? pause(req) : null;
    // 回到authenticator.js/Authenticator.prototype.deserializeUser 进行真正序列化的过程
    this._deserializeUser(su, req, function(err, user) {
      if (err) { return self.error(err); }
      if (!user) {
        delete req._passport.session.user;
      } else {
        // TODO: Remove instance access
        var property = req._passport.instance._userProperty || 'user';
        req[property] = user;
      }
      self.pass();
      if (paused) {
        paused.resume();
      }
    });
  } else {
    self.pass();
  }
};


/**
 * Expose `SessionStrategy`.
 */
module.exports = SessionStrategy;
